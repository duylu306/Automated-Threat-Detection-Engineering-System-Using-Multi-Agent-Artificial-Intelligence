"""
Orchestrator: điều phối thu thập dữ liệu CTI đa nguồn (X, Tor, Telegram)
và đóng băng kết quả thành snapshot JSONL.

Cải tiến so với bản gốc:
- Secrets đọc từ biến môi trường (.env), không hardcode trong code
- Mỗi nguồn được bọc try/except riêng -> một nguồn lỗi không làm hỏng cả pipeline
- Các hàm sync (X, Tor) chạy qua asyncio.to_thread() để không block event loop
- Logging rõ ràng theo từng bước, dễ audit cho capstone report
"""

import asyncio
import logging
import os
import sys

from dotenv import load_dotenv

from src.collectors.schema import RawCTIRecord
from src.collectors.telegram_collector import TelegramCollector
from src.collectors.tor_crawler import TorCrawler
from src.collectors.x_collector import XCollector
from src.collectors.snapshot_manager import SnapshotManager

# --- Cấu hình logging ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("orchestrator")

# --- Nạp biến môi trường từ file .env ---
load_dotenv()

X_BEARER_TOKEN = os.getenv("X_BEARER_TOKEN")
TG_API_ID = os.getenv("TG_API_ID")
TG_API_HASH = os.getenv("TG_API_HASH")

ONION_TARGET_URL = os.getenv(
    "ONION_TARGET_URL",
    "http://example.onion/",  # đặt qua .env thay vì hardcode URL thật trong code
)
TELEGRAM_CHANNEL = os.getenv("TELEGRAM_CHANNEL", "vxunderground")


def _check_required_env() -> None:
    """Kiểm tra các biến môi trường bắt buộc, dừng sớm với thông báo rõ ràng nếu thiếu."""
    missing = []
    if not X_BEARER_TOKEN:
        missing.append("X_BEARER_TOKEN")
    if not TG_API_ID:
        missing.append("TG_API_ID")
    if not TG_API_HASH:
        missing.append("TG_API_HASH")

    if missing:
        logger.error(
            "Thiếu biến môi trường bắt buộc: %s. "
            "Vui lòng khai báo trong file .env trước khi chạy.",
            ", ".join(missing),
        )
        sys.exit(1)


async def collect_from_x(query: str, max_results: int = 15) -> list[RawCTIRecord]:
    """Thu thập từ X. Bọc lỗi riêng để không ảnh hưởng các nguồn khác."""
    try:
        logger.info("Bắt đầu thu thập từ X với query: %s", query)
        x_crawler = XCollector(bearer_token=X_BEARER_TOKEN)
        # fetch_recent_tweets là hàm sync (dùng requests) -> chạy trong thread riêng
        # để không block event loop khi orchestrator là async.
        records = await asyncio.to_thread(
            x_crawler.fetch_recent_tweets, query, max_results
        )
        logger.info("X: thu thập thành công %d record(s).", len(records))
        return records
    except Exception:
        logger.exception("Lỗi khi thu thập từ X — bỏ qua nguồn này, tiếp tục pipeline.")
        return []


async def collect_from_tor(onion_url: str) -> list[RawCTIRecord]:
    """Thu thập từ Tor/dark web. Bọc lỗi riêng vì nguồn này dễ timeout/không ổn định."""
    try:
        logger.info("Bắt đầu thu thập từ Tor: %s", onion_url)
        tor_crawler = TorCrawler()
        onion_data = await asyncio.to_thread(tor_crawler.fetch_onion_page, onion_url)
        if onion_data:
            logger.info("Tor: thu thập thành công 1 record.")
            return [onion_data]
        logger.warning("Tor: không lấy được dữ liệu từ %s.", onion_url)
        return []
    except Exception:
        logger.exception("Lỗi khi thu thập từ Tor — bỏ qua nguồn này, tiếp tục pipeline.")
        return []


async def collect_from_telegram(channel: str, limit: int = 20) -> list[RawCTIRecord]:
    """Thu thập từ Telegram. Đã là async natively."""
    try:
        logger.info("Bắt đầu thu thập từ Telegram: %s", channel)
        tg_collector = TelegramCollector(
            api_id=int(TG_API_ID), api_hash=TG_API_HASH
        )
        records = await tg_collector.fetch_channel_messages(channel, limit=limit)
        logger.info("Telegram: thu thập thành công %d record(s).", len(records))
        return records
    except Exception:
        logger.exception(
            "Lỗi khi thu thập từ Telegram — bỏ qua nguồn này, tiếp tục pipeline."
        )
        return []


async def run_collection() -> None:
    _check_required_env()

    all_records: list[RawCTIRecord] = []

    # Chạy song song 3 nguồn để giảm tổng thời gian thu thập.
    # Mỗi coroutine đã tự bọc try/except nên return_exceptions không bắt buộc,
    # nhưng vẫn bật để an toàn tuyệt đối trước lỗi không lường trước.
    results = await asyncio.gather(
        collect_from_x(query="#CTI OR ransomware -is:retweet", max_results=15),
        collect_from_tor(ONION_TARGET_URL),
        collect_from_telegram(TELEGRAM_CHANNEL, limit=20),
        return_exceptions=True,
    )

    for source_name, result in zip(("X", "Tor", "Telegram"), results):
        if isinstance(result, Exception):
            logger.error("Nguồn %s thất bại hoàn toàn: %s", source_name, result)
            continue
        all_records.extend(result)

    from src.collectors.github_enrich import enrich_record_with_poc_info
    
    for record in all_records:
        poc_info = enrich_record_with_poc_info(record.content)
        record.metadata.update(poc_info)

    if not all_records:
        logger.warning(
            "Không thu thập được bất kỳ record nào từ tất cả nguồn. "
            "Vẫn tạo snapshot rỗng để giữ nhật ký chạy pipeline."
        )

    snapshot_mgr = SnapshotManager()
    filepath = snapshot_mgr.create_snapshot(all_records, prefix="cti_multi_source")
    logger.info(
        "Hoàn tất pipeline: tổng %d record(s), snapshot tại %s",
        len(all_records),
        filepath,
    )


if __name__ == "__main__":
    asyncio.run(run_collection())