import asyncio
import logging
import os

from dotenv import load_dotenv

from src.collectors.telegram_collector import TelegramCollector
from src.collectors.tor_crawler import TorCrawler
from src.collectors.snapshot_manager import SnapshotManager
# Sửa path này cho khớp với vị trí thật của file trên máy bạn:
# hiện file đang nằm ở src/collectors/github_enrich.py theo sidebar bạn gửi trước.
from src.collectors.github_enrich import enrich_record_with_poc_info

# Set up logging to see what's happening
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

load_dotenv()


async def test_real_world_collection():
    all_records = []

    # # ---------------------------------------------------------
    # # 1. TEST DARK WEB (TOR)
    # # ---------------------------------------------------------
    # logging.info("Starting Dark Web collection test...")
    # tor_crawler = TorCrawler(tor_proxy="socks5h://127.0.0.1:9050")
    # test_onion_url = "http://p53lf57qovyuvwsc6xnrppyply3vtqm7l6pcobkmyqsiofyeznfu5uqd.onion"
    # onion_record = tor_crawler.fetch_onion_page(test_onion_url)
    # if onion_record:
    #     logging.info(f"SUCCESS: Scraped {len(onion_record.content)} characters from {test_onion_url}")
    #     all_records.append(onion_record)
    # else:
    #     logging.error("FAILED: Could not reach the onion site. Is Tor running?")

    # ---------------------------------------------------------
    # 2. TEST TELEGRAM
    # ---------------------------------------------------------
    logging.info("Starting Telegram collection test...")

    # Đọc credentials từ .env thay vì hardcode trong code
    api_id_str = os.getenv("TG_API_ID")
    api_hash = os.getenv("TG_API_HASH")

    if not api_id_str or not api_hash:
        logging.error(
            "Thiếu TG_API_ID / TG_API_HASH trong file .env. "
            "Tạo file .env ở project root với 2 dòng:\n"
            "TG_API_ID=xxxxxxx\nTG_API_HASH=xxxxxxxxxxxxxxxx"
        )
        return

    api_id = int(api_id_str)

    tg_collector = TelegramCollector(api_id=api_id, api_hash=api_hash, session_name="cti_test_session")
    tg_records = await tg_collector.fetch_channel_messages("cveNotify", limit=5)

    if tg_records:
        logging.info(f"SUCCESS: Fetched {len(tg_records)} messages from Telegram.")
        all_records.extend(tg_records)
    else:
        logging.error("FAILED: Could not fetch Telegram messages.")

    # ---------------------------------------------------------
    # 3. ENRICHMENT (CVE + GitHub PoC metadata) — bước bị thiếu trước đó
    # ---------------------------------------------------------
    if all_records:
        logging.info("Bắt đầu enrichment (CVE / GitHub PoC)...")
        for record in all_records:
            try:
                poc_info = enrich_record_with_poc_info(record.content)
                record.metadata.update(poc_info)
                if poc_info.get("cve_ids") or poc_info.get("poc_available"):
                    logging.info(
                        "Enriched %s: cve_ids=%s poc_available=%s",
                        record.id,
                        poc_info.get("cve_ids"),
                        poc_info.get("poc_available"),
                    )
            except Exception:
                logging.exception("Enrichment lỗi cho record %s — bỏ qua, giữ record gốc.", record.id)

    # ---------------------------------------------------------
    # 4. TEST DATA SNAPSHOT (JSONL OUTPUT)
    # ---------------------------------------------------------
    if all_records:
        logging.info("Creating dataset snapshot...")
        snapshot_mgr = SnapshotManager(storage_dir="./data/test_snapshots")
        filepath = snapshot_mgr.create_snapshot(all_records, prefix="real_test")
        logging.info(f"All done! Check your output file at: {filepath}")


if __name__ == "__main__":
    asyncio.run(test_real_world_collection())