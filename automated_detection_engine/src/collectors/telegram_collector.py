import logging
from datetime import datetime, timezone

from telethon.sync import TelegramClient
from telethon.tl.functions.messages import GetHistoryRequest
from telethon.tl.types import MessageEntityTextUrl, MessageEntityUrl

from src.collectors.schema import RawCTIRecord, SourceType

logger = logging.getLogger(__name__)


class TelegramCollector:
    def __init__(self, api_id: int, api_hash: str, session_name: str = "cti_session"):
        self.client = TelegramClient(session_name, api_id, api_hash)

    def _extract_links(self, msg) -> list[str]:
        """
        Trích các link gắn trong tin nhắn — bao gồm cả link ẩn (hyperlink dạng
        "CVE-2025-6020" hiển thị nhưng thật ra trỏ tới URL khác), vốn KHÔNG
        xuất hiện trong msg.message dạng text thuần.

        Telegram lưu định dạng (bold, link...) tách riêng khỏi text trong
        msg.entities, mỗi entity có offset/length trỏ vào vị trí text tương ứng.
        - MessageEntityTextUrl: link ẩn (text hiển thị khác URL đích) -> có field .url
        - MessageEntityUrl: link hiển thị nguyên văn URL trong text (vd: t.me/...)
          -> không có field .url, phải tự cắt substring theo offset/length
        """
        links: list[str] = []
        if not msg.entities:
            return links

        for entity in msg.entities:
            if isinstance(entity, MessageEntityTextUrl):
                # Link ẩn: text hiển thị (vd "CVE-2025-6020") khác URL thật
                links.append(entity.url)
            elif isinstance(entity, MessageEntityUrl):
                # Link hiển thị nguyên văn -> tự cắt từ text gốc
                start = entity.offset
                end = entity.offset + entity.length
                links.append(msg.message[start:end])

        return links

    async def fetch_channel_messages(self, channel_username: str, limit: int = 100) -> list[RawCTIRecord]:
        """Thu thập tin nhắn từ kênh Telegram công khai."""
        await self.client.start()
        records = []

        try:
            channel = await self.client.get_entity(channel_username)
            messages = await self.client(GetHistoryRequest(
                peer=channel,
                offset_id=0,
                offset_date=None,
                add_offset=0,
                limit=limit,
                max_id=0,
                min_id=0,
                hash=0
            ))

            for msg in messages.messages:
                if not msg.message:
                    continue

                embedded_links = self._extract_links(msg)

                record = RawCTIRecord(
                    id=f"tg_{channel_username}_{msg.id}",
                    source_type=SourceType.TELEGRAM,
                    source_uri=f"https://t.me/{channel_username}/{msg.id}",
                    content=msg.message,
                    timestamp=msg.date or datetime.now(timezone.utc),
                    metadata={
                        "views": getattr(msg, 'views', 0),
                        "forwards": getattr(msg, 'forwards', 0),
                        # Link ẩn/hiển thị trích từ entities -> ví dụ chính là
                        # link chi tiết CVE (IBM advisory, NVD, vendor bulletin...)
                        # mà text thuần không chứa.
                        "embedded_links": embedded_links,
                    }
                )
                records.append(record)

            logger.info(f"Đã thu thập {len(records)} tin nhắn từ {channel_username}")
            return records
        except Exception as e:
            logger.error(f"Lỗi khi thu thập kênh {channel_username}: {e}")
            return []