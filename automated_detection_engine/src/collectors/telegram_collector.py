import logging
from datetime import datetime, timezone
from telethon.sync import TelegramClient
from telethon.tl.functions.messages import GetHistoryRequest
from src.collectors.schema import RawCTIRecord, SourceType

logger = logging.getLogger(__name__)

class TelegramCollector:
    def __init__(self, api_id: int, api_hash: str, session_name: str = "cti_session"):
        self.client = TelegramClient(session_name, api_id, api_hash)
        
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
                    
                record = RawCTIRecord(
                    id=f"tg_{channel_username}_{msg.id}",
                    source_type=SourceType.TELEGRAM,
                    source_uri=f"https://t.me/{channel_username}/{msg.id}",
                    content=msg.message,
                    timestamp=msg.date or datetime.now(timezone.utc),
                    metadata={
                        "views": getattr(msg, 'views', 0),
                        "forwards": getattr(msg, 'forwards', 0)
                    }
                )
                records.append(record)
                
            logger.info(f"Đã thu thập {len(records)} tin nhắn từ {channel_username}")
            return records
        except Exception as e:
            logger.error(f"Lỗi khi thu thập kênh {channel_username}: {e}")
            return []