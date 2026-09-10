import requests
import time
import logging
from bs4 import BeautifulSoup
from datetime import datetime, timezone
from urllib.parse import urlparse
from src.collectors.schema import RawCTIRecord, SourceType

logger = logging.getLogger(__name__)

class TorCrawler:
    def __init__(self, tor_proxy: str = "socks5h://127.0.0.1:9050", rate_limit_sec: int = 5):
        self.proxies = {
            'http': tor_proxy,
            'https': tor_proxy
        }
        self.rate_limit_sec = rate_limit_sec # Kiểm soát tốc độ
        
    def fetch_onion_page(self, onion_url: str) -> RawCTIRecord | None:
        """Truy cập trang dark web qua Tor và trích xuất nội dung."""
        try:
            time.sleep(self.rate_limit_sec)
            resp = requests.get(onion_url, proxies=self.proxies, timeout=30)
            resp.raise_for_status()
            
            soup = BeautifulSoup(resp.text, 'html.parser')
            # Lọc bỏ các thẻ không mang nội dung CTI
            for tag in soup(["script", "style", "nav", "footer"]):
                tag.decompose()
                
            content = soup.get_text(separator="\n").strip()
            
            return RawCTIRecord(
                id=f"onion_{hash(onion_url)}",
                source_type=SourceType.DARKWEB,
                source_uri=onion_url,
                content=content[:5000], # Tránh nội dung quá tải
                timestamp=datetime.now(timezone.utc),
                metadata={
                    "domain": urlparse(onion_url).netloc,
                    "status_code": resp.status_code
                }
            )
        except Exception as e:
            logger.error(f"Lỗi khi thu thập dark web {onion_url}: {e}")
            return None