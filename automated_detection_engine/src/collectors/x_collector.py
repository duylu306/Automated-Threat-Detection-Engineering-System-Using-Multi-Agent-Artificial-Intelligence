import requests
import time
import logging
from datetime import datetime, timezone
from typing import List, Optional
from src.collectors.schema import RawCTIRecord, SourceType

logger = logging.getLogger(__name__)

class XCollector:
    def __init__(self, bearer_token: str, rate_limit_sec: int = 3):
        """
        Khởi tạo bộ thu thập X (Twitter) sử dụng Bearer Token của X API v2.
        """
        self.bearer_token = bearer_token
        self.rate_limit_sec = rate_limit_sec
        self.headers = {
            "Authorization": f"Bearer {self.bearer_token}",
            "User-Agent": "CTI_Research_Bot_v1"
        }
        self.search_url = "https://api.twitter.com/2/tweets/search/recent"

    def fetch_recent_tweets(self, query: str, max_results: int = 10) -> List[RawCTIRecord]:
        """
        Tìm kiếm các tweet gần đây dựa trên từ khóa (query).
        Ví dụ query: "(ransomware OR IOC OR malware) -is:retweet"
        """
        # API v2 yêu cầu max_results nằm trong khoảng 10 - 100 cho mỗi request
        max_results = max(10, min(max_results, 100))
        
        params = {
            "query": query,
            "max_results": max_results,
            "tweet.fields": "created_at,public_metrics,lang,author_id",
            "expansions": "author_id",
            "user.fields": "username"
        }

        records = []
        try:
            time.sleep(self.rate_limit_sec)  # Kiểm soát tốc độ truy cập
            response = requests.get(self.search_url, headers=self.headers, params=params, timeout=15)
            
            if response.status_code == 429:
                logger.warning("Đã chạm ngưỡng giới hạn tốc độ (Rate Limit) của X API. Đang chờ...")
                time.sleep(15 * 60)  # Thường API v2 reset sau 15 phút
                return self.fetch_recent_tweets(query, max_results)
                
            response.raise_for_status()
            data = response.json()

            if "data" not in data:
                logger.info(f"Không tìm thấy tweet nào cho truy vấn: {query}")
                return records

            # Ánh xạ author_id sang username để tạo URL nguồn
            users = {u["id"]: u["username"] for u in data.get("includes", {}).get("users", [])}

            for tweet in data["data"]:
                author_id = tweet.get("author_id", "")
                username = users.get(author_id, "unknown")
                tweet_id = tweet["id"]
                
                # Chuyển đổi chuỗi thời gian ISO 8601 sang đối tượng datetime
                created_at_str = tweet.get("created_at")
                if created_at_str:
                    timestamp = datetime.strptime(created_at_str, "%Y-%m-%dT%H:%M:%S.000Z").replace(tzinfo=timezone.utc)
                else:
                    timestamp = datetime.now(timezone.utc)

                record = RawCTIRecord(
                    id=f"x_{tweet_id}",
                    source_type=SourceType.TWITTER,
                    source_uri=f"https://x.com/{username}/status/{tweet_id}",
                    content=tweet["text"],
                    timestamp=timestamp,
                    language=tweet.get("lang", "en"),
                    metadata={
                        "author_id": author_id,
                        "username": username,
                        "retweet_count": tweet.get("public_metrics", {}).get("retweet_count", 0),
                        "like_count": tweet.get("public_metrics", {}).get("like_count", 0)
                    }
                )
                records.append(record)

            logger.info(f"Đã thu thập {len(records)} tweets từ X cho truy vấn '{query}'.")
            return records

        except requests.exceptions.RequestException as e:
            logger.error(f"Lỗi kết nối khi gọi X API: {e}")
            return []
        except Exception as e:
            logger.error(f"Lỗi không xác định khi xử lý dữ liệu X: {e}")
            return []