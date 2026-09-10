from pydantic import BaseModel, Field
from typing import Dict, Any, Optional
from datetime import datetime
from enum import Enum

class SourceType(str, Enum):
    TELEGRAM = "telegram"
    TWITTER = "twitter"
    DARKWEB = "darkweb"
    BLOG = "blog"

class RawCTIRecord(BaseModel):
    """Lược đồ chuẩn hóa cho mọi nguồn CTI đầu vào."""
    id: str = Field(..., description="ID định danh duy nhất (vd: hash của content hoặc ID tin nhắn)")
    source_type: SourceType
    source_uri: str = Field(..., description="Link bài viết, tên channel Telegram, hoặc URL onion")
    content: str = Field(..., description="Nội dung văn bản thô")
    timestamp: datetime = Field(..., description="Thời gian bài viết được đăng tải")
    language: str = Field(default="en", description="Ngôn ngữ nhận diện được")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Các siêu dữ liệu kênh (lượt view, author, v.v.)")