import json
import logging
from pathlib import Path
from datetime import datetime
from typing import List
from src.collectors.schema import RawCTIRecord

logger = logging.getLogger(__name__)

class SnapshotManager:
    def __init__(self, storage_dir: str = "./data/snapshots"):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        
    def create_snapshot(self, records: List[RawCTIRecord], prefix: str = "cti_raw") -> Path:
        """Ghi danh sách CTI ra file JSONL cố định (snapshot)."""
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{prefix}_{timestamp_str}_{len(records)}_records.jsonl"
        filepath = self.storage_dir / filename
        
        with open(filepath, "w", encoding="utf-8") as f:
            for record in records:
                # Ép kiểu json qua pydantic model_dump_json
                f.write(record.model_dump_json() + "\n")
                
        logger.info(f"Đã đóng băng ảnh chụp dữ liệu tại: {filepath}")
        return filepath