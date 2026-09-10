"""
src/extraction/ioc_engine.py
────────────────────────────
Extract va normalize IOCs tu: text, PDF, EVTX log.
Su dung iocextract + regex custom cho defanged IOCs.
"""
import re
import json
import logging
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

import fitz  # PyMuPDF
import pdfplumber
import iocextract

logger = logging.getLogger(__name__)


# ─── Data Models ──────────────────────────────────────────────────────────────

@dataclass
class IOCResult:
    """Ket qua sau khi extract IOCs tu mot nguon."""
    source: str = ""
    ips: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    md5s: list[str] = field(default_factory=list)
    sha1s: list[str] = field(default_factory=list)
    sha256s: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)
    mitre_ids: list[str] = field(default_factory=list)
    registry_keys: list[str] = field(default_factory=list)
    mutexes: list[str] = field(default_factory=list)
    file_paths: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v}

    def merge(self, other: "IOCResult") -> "IOCResult":
        """Gop 2 IOCResult lai, dedup."""
        merged = IOCResult(source=self.source)
        for attr in self.__dataclass_fields__:
            if attr == "source":
                continue
            combined = list(set(getattr(self, attr) + getattr(other, attr)))
            setattr(merged, attr, combined)
        return merged

    @property
    def total_count(self) -> int:
        return sum(
            len(v) for k, v in self.__dict__.items()
            if k != "source" and isinstance(v, list)
        )


@dataclass
class EventRecord:
    """Windows Event Log record da duoc parse."""
    event_id: int
    channel: str
    computer: str
    timestamp: str
    provider: str
    data: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return self.__dict__


# ─── Refang Utilities ─────────────────────────────────────────────────────────

# Regex patterns cho defanged IOCs
_DEFANG_PATTERNS = [
    (r"\[\.\]", "."),            # 192.168[.]1.1
    (r"\(dot\)", "."),           # evil(dot)com
    (r"\[dot\]", "."),           # evil[dot]com
    (r"hxxp", "http"),           # hxxp://
    (r"hxxps", "https"),         # hxxps://
    (r"\[@\]", "@"),             # user[@]domain
    (r"\[at\]", "@"),            # user[at]domain
]

def refang(ioc: str) -> str:
    """Chuyen defanged IOC ve dang binh thuong."""
    result = ioc
    for pattern, replacement in _DEFANG_PATTERNS:
        result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)
    return result.strip()


# ─── Custom Regex Extractors ──────────────────────────────────────────────────

_MITRE_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_REGISTRY_PATTERN = re.compile(
    r"\b(?:HKEY_|HKLM|HKCU|HKCR|HKU|HKCC)\\[^\s\"'<>]+",
    re.IGNORECASE
)
_MUTEX_PATTERN = re.compile(
    r"(?:mutex|CreateMutex)[^\w]*[\"']?([A-Za-z0-9_\-\.]{4,64})[\"']?",
    re.IGNORECASE
)
_FILE_PATH_PATTERN = re.compile(
    r"(?:[A-Za-z]:\\|%\w+%\\)[^\s\"'<>:*?|]+",
    re.IGNORECASE
)


def _extract_custom(text: str) -> dict:
    """Extract cac IOC khong co trong iocextract."""
    mitre_ids = list(set(_MITRE_PATTERN.findall(text)))
    cves = list(set(_CVE_PATTERN.findall(text.upper())))
    registry_keys = list(set(_REGISTRY_PATTERN.findall(text)))
    mutexes = [m.group(1) for m in _MUTEX_PATTERN.finditer(text)]
    file_paths = list(set(_FILE_PATH_PATTERN.findall(text)))
    return {
        "mitre_ids": mitre_ids,
        "cves": cves,
        "registry_keys": registry_keys[:20],   # cap so luong
        "mutexes": list(set(mutexes))[:20],
        "file_paths": file_paths[:20],
    }


# ─── Core Engine ──────────────────────────────────────────────────────────────

class IOCExtractor:
    """
    Extract IOCs tu nhieu nguon khac nhau.

    Usage:
        extractor = IOCExtractor()
        result = extractor.extract_from_text("Attacker used 192.168[.]1.1...")
        print(result.ips)  # ['192.168.1.1']
    """

    def extract_from_text(self, text: str, source: str = "text") -> IOCResult:
        """Extract IOCs tu plain text hoac HTML."""
        if not text or not text.strip():
            return IOCResult(source=source)

        # Refang truoc khi extract
        refanged = refang(text)

        result = IOCResult(source=source)

        # iocextract handles: IPs, URLs, hashes, emails
        try:
            result.ips = list(set(iocextract.extract_ipv4s(refanged, refang=True)))
            result.urls = list(set(iocextract.extract_urls(refanged, refang=True)))
            result.md5s = list(set(iocextract.extract_md5_hashes(refanged)))
            result.sha1s = list(set(iocextract.extract_sha1_hashes(refanged)))
            result.sha256s = list(set(iocextract.extract_sha256_hashes(refanged)))
            result.emails = list(set(iocextract.extract_emails(refanged, refang=True)))
            # Extract domains tu URLs
            import re as _re
            domain_pattern = _re.compile(
                r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
            )
            raw_domains = list(set(domain_pattern.findall(refanged)))
            ignore_exts = ('.exe', '.dll', '.bat', '.txt', '.pdf', '.png', '.sys')
            result.domains = [d for d in raw_domains if not d.lower().endswith(ignore_exts)][:30]
        except Exception as e:
            logger.warning(f"iocextract error: {e}")

        # Custom extractors
        custom = _extract_custom(refanged)
        result.mitre_ids = custom["mitre_ids"]
        result.cves = custom["cves"]
        result.registry_keys = custom["registry_keys"]
        result.mutexes = custom["mutexes"]
        result.file_paths = custom["file_paths"]

        logger.info(f"Extracted {result.total_count} IOCs from {source}")
        return result

    def extract_from_pdf(self, file_path: Path) -> IOCResult:
        """
        Extract IOCs tu PDF threat report.
        Su dung PyMuPDF cho text, pdfplumber cho tables.
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"PDF not found: {path}")

        all_text = []
        table_text = []

        # Stage 1: PyMuPDF cho text nhanh
        try:
            doc = fitz.open(str(path))
            for page in doc:
                all_text.append(page.get_text("text"))
            doc.close()
            logger.info(f"PyMuPDF extracted {len(all_text)} pages")
        except Exception as e:
            logger.warning(f"PyMuPDF failed: {e}")

        # Stage 2: pdfplumber cho tables (IOC tables hay co trong threat reports)
        try:
            with pdfplumber.open(str(path)) as pdf:
                for page in pdf.pages:
                    tables = page.extract_tables()
                    for table in tables:
                        for row in table:
                            if row:
                                table_text.append(
                                    " ".join(cell or "" for cell in row)
                                )
            logger.info(f"pdfplumber extracted {len(table_text)} table rows")
        except Exception as e:
            logger.warning(f"pdfplumber failed: {e}")

        full_text = "\n".join(all_text + table_text)
        return self.extract_from_text(full_text, source=str(path.name))

    def extract_from_evtx(self, file_path: Path) -> list[EventRecord]:
        """
        Parse Windows EVTX file thanh list EventRecord.
        Require: pip install python-evtx
        """
        try:
            import Evtx.Evtx as evtx
            import xml.etree.ElementTree as ET
        except ImportError:
            raise ImportError(
                "python-evtx not installed. Run: pip install python-evtx"
            )

        path = Path(file_path)
        records = []

        with evtx.Evtx(str(path)) as log:
            for record in log.records():
                try:
                    xml_str = record.xml()
                    root = ET.fromstring(xml_str)
                    ns = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}

                    system = root.find("ns:System", ns)
                    if system is None:
                        continue

                    event_id_el = system.find("ns:EventID", ns)
                    event_id = int(event_id_el.text) if event_id_el is not None else 0

                    channel_el = system.find("ns:Channel", ns)
                    channel = channel_el.text if channel_el is not None else ""

                    computer_el = system.find("ns:Computer", ns)
                    computer = computer_el.text if computer_el is not None else ""

                    time_el = system.find(".//ns:TimeCreated", ns)
                    timestamp = time_el.get("SystemTime", "") if time_el is not None else ""

                    provider_el = system.find("ns:Provider", ns)
                    provider = provider_el.get("Name", "") if provider_el is not None else ""

                    # EventData fields
                    event_data = {}
                    ed = root.find("ns:EventData", ns)
                    if ed is not None:
                        for data_el in ed.findall("ns:Data", ns):
                            name = data_el.get("Name", "")
                            value = data_el.text or ""
                            if name:
                                event_data[name] = value

                    records.append(EventRecord(
                        event_id=event_id,
                        channel=channel,
                        computer=computer,
                        timestamp=timestamp,
                        provider=provider,
                        data=event_data,
                    ))

                except Exception as e:
                    logger.debug(f"Skip record: {e}")
                    continue

        logger.info(f"Parsed {len(records)} records from {path.name}")
        return records

    def extract_from_url(self, url: str) -> IOCResult:
        """Scrape threat blog post va extract IOCs."""
        import requests
        from bs4 import BeautifulSoup

        try:
            resp = requests.get(url, timeout=15, headers={
                "User-Agent": "Mozilla/5.0 (CTI Research Bot)"
            })
            resp.raise_for_status()
            soup = BeautifulSoup(resp.text, "html.parser")
            # Lay text chinh, bo nav/footer
            for tag in soup(["script", "style", "nav", "footer", "header"]):
                tag.decompose()
            text = soup.get_text(separator="\n")
            return self.extract_from_text(text, source=url)
        except Exception as e:
            logger.error(f"URL scraping failed for {url}: {e}")
            return IOCResult(source=url)
