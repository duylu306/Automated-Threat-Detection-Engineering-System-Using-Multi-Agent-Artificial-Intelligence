"""
CTI Enrichment Module
----------------------
Gộp toàn bộ pipeline enrichment cho 1 record CTI (Telegram/X...):

1. Resolve các link rút gọn (ift.tt, bit.ly, t.co, ...) về URL gốc — có cache
   để tránh resolve trùng lặp khi nhiều message share cùng 1 link.
2. Trích CVE ID xuất hiện trong nội dung.
3. Trích link GitHub repo (từ nội dung gốc + các link đã resolve).
4. Gọi GitHub public API lấy metadata (stars, forks, mô tả...) của repo,
   dùng làm tín hiệu "có PoC public hay không" cho việc đánh giá mức độ
   nghiêm trọng/ưu tiên vá lỗi.

Chỉ đọc metadata public, KHÔNG tải/clone/chạy code trong các repo PoC.

Sử dụng:
    from src.enrichment.github_enrichment import enrich_record_with_poc_info

    poc_info = enrich_record_with_poc_info(record.content)
    record.metadata.update(poc_info)
"""

import logging
import os
import re
from typing import Optional

import requests

logger = logging.getLogger(__name__)

# --- Regex patterns ---
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}")
GITHUB_REPO_PATTERN = re.compile(r"github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)")
URL_PATTERN = re.compile(r"https?://\S+")

# --- GitHub API config ---
GITHUB_API_BASE = "https://api.github.com/repos"
# Tùy chọn: đặt GITHUB_TOKEN trong .env để tăng rate limit từ 60 -> 5000 req/giờ.
# Token chỉ cần quyền đọc public repo (không cần scope đặc biệt).
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

# --- Cache trong bộ nhớ, sống theo vòng đời process ---
# key: short_url gốc -> value: resolved_url cuối cùng
_redirect_cache: dict[str, str] = {}
# key: "owner/repo" -> value: metadata dict (hoặc None nếu đã xác nhận không tồn tại)
_repo_metadata_cache: dict[str, Optional[dict]] = {}


def _clean_trailing_punct(url: str) -> str:
    """Dọn dấu câu thừa nếu link nằm cuối câu (ví dụ dấu chấm, dấu phẩy dính vào)."""
    return url.rstrip(").,;:!?\"'")


def resolve_redirect(short_url: str, timeout: int = 10) -> str:
    """
    Theo dõi chuỗi redirect (ift.tt, bit.ly, t.co, ...) để lấy URL đích cuối cùng.
    Kết quả được cache trong bộ nhớ để tránh gọi lại network cho cùng 1 link.
    """
    short_url = _clean_trailing_punct(short_url)

    if short_url in _redirect_cache:
        logger.debug("Cache hit (redirect): %s", short_url)
        return _redirect_cache[short_url]

    resolved = short_url
    try:
        resp = requests.head(short_url, allow_redirects=True, timeout=timeout)
        if resp.status_code >= 400:
            # Một số server không hỗ trợ HEAD đúng cách -> thử lại bằng GET
            resp = requests.get(short_url, allow_redirects=True, timeout=timeout)
        resolved = resp.url
    except requests.exceptions.RequestException as e:
        logger.warning("Không resolve được redirect cho %s: %s", short_url, e)
        # Giữ nguyên short_url gốc nếu thất bại

    _redirect_cache[short_url] = resolved
    return resolved


def extract_cves(text: str) -> list[str]:
    """Trích danh sách CVE ID xuất hiện trong text (loại trùng, giữ thứ tự)."""
    seen = []
    for match in CVE_PATTERN.findall(text):
        if match not in seen:
            seen.append(match)
    return seen


def extract_github_repos(text: str) -> list[str]:
    """Trích danh sách 'owner/repo' xuất hiện trong text (loại trùng)."""
    seen = []
    for owner, repo in GITHUB_REPO_PATTERN.findall(text):
        repo = _clean_trailing_punct(repo)
        full_name = f"{owner}/{repo}"
        if full_name not in seen:
            seen.append(full_name)
    return seen


def fetch_github_repo_metadata(owner_repo: str, timeout: int = 10) -> Optional[dict]:
    """
    Lấy metadata public của 1 GitHub repo (không auth: ~60 req/giờ/IP,
    có GITHUB_TOKEN: ~5000 req/giờ). Kết quả được cache trong bộ nhớ.
    Trả về None nếu repo không tồn tại hoặc lỗi mạng.
    """
    if owner_repo in _repo_metadata_cache:
        logger.debug("Cache hit (repo metadata): %s", owner_repo)
        return _repo_metadata_cache[owner_repo]

    api_url = f"{GITHUB_API_BASE}/{owner_repo}"
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "CTI-Research-Capstone/1.0",  # GitHub API yêu cầu User-Agent, thiếu sẽ bị 403
    }
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"

    result: Optional[dict] = None
    try:
        resp = requests.get(api_url, headers=headers, timeout=timeout)

        if resp.status_code == 404:
            logger.info("Repo không tồn tại hoặc đã bị xóa: %s", owner_repo)
        elif resp.status_code == 403 and resp.headers.get("x-ratelimit-remaining") == "0":
            logger.warning(
                "GitHub API rate limit đã hết (reset lúc %s). "
                "Đặt GITHUB_TOKEN trong .env để tăng hạn mức lên 5000/giờ.",
                resp.headers.get("x-ratelimit-reset"),
            )
            return None  # không cache, cho phép thử lại sau khi rate limit reset
        else:
            resp.raise_for_status()
            data = resp.json()
            result = {
                "repo_full_name": data.get("full_name"),
                "description": data.get("description"),
                "created_at": data.get("created_at"),
                "pushed_at": data.get("pushed_at"),
                "stargazers_count": data.get("stargazers_count", 0),
                "forks_count": data.get("forks_count", 0),
                "language": data.get("language"),
                "html_url": data.get("html_url"),
            }
    except requests.exceptions.RequestException as e:
        logger.warning("Lỗi khi gọi GitHub API cho %s: %s", owner_repo, e)
        return None  # lỗi mạng tạm thời -> không cache, cho phép thử lại

    _repo_metadata_cache[owner_repo] = result
    return result


def enrich_record_with_poc_info(content: str) -> dict:
    """
    Phân tích nội dung 1 record CTI, trả về dict enrichment sẵn sàng
    gắn vào RawCTIRecord.metadata, ví dụ:

    {
        "cve_ids": ["CVE-2026-19490"],
        "poc_available": True,
        "poc_repos": [
            {"repo_full_name": "owner/repo", "stargazers_count": 10, ...}
        ]
    }
    """
    cves = extract_cves(content)

    # Resolve mọi link rút gọn trong content về URL gốc trước khi tìm GitHub repo,
    # vì regex extract_github_repos chỉ match trực tiếp chuỗi "github.com/...".
    raw_urls = URL_PATTERN.findall(content)
    resolved_urls = [resolve_redirect(url) for url in raw_urls]
    combined_text = content + " " + " ".join(resolved_urls)

    repo_names = extract_github_repos(combined_text)

    poc_repos = []
    for owner_repo in repo_names:
        meta = fetch_github_repo_metadata(owner_repo)
        if meta:
            poc_repos.append(meta)

    return {
        "cve_ids": cves,
        "poc_available": len(poc_repos) > 0,
        "poc_repos": poc_repos,
    }


if __name__ == "__main__":
    # Demo nhanh: giả lập 1 message Telegram dạng bot RSS forward (link rút gọn ift.tt)
    sample_text = """
    CVE-2026-19490: NetScaler ADC/Gateway SAML unsigned-assertion bypass (CTX696939)
    https://ift.tt/KJerD42
    Discuss on Reddit: https://ift.tt/8aJQlm6
    @blueteamalerts
    """
    logging.basicConfig(level=logging.INFO)

    result = enrich_record_with_poc_info(sample_text)
    import json
    print(json.dumps(result, indent=2, ensure_ascii=False))

    # Chạy lần 2 để chứng minh cache hoạt động (sẽ không thấy log "resolve"/API call mới)
    print("\n--- Lần 2 (nên dùng cache, không gọi lại network) ---")
    result2 = enrich_record_with_poc_info(sample_text)
    print(json.dumps(result2, indent=2, ensure_ascii=False))