import re
import hashlib
from pathlib import Path


def calculate_hashes(file_path):
    """Calculate common forensic hashes."""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


def extract_iocs(file_path):
    """
    Extract common Indicators of Compromise (IOCs)
    from readable content in an evidence file.
    """

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Evidence file not found: {file_path}")

    # Read as text while safely ignoring undecodable bytes
    with open(path, "rb") as f:
        raw_data = f.read()

    text = raw_data.decode("utf-8", errors="ignore")

    # IPv4 addresses
    ip_pattern = r"\b(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b"

    # URLs
    url_pattern = r"https?://[^\s\"'<>]+"

    # Email addresses
    email_pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"

    # Domain names
    domain_pattern = r"\b(?:[A-Za-z0-9-]+\.)+(?:com|net|org|io|in|edu|gov|co|uk|de|xyz|info|biz)\b"

    # Hashes
    hash_pattern = r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b"

    iocs = {
        "ip_addresses": sorted(set(re.findall(ip_pattern, text))),
        "urls": sorted(set(re.findall(url_pattern, text))),
        "email_addresses": sorted(set(re.findall(email_pattern, text))),
        "domains": sorted(set(re.findall(domain_pattern, text))),
        "hashes": sorted(set(re.findall(hash_pattern, text))),
    }

    iocs["file_hashes"] = calculate_hashes(file_path)

    return iocs
