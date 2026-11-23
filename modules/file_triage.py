from pathlib import Path
from datetime import datetime
import mimetypes
import hashlib
import shutil
import subprocess


def analyze_file(file_path, original_hash=None):
    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError("Evidence file was not found.")

    stat = path.stat()

    # Read only a small header sample; do not load the entire evidence file.
    with path.open("rb") as evidence_file:
        header = evidence_file.read(16)

    # Basic file-signature hints. These are clues, not proof of file type.
    if header.startswith(b"%PDF-"):
        signature_hint = "PDF document"
    elif header.startswith(b"MZ"):
        signature_hint = "Windows executable (PE candidate)"
    elif header.startswith(b"\x7fELF"):
        signature_hint = "Linux executable (ELF)"
    elif header.startswith(b"PK\x03\x04"):
        signature_hint = "ZIP-based file"
    elif header.startswith(b"\x89PNG\r\n\x1a\n"):
        signature_hint = "PNG image"
    elif header.startswith(b"\xff\xd8\xff"):
        signature_hint = "JPEG image"
    else:
        signature_hint = "No recognized signature in header sample"

    mime_type, _ = mimetypes.guess_type(path.name)

    # Use the local 'file' utility when available for an additional hint.
    file_utility_result = "Not available"
    if shutil.which("file"):
        try:
            result = subprocess.run(
                ["file", "-b", str(path)],
                capture_output=True,
                text=True,
                timeout=15,
                check=False
            )
            file_utility_result = (
                result.stdout.strip()
                if result.returncode == 0
                else "Could not identify file"
            )
        except subprocess.TimeoutExpired:
            file_utility_result = "Identification timed out"

    # Stream the file to calculate SHA-256 without loading it all into RAM.
    digest = hashlib.sha256()
    with path.open("rb") as evidence_file:
        for chunk in iter(lambda: evidence_file.read(1024 * 1024), b""):
            digest.update(chunk)

    current_hash = digest.hexdigest()
    hash_matches = (
        current_hash.lower() == original_hash.lower()
        if original_hash
        else None
    )

    return {
        "name": path.name,
        "path": str(path),
        "size_bytes": stat.st_size,
        "size_mb": round(stat.st_size / (1024 * 1024), 3),
        "modified": datetime.fromtimestamp(
            stat.st_mtime
        ).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z"),
        "mime_type": mime_type or "Unknown / not inferred",
        "signature_hint": signature_hint,
        "file_utility_result": file_utility_result,
        "sha256": current_hash,
        "hash_matches": hash_matches,
    }
