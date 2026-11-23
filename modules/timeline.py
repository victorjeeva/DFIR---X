import os
from datetime import datetime


def format_timestamp(timestamp):
    """Convert Unix timestamp to readable forensic timestamp."""
    return datetime.fromtimestamp(timestamp).strftime(
        "%Y-%m-%d %H:%M:%S"
    )


def generate_timeline(file_path):
    """
    Generate a basic forensic timeline for an evidence file.
    """

    if not file_path:
        raise ValueError("Evidence file path is empty.")

    if not os.path.isfile(file_path):
        raise FileNotFoundError(
            f"Evidence file not found: {file_path}"
        )

    stat = os.stat(file_path)

    timeline = {
        "file_path": file_path,
        "file_size": stat.st_size,
        "created": format_timestamp(stat.st_ctime),
        "modified": format_timestamp(stat.st_mtime),
        "accessed": format_timestamp(stat.st_atime),
    }

    return timeline
