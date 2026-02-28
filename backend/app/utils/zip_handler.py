"""Enhanced ZIP file handling with security checks."""

import os
import zipfile
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

MAX_ZIP_SIZE = 500 * 1024 * 1024  # 500MB uncompressed limit
MAX_FILES_IN_ZIP = 5000
MAX_RATIO = 100  # Compression ratio limit (zip bomb protection)


class ZipExtractionError(Exception):
    pass


def safe_extract_zip(zip_path: str, extract_to: str) -> str:
    """Extract a zip file with security validations."""
    if not zipfile.is_zipfile(zip_path):
        raise ZipExtractionError("Not a valid ZIP file")

    with zipfile.ZipFile(zip_path, "r") as zf:
        # Check file count
        members = zf.infolist()
        if len(members) > MAX_FILES_IN_ZIP:
            raise ZipExtractionError(
                f"ZIP contains too many files ({len(members)} > {MAX_FILES_IN_ZIP})"
            )

        # Check total uncompressed size
        total_size = sum(m.file_size for m in members)
        if total_size > MAX_ZIP_SIZE:
            raise ZipExtractionError(f"ZIP uncompressed size too large ({total_size} bytes)")

        # Check compression ratio (zip bomb detection)
        compressed_size = os.path.getsize(zip_path)
        if compressed_size > 0 and total_size / compressed_size > MAX_RATIO:
            raise ZipExtractionError("Suspicious compression ratio — potential zip bomb")

        # Validate paths (no path traversal)
        for member in members:
            member_path = os.path.normpath(member.filename)
            if member_path.startswith("..") or member_path.startswith("/"):
                raise ZipExtractionError(f"Path traversal detected: {member.filename}")
            if "\x00" in member.filename:
                raise ZipExtractionError("Null byte in filename")

        # Extract
        zf.extractall(extract_to)
        logger.info(f"Extracted {len(members)} files ({total_size} bytes) to {extract_to}")

    # Find root directory
    items = os.listdir(extract_to)
    if len(items) == 1 and os.path.isdir(os.path.join(extract_to, items[0])):
        return os.path.join(extract_to, items[0])
    return extract_to


def get_zip_info(zip_path: str) -> dict:
    """Get information about a zip file without extracting."""
    with zipfile.ZipFile(zip_path, "r") as zf:
        members = zf.infolist()
        extensions = {}
        for m in members:
            if not m.is_dir():
                ext = Path(m.filename).suffix.lower()
                extensions[ext] = extensions.get(ext, 0) + 1

        return {
            "file_count": len([m for m in members if not m.is_dir()]),
            "total_size": sum(m.file_size for m in members),
            "extensions": extensions,
            "directories": len([m for m in members if m.is_dir()]),
        }
