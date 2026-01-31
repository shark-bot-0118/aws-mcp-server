"""Local file and folder utilities for blob field uploads.

This module provides functionality to handle $path syntax in blob fields,
allowing users to specify local file paths instead of base64-encoded content.

Usage in payload:
    {"Body": {"$path": "/path/to/file.png"}}
    {"Body": {"$path": "/path/to/folder", "keyPrefix": "uploads/"}}
"""

from __future__ import annotations

import io
import mimetypes
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator

# Service-specific blob size limits (in bytes)
BLOB_SIZE_LIMITS: dict[str, dict[str, int]] = {
    "s3": {
        "Body": 5 * 1024 * 1024 * 1024,  # 5GB for single PUT
    },
    "lambda": {
        "ZipFile": 50 * 1024 * 1024,  # 50MB direct upload
        "Code.ZipFile": 50 * 1024 * 1024,
    },
    "rekognition": {
        "Image.Bytes": 5 * 1024 * 1024,  # 5MB
        "Bytes": 5 * 1024 * 1024,
    },
    "textract": {
        "Document.Bytes": 5 * 1024 * 1024,  # 5MB for sync
        "Bytes": 5 * 1024 * 1024,
    },
    "kinesis": {
        "Data": 1 * 1024 * 1024,  # 1MB default (can be 10MB with config)
    },
    "kms": {
        "Plaintext": 4 * 1024,  # 4KB
        "CiphertextBlob": 4 * 1024,
    },
    "secretsmanager": {
        "SecretBinary": 64 * 1024,  # 64KB
    },
}

# Services that support folder uploads
FOLDER_SUPPORT: dict[str, set[str]] = {
    "s3": {"PutObject"},  # Multiple PutObject calls
    "lambda": {"CreateFunction", "UpdateFunctionCode"},  # Auto-zip
}


@dataclass
class LocalFileInfo:
    """Information about a local file or folder."""

    path: Path
    is_file: bool
    is_folder: bool
    size: int
    content_type: str | None = None


@dataclass
class FileEntry:
    """A single file entry for upload."""

    local_path: Path
    relative_key: str
    size: int
    content_type: str | None


class LocalFileError(Exception):
    """Base exception for local file operations."""

    pass


class PathNotFoundError(LocalFileError):
    """Raised when the specified path does not exist."""

    pass


class FileTooLargeError(LocalFileError):
    """Raised when file exceeds service limit."""

    def __init__(self, path: str, size: int, limit: int, service: str, field: str):
        self.path = path
        self.size = size
        self.limit = limit
        self.service = service
        self.field = field
        super().__init__(
            f"File '{path}' ({_format_size(size)}) exceeds {service} {field} limit "
            f"of {_format_size(limit)}"
        )


class FolderNotSupportedError(LocalFileError):
    """Raised when folder upload is not supported for this operation."""

    def __init__(self, service: str, operation: str):
        self.service = service
        self.operation = operation
        super().__init__(
            f"Folder upload is not supported for {service}:{operation}. "
            f"Please specify a single file."
        )


def _format_size(size: int) -> str:
    """Format bytes as human-readable size."""
    for unit in ("B", "KB", "MB", "GB"):
        if abs(size) < 1024:
            return f"{size:.1f}{unit}"
        size = int(size / 1024)
    return f"{size:.1f}TB"


def is_path_spec(value: object) -> bool:
    """Check if value is a $path specification.

    Returns True if value is a dict containing "$path" key.
    """
    return isinstance(value, dict) and "$path" in value


def parse_path_spec(value: dict) -> tuple[str, dict]:
    """Parse a $path specification.

    Args:
        value: Dict containing "$path" and optional keys like "keyPrefix", "recursive"

    Returns:
        Tuple of (path_string, options_dict)
    """
    path = value["$path"]
    options = {k: v for k, v in value.items() if k != "$path"}
    return str(path), options


def get_file_info(path_str: str) -> LocalFileInfo:
    """Get information about a local file or folder.

    Args:
        path_str: Path to file or folder (supports ~ expansion)

    Returns:
        LocalFileInfo with path details

    Raises:
        PathNotFoundError: If path does not exist
    """
    path = Path(path_str).expanduser().resolve()

    if not path.exists():
        raise PathNotFoundError(f"Path not found: {path}")

    is_file = path.is_file()
    is_folder = path.is_dir()

    if is_file:
        size = path.stat().st_size
        content_type, _ = mimetypes.guess_type(str(path))
    else:
        # Calculate total folder size
        size = sum(f.stat().st_size for f in path.rglob("*") if f.is_file())
        content_type = None

    return LocalFileInfo(
        path=path,
        is_file=is_file,
        is_folder=is_folder,
        size=size,
        content_type=content_type,
    )


def check_size_limit(
    info: LocalFileInfo,
    service: str,
    field: str,
) -> None:
    """Check if file/folder size is within service limits.

    Args:
        info: LocalFileInfo to check
        service: AWS service name (lowercase)
        field: Field name (e.g., "Body", "ZipFile")

    Raises:
        FileTooLargeError: If size exceeds limit
    """
    service_limits = BLOB_SIZE_LIMITS.get(service.lower(), {})
    limit = service_limits.get(field)

    if limit is None:
        # No specific limit known, use a reasonable default (100MB)
        limit = 100 * 1024 * 1024

    if info.size > limit:
        raise FileTooLargeError(
            path=str(info.path),
            size=info.size,
            limit=limit,
            service=service,
            field=field,
        )


def supports_folder(service: str, operation: str) -> bool:
    """Check if the service/operation supports folder uploads.

    Args:
        service: AWS service name (lowercase)
        operation: Operation name

    Returns:
        True if folder upload is supported
    """
    supported_ops = FOLDER_SUPPORT.get(service.lower(), set())
    return operation in supported_ops


def read_file_bytes(info: LocalFileInfo) -> bytes:
    """Read file content as bytes.

    Args:
        info: LocalFileInfo for a file (not folder)

    Returns:
        File content as bytes
    """
    if not info.is_file:
        raise LocalFileError(f"Expected file, got directory: {info.path}")
    return info.path.read_bytes()


def iter_folder_files(
    folder_path: Path,
    recursive: bool = True,
) -> Iterator[FileEntry]:
    """Iterate over files in a folder.

    Args:
        folder_path: Path to folder
        recursive: If True, include files in subdirectories

    Yields:
        FileEntry for each file
    """
    if recursive:
        files = folder_path.rglob("*")
    else:
        files = folder_path.glob("*")

    for file_path in files:
        if not file_path.is_file():
            continue

        # Skip hidden files and common ignore patterns
        if file_path.name.startswith("."):
            continue
        if "__pycache__" in file_path.parts:
            continue

        relative = file_path.relative_to(folder_path)
        content_type, _ = mimetypes.guess_type(str(file_path))

        yield FileEntry(
            local_path=file_path,
            relative_key=str(relative),
            size=file_path.stat().st_size,
            content_type=content_type,
        )


def create_zip_from_folder(folder_path: Path) -> bytes:
    """Create a ZIP archive from a folder.

    Args:
        folder_path: Path to folder to zip

    Returns:
        ZIP file content as bytes
    """
    buffer = io.BytesIO()

    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for entry in iter_folder_files(folder_path, recursive=True):
            zf.write(entry.local_path, entry.relative_key)

    return buffer.getvalue()


def resolve_path_for_blob(
    value: dict,
    service: str,
    operation: str,
    field: str,
) -> bytes | list[tuple[str, bytes, str | None]]:
    """Resolve a $path specification to bytes or file list.

    Args:
        value: Dict with "$path" key
        service: AWS service name
        operation: Operation name
        field: Field name (e.g., "Body", "ZipFile")

    Returns:
        For single file: bytes content
        For S3 folder: list of (key, bytes, content_type) tuples
        For Lambda folder: ZIP bytes

    Raises:
        PathNotFoundError: Path does not exist
        FileTooLargeError: File exceeds limit
        FolderNotSupportedError: Folder not supported for this operation
    """
    path_str, options = parse_path_spec(value)
    info = get_file_info(path_str)

    if info.is_file:
        check_size_limit(info, service, field)
        return read_file_bytes(info)

    # Folder handling
    if not supports_folder(service, operation):
        raise FolderNotSupportedError(service, operation)

    # Lambda: auto-zip
    if service.lower() == "lambda":
        zip_bytes = create_zip_from_folder(info.path)
        # Check ZIP size limit
        if len(zip_bytes) > BLOB_SIZE_LIMITS["lambda"].get("ZipFile", 50 * 1024 * 1024):
            raise FileTooLargeError(
                path=str(info.path),
                size=len(zip_bytes),
                limit=BLOB_SIZE_LIMITS["lambda"]["ZipFile"],
                service="lambda",
                field="ZipFile",
            )
        return zip_bytes

    # S3: return file list for batch upload
    if service.lower() == "s3":
        key_prefix = options.get("keyPrefix", "")
        recursive = options.get("recursive", True)

        result: list[tuple[str, bytes, str | None]] = []
        for entry in iter_folder_files(info.path, recursive=recursive):
            full_key = key_prefix + entry.relative_key
            content = entry.local_path.read_bytes()
            result.append((full_key, content, entry.content_type))

        return result

    raise FolderNotSupportedError(service, operation)
