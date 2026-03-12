from hashlib import sha256
from pathlib import Path
from typing import Callable, Tuple

from fastapi import HTTPException, UploadFile, status


def _read_upload_bytes(file: UploadFile, max_size: int) -> Tuple[bytes, int, str]:
    size = 0
    hash_ctx = sha256()
    try:
        chunks: list[bytes] = []
        while True:
            chunk = file.file.read(8192)
            if not chunk:
                break
            size += len(chunk)
            if size > max_size:
                raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="File too large")
            chunks.append(chunk)
            hash_ctx.update(chunk)
        if size == 0:
            raise HTTPException(status_code=400, detail="Empty file")
        return b"".join(chunks), size, hash_ctx.hexdigest()
    except Exception:
        raise


def process_upload(
    file: UploadFile,
    allowed_mimes: set,
    allowed_extensions: set[str],
    max_size: int,
    magic_check: Callable[[bytes], bool],
) -> Tuple[bytes, int, str, str]:
    if not file:
        raise HTTPException(status_code=400, detail="No file provided")
    mime = (file.content_type or "").lower()
    if mime not in allowed_mimes:
        raise HTTPException(status_code=400, detail="Invalid file type")
    extension = Path(file.filename or "").suffix.lower()
    if extension not in allowed_extensions:
        raise HTTPException(status_code=400, detail="Invalid file type")

    file_bytes, size, file_hash = _read_upload_bytes(file, max_size)
    header = file_bytes[:16]
    if not magic_check(header):
        raise HTTPException(status_code=400, detail="Corrupted or invalid file")

    return file_bytes, size, mime, file_hash
