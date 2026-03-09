import os
import tempfile
from hashlib import sha256
from typing import Callable, Tuple

from fastapi import HTTPException, UploadFile, status


def _write_temp(file: UploadFile, max_size: int) -> Tuple[str, int, str]:
    fd, path = tempfile.mkstemp(prefix="gosuraksha_media_", suffix=".bin")
    size = 0
    hash_ctx = sha256()
    try:
        with os.fdopen(fd, "wb") as out:
            while True:
                chunk = file.file.read(8192)
                if not chunk:
                    break
                size += len(chunk)
                if size > max_size:
                    raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="File too large")
                out.write(chunk)
                hash_ctx.update(chunk)
        if size == 0:
            raise HTTPException(status_code=400, detail="Empty file")
        return path, size, hash_ctx.hexdigest()
    except Exception:
        if os.path.exists(path):
            try:
                os.remove(path)
            except Exception:
                pass
        raise


def process_upload(
    file: UploadFile,
    allowed_mimes: set,
    max_size: int,
    magic_check: Callable[[bytes], bool],
) -> Tuple[str, int, str, str]:
    if not file:
        raise HTTPException(status_code=400, detail="No file provided")
    mime = (file.content_type or "").lower()
    if mime not in allowed_mimes:
        raise HTTPException(status_code=400, detail="Invalid file type")

    path, size, file_hash = _write_temp(file, max_size)

    try:
        with open(path, "rb") as fh:
            header = fh.read(16)
            if not magic_check(header):
                raise HTTPException(status_code=400, detail="Corrupted or invalid file")

        return path, size, mime, file_hash
    except Exception:
        if os.path.exists(path):
            try:
                os.remove(path)
            except Exception:
                pass
        raise
