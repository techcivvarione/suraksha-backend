import os
import tempfile
import unicodedata
from hashlib import sha256

from fastapi import HTTPException, UploadFile, status

ALLOWED_MIME = {
    "video/mp4": 25 * 1024 * 1024,
    "video/webm": 25 * 1024 * 1024,
    "audio/mpeg": 10 * 1024 * 1024,
    "audio/wav": 10 * 1024 * 1024,
}

ALLOWED_EXT = {".mp4", ".webm", ".mp3", ".wav"}


class MediaValidationResult:
    def __init__(self, path: str, mime: str, size: int, analysis_type: str, file_hash: str):
        self.path = path
        self.mime = mime
        self.size = size
        self.analysis_type = analysis_type
        self.file_hash = file_hash


def _normalize_filename(name: str) -> str:
    return unicodedata.normalize("NFKC", name) if name else ""


def _double_extension_bad(name: str) -> bool:
    if not name:
        return False
    parts = name.split(".")
    if len(parts) <= 2:
        return False
    # more than one dot and final extension allowed -> treat as suspicious
    return True


def _magic_allows(mime: str, header: bytes) -> bool:
    if mime == "video/mp4":
        return b"ftyp" in header[:12]
    if mime == "video/webm":
        return header.startswith(b"\x1a\x45\xdf\xa3")
    if mime == "audio/mpeg":
        return header.startswith(b"ID3") or header[:2] in (b"\xff\xfb", b"\xff\xf3", b"\xff\xf2")
    if mime == "audio/wav":
        return header.startswith(b"RIFF") and b"WAVE" in header[8:16]
    return False


def _enforce_duration_placeholder():
    """
    Placeholder duration guard; replace with real media duration checks when available.
    """
    return True


def validate_upload(file: UploadFile) -> MediaValidationResult:
    if not file:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No file provided")

    mime = (file.content_type or "").lower()
    if mime not in ALLOWED_MIME:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid file type")

    fname = _normalize_filename(file.filename or "")
    ext = os.path.splitext(fname)[1].lower()
    if ext and ext not in ALLOWED_EXT:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid file extension")
    if _double_extension_bad(fname):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Suspicious filename")

    size_limit = ALLOWED_MIME[mime]
    tmp_fd, tmp_path = tempfile.mkstemp(prefix="gosuraksha_media_", suffix=ext or ".bin")
    hash_ctx = sha256()
    size = 0

    try:
        with os.fdopen(tmp_fd, "wb") as out:
            while True:
                chunk = file.file.read(8192)
                if not chunk:
                    break
                size += len(chunk)
                if size > size_limit:
                    raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="File too large")
                out.write(chunk)
                hash_ctx.update(chunk)
        if size == 0:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Empty file")

        if not _enforce_duration_placeholder():
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Media duration exceeds limit")

        with open(tmp_path, "rb") as fh:
            header = fh.read(16)
            if not _magic_allows(mime, header):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Corrupted or invalid file")

        analysis_type = "VIDEO" if mime.startswith("video/") else "AUDIO"

        return MediaValidationResult(
            path=tmp_path,
            mime=mime,
            size=size,
            analysis_type=analysis_type,
            file_hash=hash_ctx.hexdigest(),
        )
    except Exception:
        # ensure temp file removed on any failure
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass
        raise
