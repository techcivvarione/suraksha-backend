import io

import pytest
from fastapi import UploadFile

from app.services.media_validator import validate_upload


def _upload(data: bytes, filename: str, content_type: str) -> UploadFile:
    return UploadFile(filename=filename, file=io.BytesIO(data), content_type=content_type)


def test_valid_mp4_passes(tmp_path):
    payload = b"\x00\x00\x00\x18ftypmp42" + b"\x00" * 1000
    upload = _upload(payload, "sample.mp4", "video/mp4")
    result = validate_upload(upload)
    assert result.analysis_type == "VIDEO"
    assert result.size == len(payload)


def test_invalid_mime_rejected():
    payload = b"notvalid"
    upload = _upload(payload, "sample.txt", "text/plain")
    with pytest.raises(Exception):
        validate_upload(upload)


def test_double_extension_rejected():
    payload = b"\x00\x00\x00\x18ftypmp42" + b"\x00" * 100
    upload = _upload(payload, "sample.mp4.exe", "video/mp4")
    with pytest.raises(Exception):
        validate_upload(upload)
