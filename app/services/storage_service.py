from __future__ import annotations

import io
import os
import uuid
from pathlib import Path

import boto3


_client = None


def _require_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"{name} not set")
    return value


def get_storage_client():
    global _client
    if _client is None:
        _client = boto3.client(
            "s3",
            endpoint_url=_require_env("R2_ENDPOINT"),
            aws_access_key_id=_require_env("R2_ACCESS_KEY"),
            aws_secret_access_key=_require_env("R2_SECRET_KEY"),
            region_name="auto",
        )
    return _client


def get_bucket_name() -> str:
    return _require_env("R2_BUCKET")


def upload_file(file_bytes: bytes, filename: str) -> str:
    extension = Path(filename or "").suffix or ".bin"
    object_key = f"scan-uploads/{uuid.uuid4().hex}{extension.lower()}"
    get_storage_client().upload_fileobj(
        io.BytesIO(file_bytes),
        get_bucket_name(),
        object_key,
    )
    return object_key


def download_file(file_key: str) -> bytes:
    buffer = io.BytesIO()
    get_storage_client().download_fileobj(get_bucket_name(), file_key, buffer)
    return buffer.getvalue()


def delete_file(file_key: str) -> None:
    get_storage_client().delete_object(Bucket=get_bucket_name(), Key=file_key)
