from abc import ABC, abstractmethod
from typing import Dict


class RealityDetectionError(Exception):
    def __init__(
        self,
        message: str,
        *,
        provider: str = "unknown",
        status_code: int | None = None,
        response_body: str | None = None,
    ):
        super().__init__(message)
        self.provider = provider
        self.status_code = status_code
        self.response_body = response_body


class BaseRealityProvider(ABC):
    @abstractmethod
    async def detect(self, file_path: str, mime_type: str) -> Dict[str, float]:
        """
        Returns {"probability": float}
        Raises RealityDetectionError on failure.
        """
        raise NotImplementedError
