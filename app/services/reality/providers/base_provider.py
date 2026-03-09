from abc import ABC, abstractmethod
from typing import Dict


class RealityDetectionError(Exception):
    pass


class BaseRealityProvider(ABC):
    @abstractmethod
    async def detect(self, file_path: str, mime_type: str) -> Dict[str, float]:
        """
        Returns {"probability": float}
        Raises RealityDetectionError on failure.
        """
        raise NotImplementedError
