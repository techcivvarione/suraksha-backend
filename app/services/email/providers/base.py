from abc import ABC, abstractmethod
from typing import Dict, Any


class EmailBreachProvider(ABC):
    @abstractmethod
    def lookup(self, email: str) -> Dict[str, Any]:
        """
        Returns:
        {
          "breach_count": int,
          "latest_year": int | None,
          "sources": list[str] | None
        }
        """
        raise NotImplementedError
