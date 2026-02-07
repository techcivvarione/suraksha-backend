from abc import ABC, abstractmethod


class BreachProvider(ABC):

    @abstractmethod
    def check_email(self, email: str) -> dict:
        """
        Returns:
        {
          breached: bool,
          risk: low|medium|high,
          score: int,
          reasons: list[str]
        }
        """
        pass

    @abstractmethod
    def check_password(self, password: str) -> dict:
        """
        Password must NEVER be stored or logged.
        Uses k-anonymity.
        """
        pass
