"""Base plugin interface for vulnerability detection."""

from abc import ABC, abstractmethod
from typing import List, Optional
import httpx

from core.models import Finding, CrawledEndpoint


class BasePlugin(ABC):
    """Abstract base for all vulnerability detection plugins."""

    name: str = "base"
    description: str = ""

    @abstractmethod
    async def detect(
        self,
        endpoint: CrawledEndpoint,
        session: httpx.AsyncClient,
        context: Optional[dict] = None,
    ) -> List[Finding]:
        """
        Run detection against a single endpoint.
        Returns a list of Findings (may be empty).
        """
        ...

    async def _send_request(
        self,
        session: httpx.AsyncClient,
        url: str,
        method: str = "GET",
        params: dict = None,
        data: dict = None,
        headers: dict = None,
        timeout: float = 10.0,
    ) -> Optional[httpx.Response]:
        """Helper to send HTTP requests with error handling."""
        try:
            if method.upper() == "GET":
                return await session.get(url, params=params, headers=headers, timeout=timeout)
            elif method.upper() == "POST":
                return await session.post(url, data=data, params=params, headers=headers, timeout=timeout)
            elif method.upper() == "PUT":
                return await session.put(url, data=data, params=params, headers=headers, timeout=timeout)
            elif method.upper() == "DELETE":
                return await session.delete(url, params=params, headers=headers, timeout=timeout)
        except Exception:
            return None

    def _baseline_time(self) -> float:
        """Default baseline response time threshold."""
        return 3.0
