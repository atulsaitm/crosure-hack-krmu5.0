"""OpenRouter API client — free cloud LLM backend for fast remediation & triage."""

import httpx
import logging
from typing import Optional
from config import settings

logger = logging.getLogger("crosure.openrouter")

OPENROUTER_BASE = "https://openrouter.ai/api/v1/chat/completions"


async def query_openrouter(
    prompt: str,
    system: str = "",
    model: Optional[str] = None,
    temperature: float = 0.3,
    max_tokens: int = 1024,
) -> str:
    """Query OpenRouter API. Returns empty string on failure."""
    api_key = settings.OPENROUTER_API_KEY
    if not api_key:
        return ""

    model = model or settings.OPENROUTER_MODEL
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    try:
        async with httpx.AsyncClient(timeout=45.0) as client:
            resp = await client.post(
                OPENROUTER_BASE,
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                    "HTTP-Referer": "https://github.com/atulsaitm/crosure-hack-krmu5.0",
                    "X-Title": "Crosure Vulnerability Scanner",
                },
                json={
                    "model": model,
                    "messages": messages,
                    "temperature": temperature,
                    "max_tokens": max_tokens,
                },
            )
            resp.raise_for_status()
            data = resp.json()
            content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
            return content
    except httpx.TimeoutException:
        logger.warning(f"[OPENROUTER] Timeout after 45s (model={model})")
        return ""
    except Exception as e:
        logger.warning(f"[OPENROUTER] Request failed: {e}")
        return ""


async def check_openrouter_available() -> bool:
    """Quick check if OpenRouter API key is set and works."""
    if not settings.OPENROUTER_API_KEY:
        return False
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.get(
                "https://openrouter.ai/api/v1/models",
                headers={"Authorization": f"Bearer {settings.OPENROUTER_API_KEY}"},
            )
            return resp.status_code == 200
    except Exception:
        return False
