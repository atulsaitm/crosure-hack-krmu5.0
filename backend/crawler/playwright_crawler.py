"""Async Playwright-based web crawler with JS rendering."""

import asyncio
import re
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from typing import List, Dict, Set, Optional, Tuple
from playwright.async_api import async_playwright, Page, Browser, BrowserContext
from bs4 import BeautifulSoup
import networkx as nx

from core.models import CrawledEndpoint
from config import settings


class PlaywrightCrawler:
    """Intelligent web crawler with JS rendering and attack surface mapping."""

    def __init__(
        self,
        target_url: str,
        max_pages: int = None,
        auth_cookie: Optional[str] = None,
        scan_depth: int = 3,
    ):
        self.target_url = target_url.rstrip("/")
        self.base_domain = urlparse(target_url).netloc
        self.max_pages = max_pages or settings.MAX_CRAWL_PAGES
        self.auth_cookie = auth_cookie
        self.scan_depth = scan_depth

        self.visited: Set[str] = set()
        self.endpoints: List[CrawledEndpoint] = []
        self.nav_graph = nx.DiGraph()
        self.detected_framework: Optional[str] = None
        self.discovered_tech: List[str] = []

        self._browser: Optional[Browser] = None
        self._context: Optional[BrowserContext] = None

    async def crawl(self, progress_callback=None) -> Tuple[List[CrawledEndpoint], nx.DiGraph]:
        """Main crawl method. Returns discovered endpoints and navigation graph."""
        async with async_playwright() as p:
            self._browser = await p.chromium.launch(headless=True)
            self._context = await self._browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Crosure/1.0",
                ignore_https_errors=True,
            )

            # Set auth cookies if provided
            if self.auth_cookie:
                await self._set_cookies()

            # Intercept API calls
            api_urls: List[str] = []
            ws_urls: List[str] = []

            self._context.on("request", lambda req: api_urls.append(req.url)
                             if "/api/" in req.url or req.resource_type == "fetch" else None)

            # Start crawling from target URL
            queue = [(self.target_url, 0, None)]

            while queue and len(self.visited) < self.max_pages:
                url, depth, parent = queue.pop(0)

                if depth > self.scan_depth:
                    continue

                normalized = self._normalize_url(url)
                if normalized in self.visited:
                    continue
                if not self._is_same_domain(url):
                    continue

                self.visited.add(normalized)

                try:
                    page = await self._context.new_page()
                    page.set_default_timeout(settings.CRAWL_TIMEOUT * 1000)

                    # Collect WebSocket URLs
                    page.on("websocket", lambda ws: ws_urls.append(ws.url))

                    response = await page.goto(url, wait_until="networkidle", timeout=settings.CRAWL_TIMEOUT * 1000)

                    if not response:
                        await page.close()
                        continue

                    # Detect framework on first page
                    if self.detected_framework is None:
                        self.detected_framework = await self._detect_framework(page)

                    # Detect technology stack
                    if response.headers:
                        self._detect_tech(dict(response.headers))

                    # Get page content
                    content = await page.content()
                    soup = BeautifulSoup(content, "html.parser")

                    # Extract links
                    links = await self._extract_links(page, soup, url)
                    # Extract forms
                    forms = self._extract_forms(soup, url)
                    # Extract JS endpoints
                    js_endpoints = self._extract_js_endpoints(content, url)

                    # Add current page as endpoint
                    parsed = urlparse(url)
                    params = parse_qs(parsed.query)
                    flat_params = {k: v[0] if v else "" for k, v in params.items()}

                    endpoint = CrawledEndpoint(
                        url=url,
                        method="GET",
                        params=flat_params,
                        requires_auth=self._check_auth_required(response),
                        depth=depth,
                        parent_url=parent,
                        framework=self.detected_framework,
                    )
                    self.endpoints.append(endpoint)

                    # Add to navigation graph
                    self.nav_graph.add_node(url, depth=depth, auth_required=endpoint.requires_auth)
                    if parent:
                        self.nav_graph.add_edge(parent, url)

                    # Add form endpoints
                    for form in forms:
                        self.endpoints.append(form)
                        self.nav_graph.add_node(form.url, depth=depth + 1, method=form.method)
                        self.nav_graph.add_edge(url, form.url)

                    # Queue discovered links
                    for link in links + js_endpoints:
                        norm_link = self._normalize_url(link)
                        if norm_link not in self.visited and self._is_same_domain(link):
                            queue.append((link, depth + 1, url))

                    # Report progress
                    if progress_callback:
                        progress = min(len(self.visited) / self.max_pages * 100, 100)
                        await progress_callback(progress, url)

                    await page.close()

                except Exception as e:
                    print(f"Crawl error at {url}: {e}")
                    continue

            # Add discovered API endpoints
            for api_url in set(api_urls):
                if self._is_same_domain(api_url) and self._normalize_url(api_url) not in self.visited:
                    parsed = urlparse(api_url)
                    params = parse_qs(parsed.query)
                    flat_params = {k: v[0] if v else "" for k, v in params.items()}
                    endpoint = CrawledEndpoint(
                        url=api_url, method="GET", params=flat_params,
                        content_type="application/json", depth=0,
                    )
                    self.endpoints.append(endpoint)

            # Add WebSocket endpoints
            for ws_url in set(ws_urls):
                endpoint = CrawledEndpoint(
                    url=ws_url, method="WS", depth=0,
                )
                self.endpoints.append(endpoint)

            await self._browser.close()

        return self.endpoints, self.nav_graph

    async def _set_cookies(self):
        """Parse and set auth cookies."""
        if not self.auth_cookie:
            return
        parsed = urlparse(self.target_url)
        cookies = []
        for part in self.auth_cookie.split(";"):
            if "=" in part:
                name, value = part.strip().split("=", 1)
                cookies.append({
                    "name": name.strip(),
                    "value": value.strip(),
                    "domain": parsed.hostname,
                    "path": "/",
                })
        if cookies:
            await self._context.add_cookies(cookies)

    async def _detect_framework(self, page: Page) -> Optional[str]:
        """Detect client-side JS framework."""
        try:
            result = await page.evaluate("""() => {
                if (window.angular || document.querySelector('[ng-app]') || document.querySelector('[ng-controller]'))
                    return 'angular';
                if (window.__NEXT_DATA__) return 'nextjs';
                if (window.__NUXT__) return 'nuxt';
                if (document.querySelector('[data-reactroot]') || window.__REACT_DEVTOOLS_GLOBAL_HOOK__)
                    return 'react';
                if (window.__VUE__ || document.querySelector('[data-v-]'))
                    return 'vue';
                if (document.querySelector('[mv-app]') || document.querySelector('[mv-storage]'))
                    return 'mavo';
                return null;
            }""")
            return result
        except Exception:
            return None

    def _detect_tech(self, headers: Dict[str, str]):
        """Detect technology from response headers."""
        server = headers.get("server", "")
        powered_by = headers.get("x-powered-by", "")
        if server and server not in self.discovered_tech:
            self.discovered_tech.append(server)
        if powered_by and powered_by not in self.discovered_tech:
            self.discovered_tech.append(powered_by)

    async def _extract_links(self, page: Page, soup: BeautifulSoup, base_url: str) -> List[str]:
        """Extract links from the page."""
        links = set()

        # From HTML href attributes
        for tag in soup.find_all(["a", "link", "area"], href=True):
            href = tag["href"]
            if href and not href.startswith(("#", "javascript:", "mailto:", "tel:")):
                full_url = urljoin(base_url, href)
                links.add(full_url)

        # From src attributes
        for tag in soup.find_all(["script", "iframe", "img"], src=True):
            src = tag["src"]
            if src and not src.startswith("data:"):
                links.add(urljoin(base_url, src))

        return list(links)

    def _extract_forms(self, soup: BeautifulSoup, base_url: str) -> List[CrawledEndpoint]:
        """Extract form endpoints."""
        forms = []
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "GET").upper()
            form_url = urljoin(base_url, action) if action else base_url

            # Extract form fields
            fields = {}
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if name:
                    value = inp.get("value", "")
                    input_type = inp.get("type", "text")
                    if input_type == "hidden":
                        fields[name] = value
                    else:
                        fields[name] = value or "test"

            endpoint = CrawledEndpoint(
                url=form_url,
                method=method,
                params=fields if method == "GET" else {},
                form_data=fields if method == "POST" else None,
                content_type="application/x-www-form-urlencoded" if method == "POST" else None,
                depth=0,
                parent_url=base_url,
            )
            forms.append(endpoint)
        return forms

    def _extract_js_endpoints(self, content: str, base_url: str) -> List[str]:
        """Extract API endpoints from JavaScript source."""
        endpoints = set()

        # Regex patterns for API paths in JS
        patterns = [
            r'["\'](/api/[^"\']+)["\']',
            r'["\'](/rest/[^"\']+)["\']',
            r'["\'](/v[0-9]+/[^"\']+)["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'\.get\(["\']([^"\']+)["\']',
            r'\.post\(["\']([^"\']+)["\']',
            r'\.put\(["\']([^"\']+)["\']',
            r'\.delete\(["\']([^"\']+)["\']',
            r'axios[^(]*\(["\']([^"\']+)["\']',
            r'XMLHttpRequest[^]*open\([^,]+,\s*["\']([^"\']+)["\']',
        ]

        for pattern in patterns:
            for match in re.finditer(pattern, content):
                path = match.group(1)
                if path.startswith("http"):
                    endpoints.add(path)
                elif path.startswith("/"):
                    endpoints.add(urljoin(base_url, path))

        return list(endpoints)

    def _normalize_url(self, url: str) -> str:
        """Normalize URL for deduplication."""
        parsed = urlparse(url)
        # Remove fragment, normalize path
        normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path.rstrip('/')}"
        if parsed.query:
            # Sort query params for consistent comparison
            params = parse_qs(parsed.query)
            sorted_params = sorted(params.keys())
            normalized += "?" + "&".join(f"{k}=" for k in sorted_params)
        return normalized

    def _is_same_domain(self, url: str) -> bool:
        """Check if URL belongs to the target domain."""
        try:
            parsed = urlparse(url)
            return parsed.netloc == self.base_domain or not parsed.netloc
        except Exception:
            return False

    def _check_auth_required(self, response) -> bool:
        """Check if the page requires authentication."""
        if response.status in (401, 403):
            return True
        if response.url and ("login" in response.url.lower() or "signin" in response.url.lower()):
            return True
        return False
