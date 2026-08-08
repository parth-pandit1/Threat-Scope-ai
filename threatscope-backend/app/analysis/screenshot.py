"""
URL screenshot capture and page intelligence extraction via Playwright.

Uses headless Chromium to navigate to URLs, capture screenshots
(uploaded to MinIO), track redirect chains, and inspect the DOM
for phishing indicators (login forms, hidden iframes, external
scripts).

All operations are async — called from RQ via ``_run_async()``.
Gracefully degrades if Playwright is not installed.
"""

import logging
import time
from typing import Any

logger = logging.getLogger(__name__)


async def capture_screenshot(url: str, job_id: str) -> dict[str, Any]:
    """
    Launch headless Chromium, navigate to the URL, and capture a
    viewport screenshot.

    The screenshot PNG is uploaded to MinIO at
    ``screenshots/{job_id}.png``.

    Args:
        url: Full URL to visit.
        job_id: Scan UUID (used as the MinIO object key).

    Returns:
        Dictionary with screenshot path, page title, final URL,
        redirect chain, and load time.
    """
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        logger.warning("Playwright not installed — screenshot capture disabled")
        return {
            "screenshot_available": False,
            "error": "Playwright not installed",
        }

    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                ],
            )
            context = await browser.new_context(
                viewport={"width": 1280, "height": 800},
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/125.0.0.0 Safari/537.36"
                ),
                ignore_https_errors=True,
            )
            page = await context.new_page()

            # Block heavy resources for faster page load
            async def _route_handler(route):
                if route.request.resource_type in ("media", "font"):
                    await route.abort()
                else:
                    await route.continue_()

            await page.route("**/*", _route_handler)

            # Track redirect chain
            redirect_chain: list[str] = []

            def _on_response(response):
                if response.status in (301, 302, 303, 307, 308):
                    redirect_chain.append(response.url)

            page.on("response", _on_response)

            # Navigate
            start = time.monotonic()
            try:
                await page.goto(url, timeout=15000, wait_until="domcontentloaded")
                # Give the page a moment to settle
                await page.wait_for_timeout(2000)
            except Exception as nav_exc:
                logger.warning("Page navigation issue for %s: %s", url, str(nav_exc))

            load_time_ms = int((time.monotonic() - start) * 1000)

            page_title = await page.title() or ""
            final_url = page.url

            # Capture screenshot
            screenshot_bytes = await page.screenshot(full_page=False, type="png")

            await browser.close()

        # Upload screenshot to MinIO
        object_name = f"screenshots/{job_id}.png"
        try:
            from app.core.storage import upload_file

            upload_file(screenshot_bytes, object_name, "image/png")
            logger.info("Screenshot uploaded to MinIO: %s", object_name)
        except Exception as upload_exc:
            logger.warning("Failed to upload screenshot to MinIO: %s", str(upload_exc))
            object_name = None

        return {
            "screenshot_available": True,
            "screenshot_path": object_name,
            "page_title": page_title,
            "final_url": final_url,
            "redirect_count": len(redirect_chain),
            "redirect_chain": redirect_chain[:10],
            "page_load_time_ms": load_time_ms,
            "error": None,
        }

    except Exception as exc:
        logger.warning("Screenshot capture failed for %s: %s", url, str(exc))
        return {
            "screenshot_available": False,
            "error": str(exc),
        }


async def extract_page_intel(url: str) -> dict[str, Any]:
    """
    Deep DOM inspection for phishing and malicious page indicators.

    Launches a separate headless browser to inspect:
    - Hidden iframes (display:none, 0×0, 1×1)
    - External JavaScript sources
    - Form action URLs (credential stealing)
    - Password input fields
    - Login form patterns
    - First 500 chars of visible page text

    Args:
        url: Full URL to inspect.

    Returns:
        Dictionary of page intelligence findings.
    """
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return {"page_intel_available": False, "error": "Playwright not installed"}

    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage"],
            )
            context = await browser.new_context(
                viewport={"width": 1280, "height": 800},
                ignore_https_errors=True,
            )
            page = await context.new_page()

            try:
                await page.goto(url, timeout=15000, wait_until="domcontentloaded")
                await page.wait_for_timeout(2000)
            except Exception:
                pass  # Still inspect whatever loaded

            # ── Hidden iframes ───────────────
            hidden_iframes = await page.evaluate("""
                () => {
                    const iframes = document.querySelectorAll('iframe');
                    return Array.from(iframes)
                        .filter(f => {
                            const style = window.getComputedStyle(f);
                            return (
                                style.display === 'none' ||
                                style.visibility === 'hidden' ||
                                f.width === '0' || f.width === '1' ||
                                f.height === '0' || f.height === '1' ||
                                parseInt(style.width) <= 1 ||
                                parseInt(style.height) <= 1
                            );
                        })
                        .map(f => f.src)
                        .filter(src => src && src.length > 0);
                }
            """)

            # ── External scripts ─────────────
            external_scripts = await page.evaluate("""
                () => {
                    return Array.from(document.querySelectorAll('script[src]'))
                        .map(s => s.src)
                        .filter(src => {
                            try {
                                return new URL(src).hostname !== window.location.hostname;
                            } catch { return false; }
                        });
                }
            """)

            # ── Form actions ─────────────────
            form_actions = await page.evaluate("""
                () => {
                    return Array.from(document.querySelectorAll('form'))
                        .map(f => f.action)
                        .filter(a => a && a !== '' && a !== window.location.href);
                }
            """)

            # ── Password fields ──────────────
            has_password_field = await page.evaluate("""
                () => document.querySelectorAll('input[type="password"]').length > 0
            """)

            # ── Login form ───────────────────
            has_login_form = await page.evaluate("""
                () => {
                    const forms = document.querySelectorAll('form');
                    return Array.from(forms).some(
                        f => f.querySelector('input[type="password"]')
                    );
                }
            """)

            # ── Page text sample ─────────────
            page_text_sample = await page.evaluate("""
                () => {
                    const text = document.body ? document.body.innerText : '';
                    return text.substring(0, 500);
                }
            """)

            await browser.close()

            return {
                "page_intel_available": True,
                "hidden_iframes": hidden_iframes or [],
                "external_scripts": (external_scripts or [])[:20],
                "form_actions": form_actions or [],
                "has_password_field": bool(has_password_field),
                "has_login_form": bool(has_login_form),
                "page_text_sample": page_text_sample or "",
            }

    except Exception as exc:
        logger.warning("Page intel extraction failed for %s: %s", url, str(exc))
        return {
            "page_intel_available": False,
            "error": str(exc),
        }
