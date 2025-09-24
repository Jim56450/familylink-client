"""Family Link API client (patched for Docker profile-based auth).

- Supports per-profile `sapisid.txt`, `cookies.txt`, and `authuser.txt`.
- Avoids browser_cookie3 in containers (no DBus/keychain).
- Still works on host with browser_cookie3 if not in a profiles dir.
"""

import hashlib
import json
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Optional, Iterable

import os
import httpx
try:
    import browser_cookie3  # may be unavailable in Docker
except Exception:
    browser_cookie3 = None

from http.cookiejar import MozillaCookieJar, CookieJar
from familylink.models import AlwaysAllowedState, AppUsage, MembersResponse

logger = logging.getLogger(__name__)

def _generate_sapisidhash(sapisid: str, origin: str) -> str:
    """Generate the SAPISIDHASH value for Authorization header.
    Format: f"{timestamp} {sha1(f'{timestamp} {sapisid} {origin}')}"
    """
    # ts = int(time.time())
    # to_hash = f"{ts} {sapisid} {origin}".encode("utf-8")
    # digest = hashlib.sha1(to_hash).hexdigest()
    # return f"{ts}_{digest}"  # underscore is accepted by many Google backends

    # ts = int(time.time() * 1000)  # milliseconds
    # digest = hashlib.sha1(f"{ts} {sapisid} {origin}".encode("utf-8")).hexdigest()
    # return f"{ts}_{digest}"  # underscore, not space

    ts = int(time.time() * 1000)
    digest = hashlib.sha1(f"{ts} {sapisid} {origin}".encode()).hexdigest()
    return f"{ts}_{digest}"

    # ts = int(time.time())
    # msg = f"{ts} {sapisid} {origin}".encode("utf-8")
    # digest = hashlib.sha1(msg).hexdigest()
    # return f"{ts} {digest}"  # <— space, not underscore

class FamilyLink:
    """Client to interact with Google Family Link."""

    BASE_URL = "https://kidsmanagement-pa.clients6.google.com/kidsmanagement/v1"
    ORIGIN = "https://familylink.google.com"

    def __init__(
        self,
        account_id: Optional[str] = None,
        browser: str = "firefox",
        cookie_file_path: Optional[Path] = None,
    ):
        """Initialize the Family Link client.

        Args:
            account_id: The Google account ID to manage
            browser: The browser to get cookies from if sapisid not provided
            cookie_file_path: Optional path to a cookie file to load
        """
        self.account_id = account_id

        # --- Environment & profile context ---
        env_browser = os.getenv("FAMILYLINK_BROWSER")
        browser = (env_browser or browser or "chrome").lower()

        profiles_dir = os.getenv("FAMILYLINK_PROFILES_DIR", "").strip()
        cwd = os.getcwd()
        in_profiles_dir = bool(profiles_dir and cwd.startswith(profiles_dir))

        # Per-profile authuser (account index)
        authuser = os.getenv("FAMILYLINK_AUTHUSER", "").strip()
        if in_profiles_dir and not authuser:
            p = Path("authuser.txt")
            if p.exists() and p.is_file():
                authuser = p.read_text(encoding="utf-8").strip()
        if not authuser:
            authuser = "0"

        # --- Cookie/SAPISID sources ---
        sapisid = os.getenv("FAMILYLINK_SAPISID", "").strip() or None
        cookies_jar: Optional[CookieJar] = None

        # ENV cookie file overrides
        env_cookie_file = os.getenv("FAMILYLINK_COOKIE_FILE", "").strip()
        if env_cookie_file:
            cookie_file_path = Path(env_cookie_file)

        # If running under profile dir, first try local sapisid/cookies files
        if in_profiles_dir and not sapisid:
            # a) sapisid.txt or SAPISID file (raw value)
            for fname in ("sapisid.txt", "SAPISID"):
                p = Path(fname)
                if p.exists() and p.is_file():
                    val = p.read_text(encoding="utf-8").strip()
                    if val:
                        sapisid = val
                        break

        # Always try cookies.txt if present (even if sapisid already set)
        if in_profiles_dir and cookies_jar is None:
            p = Path("cookies.txt")
            if p.exists() and p.is_file():
                try:
                    cj = MozillaCookieJar()
                    cj.load(str(p), ignore_discard=True, ignore_expires=True)
                    cookies_jar = cj
                except Exception as e:
                    logger.debug("Failed to load cookies.txt: %s", e)

        # Fallback: explicit cookie file
        if not cookies_jar and cookie_file_path:
            if not cookie_file_path.exists():
                raise ValueError(f"Cookie file not found: {cookie_file_path}")
            if not cookie_file_path.is_file():
                raise ValueError(f"Cookie file is not a file: {cookie_file_path}")
            try:
                cj = MozillaCookieJar()
                cj.load(str(cookie_file_path.resolve()), ignore_discard=True, ignore_expires=True)
                cookies_jar = cj
            except Exception as e:
                logger.debug("Failed to load cookie_file_path: %s", e)

        # Last resort: read from local browser (only when not in container profile dir)
        if not sapisid and not cookies_jar:
            if in_profiles_dir:
                raise RuntimeError(
                    "No cached SAPISID/cookies found in profile dir and browser access is disabled in container. "
                    "Provide sapisid.txt or cookies.txt under the profile folder, or set FAMILYLINK_SAPISID/FAMILYLINK_COOKIE_FILE."
                )
            if browser_cookie3 is None:
                raise RuntimeError("browser_cookie3 not available and no cached session found")
            cookie_kwargs = {}
            if cookie_file_path:
                cookie_kwargs["cookie_file"] = str(cookie_file_path.resolve())
            cookies_jar = getattr(browser_cookie3, browser)(**cookie_kwargs)

        # Extract SAPISID from whatever cookie jar we have (if not from sapisid.txt)
        if not sapisid and cookies_jar is not None:
            for cookie in cookies_jar:
                if cookie.name == "SAPISID" and cookie.domain == ".google.com":
                    sapisid = cookie.value
                    break

        if not sapisid:
            raise ValueError(
                "Could not find SAPISID. "
                "On host: ensure you’re signed in (Chrome/Firefox) or pass FAMILYLINK_COOKIE_FILE. "
                "In Docker: put sapisid.txt (with the raw SAPISID value) or cookies.txt in the profile folder, "
                "or set FAMILYLINK_SAPISID."
            )

        # --- Build headers/session ---
        sapisidhash = _generate_sapisidhash(sapisid, self.ORIGIN)
        authorization = f"SAPISIDHASH {sapisidhash}"

        # self._headers = {
        #     "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
        #     "Origin": self.ORIGIN,
        #     "Content-Type": "application/json+protobuf",
        #     "X-Goog-Api-Key": "AIzaSyAQb1gupaJhY3CXQy2xmTwJMcjmot3M2hw",
        #     "Authorization": authorization,
        #     "X-Goog-AuthUser": authuser,
        # }

        self._headers = {
            "User-Agent": "Mozilla/5.0",
            "Origin": "https://familylink.google.com",  # match working request
            # no Referer
            # no X-Goog-AuthUser
            "Content-Type": "application/json+protobuf",
            "X-Goog-Api-Key": "AIzaSyAQb1gupaJhY3CXQy2xmTwJMcjmot3M2hw",
            "Authorization": f"SAPISIDHASH {_generate_sapisidhash(sapisid, 'https://familylink.google.com')}",
        }

        self._cookies = cookies_jar
        self._session = httpx.Client(headers=self._headers, cookies=self._cookies, timeout=30)
        self._app_names = {}

    # ----------------- minimal API methods -----------------
    def _get(self, path: str, params: Optional[dict] = None) -> httpx.Response:
        url = f"{self.BASE_URL}{path}"
        r = self._session.get(url, params=params)
        r.raise_for_status()
        return r

    def get_members(self) -> MembersResponse:
        """List family members for the authenticated parent."""
        resp = self._get("/families/mine/members")
        data = resp.json()
        return MembersResponse(**data)

    # Optional helper to print usage if your models implement it differently
    def print_usage(self) -> None:
        members = self.get_members().members
        for m in members:
            p = getattr(m, "profile", None)
            if not p:
                continue
            print(f"- {getattr(p,'display_name',None)} | {getattr(p,'email',None)} | user_id={getattr(m,'user_id',None)}")
