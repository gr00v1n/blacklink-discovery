"""Streaming browser-profile HTTP transport; redirects stay under crawler authorization."""

from contextlib import contextmanager

from curl_cffi.requests import Session
from curl_cffi.requests.impersonate import BrowserType

DEFAULT_FINGERPRINTS = ("chrome142", "safari260", "firefox144")
FORBIDDEN_ATTEMPTS = 3


def validate_fingerprints(values):
    profiles = list(values)
    if not profiles or len(profiles) != len(set(profiles)):
        raise ValueError("fingerprints must be a nonempty ordered list without duplicates")
    for profile in profiles:
        BrowserType(profile)
    return profiles


class FingerprintClient:
    def __init__(self, user_agent: str | None = None):
        self.user_agent = user_agent
        self.sessions = {}

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        for session in self.sessions.values():
            session.close()

    @contextmanager
    def stream(self, method: str, url: str, fingerprint: str):
        if fingerprint not in self.sessions:
            self.sessions[fingerprint] = Session(
                impersonate=BrowserType(fingerprint),
                timeout=20,
                allow_redirects=False,
                trust_env=False,
                headers={"User-Agent": self.user_agent} if self.user_agent else {},
            )
        with self.sessions[fingerprint].stream(method, url) as response:
            yield response
