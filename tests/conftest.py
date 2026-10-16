from contextlib import contextmanager

import httpx
import pytest


@pytest.fixture
def mock_static_http(monkeypatch):
    """Keep existing response fixtures independent of the production HTTP implementation."""

    def install(handler):
        class Client:
            def __init__(self, user_agent=None):
                self.client = httpx.Client(
                    transport=httpx.MockTransport(handler),
                    headers={"User-Agent": user_agent} if user_agent else {},
                )

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                self.client.close()

            @contextmanager
            def stream(self, method, url, fingerprint):
                with self.client.stream(method, url) as response:

                    class Response:
                        status_code = response.status_code
                        headers = response.headers

                        def iter_content(self):
                            yield from response.iter_bytes()

                    yield Response()

        monkeypatch.setattr("blacklink_discovery.collect.FingerprintClient", Client)

    return install
