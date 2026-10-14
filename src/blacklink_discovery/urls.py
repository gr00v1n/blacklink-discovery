"""One URL and host authorization boundary for all collectors."""

from urllib.parse import urldefrag, urljoin, urlsplit, urlunsplit

import idna


def canonical_url(value: str, base: str | None = None) -> str:
    try:
        parsed = urlsplit(urldefrag(urljoin(base, value) if base else value)[0])
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise ValueError("only HTTP(S) URLs with a host are supported")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("URL credentials are forbidden; use private authentication state")
        host = parsed.hostname.lower().rstrip(".")
        host = f"[{host}]" if ":" in host else idna.encode(host, uts46=True).decode()
        port = parsed.port
        scheme = parsed.scheme.lower()
        authority = (
            host if port is None or port == {"http": 80, "https": 443}[scheme] else f"{host}:{port}"
        )
        return urlunsplit((scheme, authority, parsed.path or "/", parsed.query, ""))
    except (ValueError, idna.IDNAError) as error:
        raise ValueError("invalid HTTP(S) URL (host, port or credentials)") from error


def authorized(url: str, site: str, asset: bool, asset_hosts: set[str]) -> bool:
    target, origin = urlsplit(canonical_url(url)), urlsplit(canonical_url(site))
    return target.netloc == origin.netloc or (asset and target.hostname in asset_hosts)


def normalize_hosts(hosts) -> set[str]:
    result = set()
    for host in hosts:
        parsed = urlsplit(canonical_url("https://" + host))
        if parsed.path != "/" or parsed.query or parsed.port:
            raise ValueError("asset hosts must be exact hostnames, not URLs or paths")
        result.add(parsed.hostname)
    return result
