"""Which proxies Twitch lets play a stream, and where Twitch thinks they are.

Twitch's www pages let nearly every proxy through (see sites.py), but the stream itself does not: the manifest
host usher.ttvnw.net sits behind a CDN that answers most free proxies with a 403 "Request blocked" page, even with
a valid playback token. Measured 2026-11-02 on the hourly list: 34 of 338 HTTPS-capable proxies got a manifest.

The manifest also carries Twitch's own idea of the viewer's country (USER-COUNTRY), which often differs from
GeoIP: rotating gateways, and providers registered in one country with exits in another. Tools that pick proxies
by country for Twitch (ad-free regions, unlocked quality) need that country, not the GeoIP one.

    python -m proxyscraper.twitch results/<run>                    # adds "twitch": {...} to proxies.json
    python -m proxyscraper.twitch results/<run> --out public/      # ... and writes twitch.json / twitch.txt

Per HTTPS-capable proxy, through a verified TLS tunnel: a playback token from gql.twitch.tv, then the manifest
from usher.ttvnw.net. Only clear answers are kept: a timeout, or a channel that went offline, says nothing.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import random
import re
import secrets
import sys
from pathlib import Path
from typing import Awaitable, Callable, Dict, List, Optional
from urllib.parse import quote, urlencode

from .netio import http_request, read_response
from .paths import atomic_write
from .runsteps import PROBE_ERRORS, Tunnels, https_rows, load_rows, resolve_ipv4, run_limited, save_rows

TIMEOUT = 12.0
CONCURRENCY = 300

GQL_HOST = "gql.twitch.tv"
USHER_HOST = "usher.ttvnw.net"
# Twitch's public web player client ID: what twitch.tv itself sends, no account behind it
CLIENT_ID = "kimne78kx3ncx6brgo4mv6wki5h1ko"
LIVE_CHANNELS_QUERY = ("query { streams(first: 20, options: {sort: VIEWER_COUNT}) "
                       "{ edges { node { broadcaster { login } } } } }")
TOKEN_QUERY = (
    "query PlaybackAccessToken_Template($login: String!, $isLive: Boolean!, $vodID: ID!, $isVod: Boolean!, "
    "$playerType: String!, $platform: String!) {  streamPlaybackAccessToken(channelName: $login, params: "
    "{platform: $platform, playerBackend: \"mediaplayer\", playerType: $playerType}) @include(if: $isLive) {"
    "    value    signature   __typename  }  videoPlaybackAccessToken(id: $vodID, params: {platform: $platform, "
    "playerBackend: \"mediaplayer\", playerType: $playerType}) @include(if: $isVod) {    value    signature   "
    "__typename  }}"
)

COUNTRY_RE = re.compile(rb'USER-COUNTRY="([A-Z]{2})"', re.I)
COUNTRY_V2_RE = re.compile(rb'"USER-COUNTRY",VALUE="([A-Z]{2})"', re.I)
# the CDN's block page; any other non-manifest answer says nothing about the proxy
CDN_BLOCK_RE = re.compile(rb"could not be satisfied|request blocked", re.I)

# What a probe found: {"usher": True, "country": "HR", "exit_ip": "..."} or {"usher": False}; None = no verdict
Verdict = Optional[Dict[str, object]]
Probe = Callable[[dict, str], Awaitable[Verdict]]


def token_request(channel: str) -> bytes:
    body = json.dumps({
        "operationName": "PlaybackAccessToken_Template",
        "query": TOKEN_QUERY,
        "variables": {"isLive": True, "isVod": False, "login": channel, "platform": "web", "playerType": "site",
                      "vodID": ""},
    }).encode()
    # a device ID like the web player's: without one Twitch treats the viewer differently (house preroll ads)
    device_id = secrets.token_hex(16)
    head = (f"POST /gql HTTP/1.1\r\nHost: {GQL_HOST}\r\nClient-ID: {CLIENT_ID}\r\nDevice-ID: {device_id}\r\n"
            f"X-Device-Id: {device_id}\r\nContent-Type: text/plain; charset=UTF-8\r\nAccept: */*\r\n"
            f"Accept-Encoding: identity\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n")
    return head.encode() + body


def parse_token(body: bytes) -> Optional[Dict[str, Optional[str]]]:
    """{"value", "signature", "user_ip"} of a PlaybackAccessToken answer; None if it isn't one."""
    try:
        token = json.loads(body)["data"]["streamPlaybackAccessToken"]
        value, signature = token["value"], token["signature"]
    except (ValueError, KeyError, TypeError):
        return None
    if not isinstance(value, str) or not isinstance(signature, str):
        return None
    try:
        user_ip = json.loads(value).get("user_ip")
    except (ValueError, AttributeError):
        user_ip = None
    return {"value": value, "signature": signature, "user_ip": user_ip if isinstance(user_ip, str) else None}


def usher_request(channel: str, token: Dict[str, Optional[str]]) -> bytes:
    query = urlencode({"sig": token["signature"], "token": token["value"], "allow_source": "true",
                       "p": random.randint(0, 9_999_999)})
    return (f"GET /api/channel/hls/{quote(channel)}.m3u8?{query} HTTP/1.1\r\nHost: {USHER_HOST}\r\n"
            f"Accept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n").encode()


def usher_verdict(status: int, body: bytes) -> Verdict:
    """What the manifest answer says about the proxy (the token step already worked)."""
    if status == 200 and body.startswith(b"#EXTM3U"):
        match = COUNTRY_RE.search(body) or COUNTRY_V2_RE.search(body)
        return {"usher": True, "country": match.group(1).decode().upper() if match else None}
    if status == 403 and CDN_BLOCK_RE.search(body):
        return {"usher": False}
    return None  # 404 (channel went offline), 5xx, a proxy's own error page: nothing about the proxy


def real_probe(ips: Dict[str, str], timeout: float = TIMEOUT) -> Probe:
    tunnels = Tunnels(timeout)

    async def exchange(row: dict, host: str, request: bytes):
        opened = await tunnels.open(row, host, ips[host])
        if opened is None:
            return None
        reader, writer = opened
        try:
            writer.write(request)
            await writer.drain()
            return await read_response(reader)
        finally:
            writer.close()

    async def probe(row: dict, channel: str) -> Verdict:
        async def go() -> Verdict:
            answer = await exchange(row, GQL_HOST, token_request(channel))
            if answer is None or answer[0] != 200:
                return None
            token = parse_token(answer[2])
            if token is None:
                return None
            answer = await exchange(row, USHER_HOST, usher_request(channel, token))
            if answer is None:
                return None
            verdict = usher_verdict(answer[0], answer[2])
            if verdict and verdict.get("usher"):
                verdict["exit_ip"] = token["user_ip"]
            return verdict
        try:
            return await asyncio.wait_for(go(), timeout * 2)
        except PROBE_ERRORS:
            return None
    return probe


async def live_channels(timeout: float = 15.0) -> List[str]:
    """Twitch's most-watched live channels right now – always live, so a 404 from usher is rare."""
    status, _, body = await http_request(
        f"https://{GQL_HOST}/gql", timeout, headers={"Client-ID": CLIENT_ID, "Content-Type": "application/json"},
        method="POST", body=json.dumps({"query": LIVE_CHANNELS_QUERY}).encode(), insecure_fallback=False)
    if status != 200:
        raise ConnectionError(f"live channels: HTTP {status}")
    edges = json.loads(body)["data"]["streams"]["edges"]
    logins = [e["node"]["broadcaster"]["login"] for e in edges if e.get("node") and e["node"].get("broadcaster")]
    if not logins:
        raise ConnectionError(f"live channels: none in the answer ({body[:80]!r})")
    return logins


async def fill_run(run_dir: Path, probe: Optional[Probe] = None, channels: Optional[List[str]] = None,
                   resolve: Callable[[str], str] = resolve_ipv4, concurrency: int = CONCURRENCY) -> Dict[str, int]:
    """Probe every HTTPS-capable proxy of a run; writes "twitch" (and "twitch_country") into its proxies.json.
    Returns how many got a manifest and how many were turned away."""
    channels = channels or await live_channels()
    if probe is None:
        probe = real_probe({host: resolve(host) for host in (GQL_HOST, USHER_HOST)})
    path, rows = load_rows(run_dir)

    def job(index: int, row: dict):
        async def run() -> None:
            # spread the proxies over the channels, so one going offline costs only a few verdicts
            verdict = await probe(row, channels[index % len(channels)])
            if verdict is not None:
                row["twitch"] = verdict
                if verdict.get("usher") and verdict.get("country"):
                    row["twitch_country"] = verdict["country"]
        return run

    for row in rows:
        row.pop("twitch", None)
        row.pop("twitch_country", None)
    await run_limited((job(i, row) for i, row in enumerate(https_rows(rows))), concurrency)
    save_rows(path, rows)
    return {"usher": sum(1 for r in rows if (r.get("twitch") or {}).get("usher")),
            "blocked": sum(1 for r in rows if (r.get("twitch") or {}).get("usher") is False)}


def passed(rows: List[dict]) -> List[dict]:
    """The proxies that got a manifest, in the list's order (best first)."""
    return [r for r in rows if (r.get("twitch") or {}).get("usher")]


def write_list(rows: List[dict], out: Path) -> int:
    """twitch.json (full entries, with twitch_country) and twitch.txt (type://ip:port) of the ones that passed."""
    hits = passed(rows)
    out.mkdir(parents=True, exist_ok=True)
    atomic_write(out / "twitch.json", json.dumps(hits, indent=1, ensure_ascii=False))
    atomic_write(out / "twitch.txt", "".join(f"{r['url']}\n" for r in hits))
    return len(hits)


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description="check which proxies of a run Twitch lets play a stream")
    p.add_argument("run_dir", type=Path)
    p.add_argument("--timeout", type=float, default=TIMEOUT)
    p.add_argument("--out", type=Path, help="also write twitch.json and twitch.txt into this directory")
    args = p.parse_args(argv)

    async def go() -> Dict[str, int]:
        ips = {host: resolve_ipv4(host) for host in (GQL_HOST, USHER_HOST)}
        return await fill_run(args.run_dir, real_probe(ips, args.timeout))

    counts = asyncio.run(go())
    print(f"twitch: {counts['usher']} got a stream manifest, {counts['blocked']} turned away by the CDN")
    if args.out:
        _, rows = load_rows(args.run_dir)
        countries: Dict[str, int] = {}
        for r in passed(rows):
            countries[r.get("twitch_country") or "?"] = countries.get(r.get("twitch_country") or "?", 0) + 1
        print(f"wrote {write_list(rows, args.out)} to {args.out}/twitch.json – by Twitch country: "
              + ", ".join(f"{cc} {n}" for cc, n in sorted(countries.items(), key=lambda kv: -kv[1])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
