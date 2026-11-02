"""The Twitch check: what an answer says about a proxy, the step that fills it into a run, and the lists."""

import asyncio
import json
from urllib.parse import parse_qs, urlsplit

import pytest

from proxyscraper import twitch

TOKEN_VALUE = json.dumps({"channel": "somechannel", "user_ip": "203.0.113.7", "show_ads": True})
TOKEN_ANSWER = json.dumps({"data": {"streamPlaybackAccessToken": {
    "value": TOKEN_VALUE, "signature": "abc123", "__typename": "PlaybackAccessToken"}}}).encode()
MANIFEST = (b'#EXTM3U\n#EXT-X-TWITCH-INFO:NODE="video-edge",USER-IP="203.0.113.7",USER-COUNTRY="HR",'
            b'SERVING-ID="x"\n#EXT-X-STREAM-INF:BANDWIDTH=1\nhttps://euc13.playlist.ttvnw.net/v1/playlist/x.m3u8\n')
# what usher.ttvnw.net's CDN answers most free proxies (seen 2026-11-02), shortened
CDN_BLOCK = (b'<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">\n<TITLE>ERROR: The request could not '
             b'be satisfied</TITLE>\n<H1>403 ERROR</H1>\nRequest blocked.\n')


def test_token_answer_is_parsed():
    assert twitch.parse_token(TOKEN_ANSWER) == {"value": TOKEN_VALUE, "signature": "abc123",
                                                "user_ip": "203.0.113.7"}


@pytest.mark.parametrize("body", [
    b"", b"not json", b"{}", b'{"data": {"streamPlaybackAccessToken": null}}',
    b'{"errors": [{"message": "service timeout"}]}',
    json.dumps({"data": {"streamPlaybackAccessToken": {"value": 1, "signature": "x"}}}).encode(),
])
def test_anything_else_is_no_token(body):
    assert twitch.parse_token(body) is None


def test_a_token_without_user_ip_still_works():
    answer = json.dumps({"data": {"streamPlaybackAccessToken": {"value": "{}", "signature": "s"}}}).encode()
    assert twitch.parse_token(answer)["user_ip"] is None


@pytest.mark.parametrize("status,body,expected", [
    (200, MANIFEST, {"usher": True, "country": "HR"}),
    # the newer v2 manifest format
    (200, b'#EXTM3U\n#EXT-X-SESSION-DATA:DATA-ID="USER-COUNTRY",VALUE="IS"\n', {"usher": True, "country": "IS"}),
    (200, b"#EXTM3U\n", {"usher": True, "country": None}),
    (403, CDN_BLOCK, {"usher": False}),                 # turned away by the CDN
    (403, b"<html>proxy says no</html>", None),         # some other 403: not the CDN's verdict
    (404, b'[{"error":"twirp error not_found"}]', None),  # the channel went offline
    (200, b"<html>captive portal</html>", None),
    (502, b"", None),
])
def test_usher_verdicts(status, body, expected):
    assert twitch.usher_verdict(status, body) == expected


def test_requests_look_like_the_web_player():
    head, _, body = twitch.token_request("some_channel").partition(b"\r\n\r\n")
    assert head.startswith(b"POST /gql HTTP/1.1\r\nHost: gql.twitch.tv\r\n")
    assert b"Client-ID: " + twitch.CLIENT_ID.encode() in head
    assert b"Device-ID: " in head and b"X-Device-Id: " in head  # without one Twitch treats the viewer differently
    assert f"Content-Length: {len(body)}".encode() in head
    assert json.loads(body)["variables"]["login"] == "some_channel"

    request = twitch.usher_request("some_channel", {"value": TOKEN_VALUE, "signature": "abc123", "user_ip": None})
    line = request.split(b"\r\n")[0].decode()
    assert line.startswith("GET /api/channel/hls/some_channel.m3u8?") and line.endswith(" HTTP/1.1")
    query = parse_qs(urlsplit(line.split()[1]).query)
    assert query["sig"] == ["abc123"] and query["token"] == [TOKEN_VALUE] and query["allow_source"] == ["true"]
    assert b"\r\nHost: usher.ttvnw.net\r\n" in request


# --------------------------------------------------------------------------- the step on a run

def run_dir(tmp_path, rows):
    d = tmp_path / "run"
    d.mkdir()
    (d / "proxies.json").write_text(json.dumps(rows))
    return d


def row(n, https=True, country="HR"):
    return {"url": f"socks5://1.1.1.{n}:1080", "ptype": "socks5", "proxy": f"1.1.1.{n}:1080", "https": https,
            "latency": 100, "country": country}


def test_only_https_proxies_are_probed_and_only_clear_answers_are_kept(tmp_path):
    asked = []

    async def probe(r, channel):
        asked.append((r["proxy"], channel))
        n = r["proxy"].split(".")[3].split(":")[0]
        return {"1": {"usher": True, "country": "IS", "exit_ip": "198.51.100.1"},  # GeoIP said HR
                "2": {"usher": False},
                "3": None}[n]

    rows = [row(1), row(2), row(3), row(4, https=False)]
    rows[0]["twitch"] = {"usher": False}  # stale from an earlier run: replaced
    rows[2]["twitch_country"] = "RU"      # stale: gone when this run says nothing
    d = run_dir(tmp_path, rows)
    counts = asyncio.run(twitch.fill_run(d, probe=probe, channels=["a", "b"]))
    by_proxy = {r["proxy"]: r for r in json.loads((d / "proxies.json").read_text())}
    assert by_proxy["1.1.1.1:1080"]["twitch"] == {"usher": True, "country": "IS", "exit_ip": "198.51.100.1"}
    assert by_proxy["1.1.1.1:1080"]["twitch_country"] == "IS"
    assert by_proxy["1.1.1.1:1080"]["country"] == "HR"  # GeoIP country stays as it was
    assert by_proxy["1.1.1.2:1080"]["twitch"] == {"usher": False}
    assert "twitch_country" not in by_proxy["1.1.1.2:1080"]
    assert "twitch" not in by_proxy["1.1.1.3:1080"] and "twitch_country" not in by_proxy["1.1.1.3:1080"]
    assert "twitch" not in by_proxy["1.1.1.4:1080"]
    assert {p for p, _ in asked} == {"1.1.1.1:1080", "1.1.1.2:1080", "1.1.1.3:1080"}
    assert {c for _, c in asked} == {"a", "b"}  # spread over the channels
    assert counts == {"usher": 1, "blocked": 1}


def test_write_list_keeps_only_the_ones_that_passed_in_order(tmp_path):
    rows = [row(1), row(2), row(3)]
    rows[0]["twitch"] = {"usher": False}
    rows[1].update(twitch={"usher": True, "country": "HR"}, twitch_country="HR")
    rows[2].update(twitch={"usher": True, "country": None})
    out = tmp_path / "out"
    assert twitch.write_list(rows, out) == 2
    assert (out / "twitch.txt").read_text() == "socks5://1.1.1.2:1080\nsocks5://1.1.1.3:1080\n"
    listed = json.loads((out / "twitch.json").read_text())
    assert [r["url"] for r in listed] == ["socks5://1.1.1.2:1080", "socks5://1.1.1.3:1080"]
    assert listed[0]["twitch_country"] == "HR"


def test_publish_writes_the_twitch_lists_and_counts(tmp_path):
    from proxyscraper import publish
    from tests.test_publish import run_dir as publish_run
    d = publish_run(tmp_path)
    rows = json.loads((d / "proxies.json").read_text())
    for r in rows:
        if r.get("https") and r["ptype"] == "socks5":
            r.update(twitch={"usher": True, "country": "HR"}, twitch_country="HR")
        elif r.get("https"):
            r["twitch"] = {"usher": False}
    (d / "proxies.json").write_text(json.dumps(rows))
    out = tmp_path / "public"
    publish.publish(d, out, minimum=2)
    assert (out / "works-with" / "twitch.txt").read_text() == "socks5://2.2.2.2:1080\n"
    listed = json.loads((out / "works-with" / "twitch.json").read_text())
    assert [(r["url"], r["twitch_country"]) for r in listed] == [("socks5://2.2.2.2:1080", "HR")]
    assert json.loads((out / "stats.json").read_text())["twitch"] == 1


def test_publish_without_the_step_says_not_measured(tmp_path):
    from proxyscraper import publish
    from tests.test_publish import run_dir as publish_run
    out = tmp_path / "public"
    publish.publish(publish_run(tmp_path), out, minimum=2)
    assert json.loads((out / "stats.json").read_text())["twitch"] is None  # not a measured 0
    assert (out / "works-with" / "twitch.txt").read_text() == ""
    assert json.loads((out / "works-with" / "twitch.json").read_text()) == []
