#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Web API Hunter V3
=================
Generic browser API/protocol discovery companion for the bundled Chrome extension.

V3 adds:
- full WebSocket message capture, not just 5 samples
- dedicated WEBSOCKET FRAMES tab with text/binary search
- CDP binary WebSocket base64 decode
- gzip/zlib probing and printable UTF-8 extraction
- schema-less protobuf wire hints for binary payloads
- export of all WS frames + action-window WS frames + raw binary files
- URL/query/header redaction for common auth/security material
- redirect-chain-safe request keys
- extension action state persisted across MV3 service-worker restarts
- WebSocket handshake capture
"""

from __future__ import annotations

import argparse
import base64
import binascii
import gzip
import hashlib
import json
import queue
import re
import threading
import time
import zlib
from dataclasses import dataclass, field, asdict
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

APP_VERSION = "3.0.0"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765

MAX_POST_DATA = 12000
MAX_RESPONSE_BODY = 80000
MAX_WS_FRAME_CHARS = 6_000_000
MAX_DECOMPRESSED_BYTES = 4_000_000
MAX_STRING_CANDIDATES = 120
MAX_PROTO_HINTS = 120

SENSITIVE_HEADER_RE = re.compile(
    r"(authorization|cookie|csrf|xsrf|token|secret|api[-_]?key|"
    r"ticket[-_]?guard|secsdk|signature)",
    re.I,
)

SENSITIVE_QUERY_RE = re.compile(
    r"^(msToken|X-Bogus|X-Gnarly|X-Dynosaur|signature|sign|token|"
    r"access_token|auth|authorization|device_id|ttwid)$",
    re.I,
)

STATIC_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico",
    ".css", ".woff", ".woff2", ".ttf", ".otf", ".map",
    ".mp4", ".webm", ".mp3", ".wav", ".m4a", ".flv",
}

JS_EXTS = {".js", ".mjs", ".cjs"}

ANALYTICS_DOMAINS = {
    "www.google-analytics.com", "google-analytics.com",
    "www.googletagmanager.com", "googletagmanager.com",
    "mc.yandex.ru", "metrika.yandex.ru",
    "static.cloudflareinsights.com", "cloudflareinsights.com",
    "www.clarity.ms", "clarity.ms",
    "connect.facebook.net", "www.facebook.com",
}

ANALYTICS_HINTS = (
    "/analytics", "/collect", "/g/collect", "/pixel", "/telemetry",
    "google-analytics", "googletagmanager", "doubleclick",
    "metrika", "yandex", "cloudflareinsights", "clarity",
    "sentry", "datadog", "newrelic", "amplitude",
    "mcs-sg.tiktokv.com/v1/list",
)

API_HINTS = (
    "/api/", "/ajax/", "/graphql", "/rest/", "/rpc",
    "/v1/", "/v2/", "/v3/", "/go/", "batchexecute",
    "/webcast/", "/im/fetch", "/room/chat",
)

JS_ENDPOINT_PATTERNS = [
    re.compile(r"fetch\s*\(\s*[\"']([^\"'`]+)[\"']", re.I),
    re.compile(r"axios\.(?:get|post|put|patch|delete)\s*\(\s*[\"']([^\"'`]+)[\"']", re.I),
    re.compile(r"\.open\s*\(\s*[\"'](?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)[\"']\s*,\s*[\"']([^\"'`]+)[\"']", re.I),
    re.compile(r"\$\.(?:get|post|getJSON)\s*\(\s*[\"']([^\"'`]+)[\"']", re.I),
    re.compile(r"\burl\s*:\s*[\"']([^\"'`]+)[\"']", re.I),
    re.compile(r"[\"']((?:https?://[^\"'`]+)|(?:/(?:api|ajax|graphql|rest|rpc|go|webcast|v[1-9])(?:/|[?])[^\"'`]*)?)[\"']", re.I),
]


def short_text(value, limit):
    if value is None:
        return None
    value = str(value)
    return value if len(value) <= limit else value[:limit] + f"\n...[truncated {len(value)-limit} chars]"


def redact_headers(headers):
    if not isinstance(headers, dict):
        return {}
    out = {}
    for k, v in headers.items():
        out[k] = "[REDACTED]" if SENSITIVE_HEADER_RE.search(str(k)) else v
    return out


def redact_url(url):
    if not url:
        return url
    try:
        p = urlparse(url)
        pairs = []
        for k, v in parse_qsl(p.query, keep_blank_values=True):
            if SENSITIVE_QUERY_RE.search(k) or SENSITIVE_HEADER_RE.search(k):
                v = "[REDACTED]"
            pairs.append((k, v))
        return urlunparse((
            p.scheme, p.netloc, p.path, p.params,
            urlencode(pairs, doseq=True), p.fragment
        ))
    except Exception:
        return url


def host_of(url):
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def path_ext(url):
    try:
        p = urlparse(url).path.lower()
        idx = p.rfind(".")
        return p[idx:] if idx >= 0 else ""
    except Exception:
        return ""


def is_analytics(url):
    host = host_of(url)
    low = (url or "").lower()
    return host in ANALYTICS_DOMAINS or any(x in low for x in ANALYTICS_HINTS)


def is_static_non_js(url):
    return path_ext(url) in STATIC_EXTS


def is_javascript(url, mime):
    ext = path_ext(url)
    m = (mime or "").lower()
    return ext in JS_EXTS or "javascript" in m or "ecmascript" in m


def decode_varint(data: bytes, pos: int):
    value = 0
    shift = 0
    start = pos
    while pos < len(data) and shift <= 63:
        b = data[pos]
        pos += 1
        value |= (b & 0x7F) << shift
        if not (b & 0x80):
            return value, pos
        shift += 7
    raise ValueError(f"invalid varint at {start}")


def printable_unicode_strings(data: bytes, min_chars=4, limit=MAX_STRING_CANDIDATES):
    """
    Extract human-readable UTF-8 runs. This often exposes text fields inside
    protobuf length-delimited fields even when no schema is available.
    """
    try:
        decoded = data.decode("utf-8", errors="ignore")
    except Exception:
        return []

    # Replace control / non-printing characters with separators.
    normalized = "".join(
        ch if (ch.isprintable() and ch not in "\x0b\x0c") else "\n"
        for ch in decoded
    )

    out = []
    seen = set()

    for raw in re.split(r"[\r\n\t\x00-\x1f]+", normalized):
        s = raw.strip()
        if len(s) < min_chars:
            continue

        # Split pathological binary-derived runs around obvious replacement noise.
        if len(s) > 1000:
            s = s[:1000]

        marker = s.casefold()
        if marker in seen:
            continue

        # Require at least a modest printable/text ratio.
        textish = sum(ch.isalnum() or ch.isspace() or ch in ".,:;!?_@#%+-/()[]{}'\"…" for ch in s)
        if textish / max(1, len(s)) < 0.55:
            continue

        seen.add(marker)
        out.append(s)

        if len(out) >= limit:
            break

    return out


def protobuf_wire_hints(data: bytes, max_hints=MAX_PROTO_HINTS, max_depth=3):
    hints = []
    strings = []
    seen_strings = set()
    visited = set()

    def add_string(s, path):
        s = s.strip()
        if len(s) < 2:
            return
        key = s.casefold()
        if key in seen_strings:
            return
        seen_strings.add(key)
        strings.append({"path": path, "text": s[:800]})

    def walk(buf: bytes, depth: int, path: str):
        if depth > max_depth or len(hints) >= max_hints:
            return

        fingerprint = (len(buf), hashlib.sha1(buf[:128]).hexdigest(), depth)
        if fingerprint in visited:
            return
        visited.add(fingerprint)

        pos = 0
        parsed = 0

        while pos < len(buf) and len(hints) < max_hints:
            start = pos
            try:
                key, pos = decode_varint(buf, pos)
            except Exception:
                break

            field_no = key >> 3
            wire = key & 7

            if field_no <= 0 or wire not in (0, 1, 2, 5):
                break

            field_path = f"{path}.{field_no}" if path else str(field_no)

            try:
                if wire == 0:
                    value, pos = decode_varint(buf, pos)
                    hints.append({
                        "path":field_path, "wire":0, "kind":"varint", "value":value
                    })

                elif wire == 1:
                    if pos + 8 > len(buf):
                        break
                    hints.append({
                        "path":field_path, "wire":1, "kind":"fixed64",
                        "hex":buf[pos:pos+8].hex()
                    })
                    pos += 8

                elif wire == 5:
                    if pos + 4 > len(buf):
                        break
                    hints.append({
                        "path":field_path, "wire":5, "kind":"fixed32",
                        "hex":buf[pos:pos+4].hex()
                    })
                    pos += 4

                elif wire == 2:
                    n, pos = decode_varint(buf, pos)
                    if n < 0 or pos + n > len(buf):
                        break

                    payload = buf[pos:pos+n]
                    pos += n

                    item = {
                        "path":field_path,
                        "wire":2,
                        "kind":"length_delimited",
                        "length":n,
                    }

                    if payload.startswith(b"\x1f\x8b"):
                        item["magic"] = "gzip"
                    elif len(payload) >= 2 and payload[0] == 0x78:
                        item["magic"] = "zlib?"

                    try:
                        s = payload.decode("utf-8")
                        if s and sum(c.isprintable() for c in s) / len(s) > 0.85:
                            s = s.strip()
                            if s:
                                item["utf8"] = s[:800]
                                add_string(s, field_path)
                    except Exception:
                        pass

                    hints.append(item)

                    # Nested protobuf is only a heuristic. Recurse into reasonably sized
                    # non-text length-delimited values.
                    if 2 <= len(payload) <= 500_000 and "utf8" not in item:
                        walk(payload, depth + 1, field_path)

                parsed += 1

            except Exception:
                break

            if pos <= start:
                break

        return parsed

    walk(data, 0, "")
    return hints, strings


def safe_gzip_candidates(data: bytes):
    results = []
    offsets = []
    start = 0

    while len(offsets) < 8:
        idx = data.find(b"\x1f\x8b", start)
        if idx < 0:
            break
        offsets.append(idx)
        start = idx + 2

    for offset in offsets:
        try:
            out = gzip.decompress(data[offset:])
            if len(out) > MAX_DECOMPRESSED_BYTES:
                out = out[:MAX_DECOMPRESSED_BYTES]
            results.append(("gzip", offset, out))
        except Exception:
            pass

    return results


def safe_zlib_candidates(data: bytes):
    results = []
    offsets = []

    for i in range(min(len(data) - 1, 500_000)):
        if data[i] == 0x78 and data[i + 1] in (0x01, 0x5E, 0x9C, 0xDA):
            offsets.append(i)
            if len(offsets) >= 6:
                break

    for offset in offsets:
        try:
            out = zlib.decompress(data[offset:])
            if len(out) > MAX_DECOMPRESSED_BYTES:
                out = out[:MAX_DECOMPRESSED_BYTES]
            results.append(("zlib", offset, out))
        except Exception:
            pass

    return results


def analyze_ws_payload(opcode, payload, payload_encoding):
    result = {
        "payload_encoding": payload_encoding,
        "raw_bytes": None,
        "raw_size": 0,
        "sha256": None,
        "strings": [],
        "protobuf_hints": [],
        "protobuf_strings": [],
        "decompressed": [],
        "decode_error": None,
    }

    try:
        if int(opcode or 0) == 1 or payload_encoding == "utf8":
            raw = str(payload or "").encode("utf-8", errors="replace")
        else:
            raw = base64.b64decode(str(payload or ""), validate=False)

        result["raw_bytes"] = raw
        result["raw_size"] = len(raw)
        result["sha256"] = hashlib.sha256(raw).hexdigest()

        result["strings"] = printable_unicode_strings(raw)

        hints, pstrings = protobuf_wire_hints(raw)
        result["protobuf_hints"] = hints
        result["protobuf_strings"] = pstrings

        decompressed = []
        seen_hashes = set()

        for kind, offset, out in safe_gzip_candidates(raw) + safe_zlib_candidates(raw):
            digest = hashlib.sha256(out).hexdigest()
            if digest in seen_hashes:
                continue
            seen_hashes.add(digest)

            dhints, dpstrings = protobuf_wire_hints(out)

            decompressed.append({
                "kind":kind,
                "offset":offset,
                "size":len(out),
                "sha256":digest,
                "strings":printable_unicode_strings(out),
                "protobuf_hints":dhints[:80],
                "protobuf_strings":dpstrings[:80],
            })

        result["decompressed"] = decompressed

    except Exception as exc:
        result["decode_error"] = str(exc)

    return result


@dataclass
class ObservedRecord:
    request_id: str
    request_key: str
    tab_id: int | None = None
    ts_start: float = 0.0
    ts_end: float | None = None
    method: str | None = None
    url: str | None = None
    resource_type: str | None = None
    status: int | None = None
    mime_type: str | None = None
    request_headers: dict = field(default_factory=dict)
    response_headers: dict = field(default_factory=dict)
    post_data: str | None = None
    response_body: str | None = None
    response_body_base64: bool = False
    initiator: dict | None = None
    protocol: str = "HTTP"
    score: int = 0
    category: str = "other"
    action_name: str | None = None
    action_window: bool = False
    websocket_frames_sent: int = 0
    websocket_frames_received: int = 0
    websocket_errors: int = 0


@dataclass
class WebSocketFrameRecord:
    frame_no: int
    socket_frame_no: int
    ts: float
    tab_id: int | None
    request_id: str
    request_key: str
    url: str | None
    direction: str
    opcode: int | None
    mask: bool
    payload_encoding: str
    payload: str
    payload_chars: int
    raw_size: int
    sha256: str | None
    action_name: str | None
    action_window: bool
    strings: list = field(default_factory=list)
    protobuf_hints: list = field(default_factory=list)
    protobuf_strings: list = field(default_factory=list)
    decompressed: list = field(default_factory=list)
    decode_error: str | None = None


@dataclass
class DiscoveredEndpoint:
    source_url: str
    endpoint: str
    resolved_url: str
    first_seen_ts: float
    pattern: str
    action_name: str | None = None
    score: int = 70


@dataclass
class Marker:
    ts: float
    marker: str
    note: str
    tab_id: int | None = None


def classify_record(r):
    url = r.url or ""
    low_url = url.lower()
    method = (r.method or "").upper()
    rtype = (r.resource_type or "").lower()
    mime = (r.mime_type or "").lower()
    body = r.post_data or ""
    low_body = body.lower()

    if is_analytics(url):
        return "Analytics/telemetry", 5, "analytics"
    if is_static_non_js(url):
        return "Static asset", 0, "static"
    if rtype == "websocket":
        return "WebSocket", 96, "api"
    if rtype == "eventsource" or "text/event-stream" in mime:
        return "SSE", 94, "api"
    if "application/grpc-web" in mime or "grpc-web" in low_url or "grpc-web" in low_body:
        return "gRPC-Web", 96, "api"
    if "protobuf" in mime or "resp_content_type=protobuf" in low_url:
        return "Protobuf HTTP", 95, "api"
    if "graphql" in low_url or '"query"' in low_body or '"operationname"' in low_body:
        return "GraphQL", 96, "api"
    if "batchexecute" in low_url:
        return "Custom RPC / batchexecute", 97, "api"

    try:
        obj = json.loads(body) if body.strip().startswith(("{", "[")) else None
    except Exception:
        obj = None

    if isinstance(obj, dict) and "jsonrpc" in obj and "method" in obj:
        return "JSON-RPC", 97, "api"
    if is_javascript(url, mime):
        return "JavaScript source", 20, "javascript"

    score = 15
    protocol = "HTTP"
    category = "other"

    if rtype in ("xhr", "fetch"):
        protocol, score, category = "XHR/fetch API", 82, "api"
    elif any(h in low_url for h in API_HINTS):
        protocol, score, category = "REST/API-like HTTP", 80, "api"
    elif method in ("POST", "PUT", "PATCH", "DELETE"):
        protocol, score, category = "State-changing HTTP", 68, "api"

    if "application/json" in mime or mime.endswith("+json"):
        score += 8
        if category == "other":
            category = "api"
    if r.status is not None and 200 <= r.status < 300:
        score += 3
    if method in ("POST", "PUT", "PATCH", "DELETE"):
        score += 4

    return protocol, min(score, 100), category


class CaptureStore:
    def __init__(self):
        self.lock = threading.RLock()
        self.records = {}
        self.order = []
        self.discovered = {}
        self.markers = []
        self.ws_frames = []
        self.socket_frame_counts = {}
        self.action_active = False
        self.action_name = None

    def current_action(self):
        return self.action_name if self.action_active else None

    def add_marker(self, raw):
        marker = str(raw.get("marker") or "")
        note = str(raw.get("note") or "Action")
        ts = float(raw.get("ts") or time.time())
        m = Marker(ts=ts, marker=marker, note=note, tab_id=raw.get("tab_id"))

        with self.lock:
            self.markers.append(m)
            if marker == "start":
                self.action_active = True
                self.action_name = note
            elif marker == "end":
                self.action_active = False

        GUI_QUEUE.put(("marker", m))
        return m

    def ensure_record(self, raw):
        rid = str(raw.get("request_id") or f"anon-{raw.get('ts', time.time())}")
        rkey = str(raw.get("request_key") or rid)

        with self.lock:
            if rkey not in self.records:
                explicit_action_window = raw.get("action_window")
                explicit_action_name = raw.get("action_name")

                r = ObservedRecord(
                    request_id=rid,
                    request_key=rkey,
                    tab_id=raw.get("tab_id"),
                    ts_start=float(raw.get("ts") or time.time()),
                    action_name=(
                        explicit_action_name
                        if explicit_action_name is not None
                        else self.current_action()
                    ),
                    action_window=(
                        bool(explicit_action_window)
                        if explicit_action_window is not None
                        else bool(self.action_active)
                    ),
                )

                self.records[rkey] = r
                self.order.append(rkey)

            return self.records[rkey]

    def add_ws_frame(self, raw):
        r = self.ensure_record(raw)

        direction = "sent" if raw.get("kind") == "websocket_sent" else "received"
        opcode = raw.get("websocket_opcode")
        try:
            opcode = int(opcode)
        except Exception:
            opcode = None

        payload = str(raw.get("websocket_payload") or "")
        truncated = False

        if len(payload) > MAX_WS_FRAME_CHARS:
            payload = payload[:MAX_WS_FRAME_CHARS]
            truncated = True

        analysis = analyze_ws_payload(
            opcode,
            payload,
            str(raw.get("websocket_payload_encoding") or ("utf8" if opcode == 1 else "base64")),
        )

        with self.lock:
            socket_key = str(raw.get("request_key") or raw.get("request_id") or "")
            socket_no = self.socket_frame_counts.get(socket_key, 0) + 1
            self.socket_frame_counts[socket_key] = socket_no

            frame_no = len(self.ws_frames) + 1

            action_window = raw.get("action_window")
            action_name = raw.get("action_name")

            f = WebSocketFrameRecord(
                frame_no=frame_no,
                socket_frame_no=socket_no,
                ts=float(raw.get("ts") or time.time()),
                tab_id=raw.get("tab_id"),
                request_id=str(raw.get("request_id") or ""),
                request_key=str(raw.get("request_key") or ""),
                url=redact_url(raw.get("url")),
                direction=direction,
                opcode=opcode,
                mask=bool(raw.get("websocket_mask")),
                payload_encoding=str(raw.get("websocket_payload_encoding") or ""),
                payload=payload + ("\n...[frame truncated]" if truncated else ""),
                payload_chars=len(payload),
                raw_size=analysis["raw_size"],
                sha256=analysis["sha256"],
                action_name=(
                    action_name if action_name is not None else r.action_name
                ),
                action_window=(
                    bool(action_window)
                    if action_window is not None
                    else r.action_window
                ),
                strings=analysis["strings"],
                protobuf_hints=analysis["protobuf_hints"],
                protobuf_strings=analysis["protobuf_strings"],
                decompressed=analysis["decompressed"],
                decode_error=analysis["decode_error"],
            )

            self.ws_frames.append(f)

            if direction == "sent":
                r.websocket_frames_sent += 1
            else:
                r.websocket_frames_received += 1

            r.resource_type = "WebSocket"
            r.protocol, r.score, r.category = classify_record(r)

        GUI_QUEUE.put(("ws_frame", f))
        GUI_QUEUE.put(("observed", r))
        return f

    def add_raw(self, raw):
        kind = str(raw.get("kind") or "")

        if kind == "marker":
            return self.add_marker(raw)

        if kind in ("websocket_sent", "websocket_received"):
            return self.add_ws_frame(raw)

        r = self.ensure_record(raw)

        with self.lock:
            r.tab_id = raw.get("tab_id", r.tab_id)

            if raw.get("action_window") is not None and not r.ts_end:
                r.action_window = bool(raw.get("action_window"))
                if raw.get("action_name") is not None:
                    r.action_name = raw.get("action_name")

            if raw.get("method") is not None:
                r.method = raw.get("method")
            if raw.get("url") is not None:
                r.url = redact_url(raw.get("url"))
            if raw.get("resource_type") is not None:
                r.resource_type = raw.get("resource_type")
            if raw.get("status") is not None:
                try:
                    r.status = int(raw.get("status"))
                except Exception:
                    r.status = raw.get("status")
            if raw.get("mime_type") is not None:
                r.mime_type = raw.get("mime_type")
            if raw.get("request_headers") is not None:
                r.request_headers = redact_headers(raw.get("request_headers"))
            if raw.get("response_headers") is not None:
                r.response_headers = redact_headers(raw.get("response_headers"))
            if raw.get("post_data") is not None:
                r.post_data = short_text(raw.get("post_data"), MAX_POST_DATA)
            if raw.get("response_body") is not None:
                r.response_body = short_text(raw.get("response_body"), MAX_RESPONSE_BODY)
                r.response_body_base64 = bool(raw.get("response_body_base64"))
            if raw.get("initiator") is not None:
                r.initiator = raw.get("initiator")

            if kind.startswith("websocket_"):
                r.resource_type = "WebSocket"

            if kind == "websocket_error":
                r.websocket_errors += 1

            if kind in ("loading_finished", "websocket_closed"):
                r.ts_end = float(raw.get("ts") or time.time())

            r.protocol, r.score, r.category = classify_record(r)

        if r.response_body and is_javascript(r.url or "", r.mime_type):
            self.scan_js(r)

        GUI_QUEUE.put(("observed", r))
        return r

    def scan_js(self, r):
        body = r.response_body or ""
        if not body or r.response_body_base64:
            return

        found = []

        for idx, pat in enumerate(JS_ENDPOINT_PATTERNS):
            for m in pat.finditer(body):
                endpoint = m.group(1).strip()

                if not endpoint or endpoint in ("/", "#") or len(endpoint) > 500:
                    continue

                low = endpoint.lower()

                if idx == len(JS_ENDPOINT_PATTERNS) - 1:
                    if not (
                        endpoint.startswith(("http://", "https://", "ws://", "wss://"))
                        or any(
                            x in low
                            for x in (
                                "/api", "/ajax", "/graphql", "/rest", "/rpc",
                                "/go/", "/v1/", "/v2/", "/v3/", "/webcast/"
                            )
                        )
                    ):
                        continue

                found.append((endpoint, f"pattern_{idx+1}"))

        with self.lock:
            for endpoint, pattern in found:
                try:
                    resolved = urljoin(r.url or "", endpoint)
                except Exception:
                    resolved = endpoint

                endpoint = redact_url(endpoint)
                resolved = redact_url(resolved)

                key = (r.url or "", endpoint)

                if key in self.discovered:
                    continue

                d = DiscoveredEndpoint(
                    source_url=r.url or "",
                    endpoint=endpoint,
                    resolved_url=resolved,
                    first_seen_ts=time.time(),
                    pattern=pattern,
                    action_name=r.action_name,
                    score=82 if any(h in endpoint.lower() for h in API_HINTS) else 70,
                )

                self.discovered[key] = d
                GUI_QUEUE.put(("discovered", d))

    def clear(self):
        with self.lock:
            self.records.clear()
            self.order.clear()
            self.discovered.clear()
            self.markers.clear()
            self.ws_frames.clear()
            self.socket_frame_counts.clear()
            self.action_active = False
            self.action_name = None

    def snapshot_records(self):
        with self.lock:
            return [self.records[x] for x in self.order if x in self.records]

    def snapshot_discovered(self):
        with self.lock:
            return list(self.discovered.values())

    def snapshot_markers(self):
        with self.lock:
            return list(self.markers)

    def snapshot_ws_frames(self):
        with self.lock:
            return list(self.ws_frames)


STORE = CaptureStore()
GUI_QUEUE = queue.Queue()


class ReceiverHandler(BaseHTTPRequestHandler):
    server_version = "WebAPIHunter/3.0"

    def log_message(self, fmt, *args):
        pass

    def send_json(self, status, obj):
        payload = json.dumps(obj, ensure_ascii=False).encode("utf-8")

        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
        self.end_headers()
        self.wfile.write(payload)

    def do_OPTIONS(self):
        self.send_json(200, {"ok": True})

    def do_GET(self):
        if self.path == "/health":
            self.send_json(200, {
                "ok": True,
                "app": "Web API Hunter",
                "version": APP_VERSION,
                "observed": len(STORE.snapshot_records()),
                "discovered": len(STORE.snapshot_discovered()),
                "websocket_frames": len(STORE.snapshot_ws_frames()),
                "action_active": STORE.action_active,
                "action_name": STORE.action_name,
            })
        else:
            self.send_json(404, {"ok": False, "error": "not_found"})

    def do_POST(self):
        if self.path != "/event":
            self.send_json(404, {"ok": False, "error": "not_found"})
            return

        try:
            n = int(self.headers.get("Content-Length", "0"))

            if n <= 0 or n > 10_000_000:
                raise ValueError("invalid body length")

            obj = json.loads(self.rfile.read(n).decode("utf-8"))

            if not isinstance(obj, dict):
                raise ValueError("body must be an object")

            STORE.add_raw(obj)
            self.send_json(200, {"ok": True})

        except Exception as exc:
            self.send_json(400, {"ok": False, "error": str(exc)})


def frame_search_blob(f: WebSocketFrameRecord):
    chunks = [
        f.url or "",
        f.payload if f.opcode == 1 else "",
        "\n".join(f.strings),
        "\n".join(str(x.get("text", "")) for x in f.protobuf_strings),
    ]

    for d in f.decompressed:
        chunks.extend(d.get("strings") or [])
        chunks.extend(
            str(x.get("text", ""))
            for x in (d.get("protobuf_strings") or [])
        )

    return "\n".join(chunks)


class HunterGUI:
    def __init__(self, root, server):
        self.root = root
        self.server = server

        self.root.title("Web API Hunter V3")
        self.root.geometry("1500x900")

        top = ttk.Frame(root, padding=8)
        top.pack(fill="x")

        ttk.Label(
            top,
            text=f"Receiver: http://{server.server_address[0]}:{server.server_address[1]}"
        ).pack(side="left")

        self.action_label = tk.Label(
            top,
            text="ACTION: idle",
            bg="#444",
            fg="white",
            padx=10,
            pady=4,
        )
        self.action_label.pack(side="left", padx=14)

        ttk.Button(top, text="Clear", command=self.clear).pack(side="right", padx=4)
        ttk.Button(top, text="Export", command=self.export).pack(side="right", padx=4)

        self.only_action = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            top,
            text="Only action window",
            variable=self.only_action,
            command=self.refresh_all,
        ).pack(side="right", padx=10)

        ttk.Label(top, text="Min score:").pack(side="right")

        self.min_score = tk.IntVar(value=40)
        sp = ttk.Spinbox(
            top,
            from_=0,
            to=100,
            width=5,
            textvariable=self.min_score,
        )
        sp.pack(side="right", padx=4)
        sp.bind("<Return>", lambda e: self.refresh_all())
        sp.bind("<FocusOut>", lambda e: self.refresh_all())

        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        self.observed_tab = ttk.Frame(self.notebook)
        self.discovered_tab = ttk.Frame(self.notebook)
        self.ws_tab = ttk.Frame(self.notebook)

        self.notebook.add(self.observed_tab, text="OBSERVED API")
        self.notebook.add(self.discovered_tab, text="DISCOVERED API")
        self.notebook.add(self.ws_tab, text="WEBSOCKET FRAMES")

        self._build_observed()
        self._build_discovered()
        self._build_ws()

        self.status = tk.StringVar(
            value="Run START_APP.cmd, load V3 extension, then Start capture."
        )

        ttk.Label(
            root,
            textvariable=self.status,
            padding=(8, 0, 8, 8),
        ).pack(fill="x")

        self.root.after(180, self.poll_queue)

    def _build_observed(self):
        paned = ttk.Panedwindow(self.observed_tab, orient="vertical")
        paned.pack(fill="both", expand=True)

        upper = ttk.Frame(paned)
        lower = ttk.Frame(paned)
        paned.add(upper, weight=3)
        paned.add(lower, weight=2)

        cols = ("time", "score", "protocol", "method", "status", "type", "action", "url")
        self.obs_tree = ttk.Treeview(upper, columns=cols, show="headings")

        widths = {
            "time":85, "score":50, "protocol":190, "method":65,
            "status":60, "type":90, "action":140, "url":760,
        }

        for c in cols:
            self.obs_tree.heading(c, text=c.upper())
            self.obs_tree.column(c, width=widths[c], anchor="w")

        oy = ttk.Scrollbar(upper, orient="vertical", command=self.obs_tree.yview)
        ox = ttk.Scrollbar(upper, orient="horizontal", command=self.obs_tree.xview)

        self.obs_tree.configure(yscrollcommand=oy.set, xscrollcommand=ox.set)
        self.obs_tree.grid(row=0, column=0, sticky="nsew")
        oy.grid(row=0, column=1, sticky="ns")
        ox.grid(row=1, column=0, sticky="ew")

        upper.columnconfigure(0, weight=1)
        upper.rowconfigure(0, weight=1)

        self.obs_detail = tk.Text(lower, wrap="none")
        dy = ttk.Scrollbar(lower, orient="vertical", command=self.obs_detail.yview)
        dx = ttk.Scrollbar(lower, orient="horizontal", command=self.obs_detail.xview)

        self.obs_detail.configure(yscrollcommand=dy.set, xscrollcommand=dx.set)
        self.obs_detail.grid(row=0, column=0, sticky="nsew")
        dy.grid(row=0, column=1, sticky="ns")
        dx.grid(row=1, column=0, sticky="ew")

        lower.columnconfigure(0, weight=1)
        lower.rowconfigure(0, weight=1)

        self.obs_tree.bind("<<TreeviewSelect>>", self.on_obs_select)
        self.obs_map = {}

    def _build_discovered(self):
        paned = ttk.Panedwindow(self.discovered_tab, orient="vertical")
        paned.pack(fill="both", expand=True)

        upper = ttk.Frame(paned)
        lower = ttk.Frame(paned)
        paned.add(upper, weight=3)
        paned.add(lower, weight=2)

        cols = ("time", "score", "action", "endpoint", "source")
        self.dis_tree = ttk.Treeview(upper, columns=cols, show="headings")

        widths = {
            "time":85, "score":55, "action":140,
            "endpoint":560, "source":600,
        }

        for c in cols:
            self.dis_tree.heading(c, text=c.upper())
            self.dis_tree.column(c, width=widths[c], anchor="w")

        y = ttk.Scrollbar(upper, orient="vertical", command=self.dis_tree.yview)
        x = ttk.Scrollbar(upper, orient="horizontal", command=self.dis_tree.xview)

        self.dis_tree.configure(yscrollcommand=y.set, xscrollcommand=x.set)
        self.dis_tree.grid(row=0, column=0, sticky="nsew")
        y.grid(row=0, column=1, sticky="ns")
        x.grid(row=1, column=0, sticky="ew")

        upper.columnconfigure(0, weight=1)
        upper.rowconfigure(0, weight=1)

        self.dis_detail = tk.Text(lower, wrap="none")
        dy = ttk.Scrollbar(lower, orient="vertical", command=self.dis_detail.yview)
        dx = ttk.Scrollbar(lower, orient="horizontal", command=self.dis_detail.xview)

        self.dis_detail.configure(yscrollcommand=dy.set, xscrollcommand=dx.set)
        self.dis_detail.grid(row=0, column=0, sticky="nsew")
        dy.grid(row=0, column=1, sticky="ns")
        dx.grid(row=1, column=0, sticky="ew")

        lower.columnconfigure(0, weight=1)
        lower.rowconfigure(0, weight=1)

        self.dis_tree.bind("<<TreeviewSelect>>", self.on_dis_select)
        self.dis_map = {}

    def _build_ws(self):
        wrap = ttk.Frame(self.ws_tab)
        wrap.pack(fill="both", expand=True)

        searchbar = ttk.Frame(wrap, padding=(4, 4, 4, 6))
        searchbar.pack(fill="x")

        ttk.Label(searchbar, text="Search decoded WS:").pack(side="left")

        self.ws_search = tk.StringVar(value="")
        ent = ttk.Entry(searchbar, textvariable=self.ws_search, width=45)
        ent.pack(side="left", padx=6)
        ent.bind("<Return>", lambda e: self.refresh_ws())

        ttk.Button(
            searchbar,
            text="Search",
            command=self.refresh_ws,
        ).pack(side="left")

        ttk.Button(
            searchbar,
            text="Clear search",
            command=self.clear_ws_search,
        ).pack(side="left", padx=5)

        self.ws_received_only = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            searchbar,
            text="Received only",
            variable=self.ws_received_only,
            command=self.refresh_ws,
        ).pack(side="left", padx=10)

        self.ws_action_only = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            searchbar,
            text="Action frames only",
            variable=self.ws_action_only,
            command=self.refresh_ws,
        ).pack(side="left", padx=6)

        paned = ttk.Panedwindow(wrap, orient="vertical")
        paned.pack(fill="both", expand=True)

        upper = ttk.Frame(paned)
        lower = ttk.Frame(paned)
        paned.add(upper, weight=3)
        paned.add(lower, weight=2)

        cols = (
            "no", "time", "dir", "opcode", "bytes",
            "action", "strings", "url",
        )
        self.ws_tree = ttk.Treeview(upper, columns=cols, show="headings")

        widths = {
            "no":60, "time":85, "dir":75, "opcode":60,
            "bytes":80, "action":150, "strings":480, "url":520,
        }

        for c in cols:
            self.ws_tree.heading(c, text=c.upper())
            self.ws_tree.column(c, width=widths[c], anchor="w")

        y = ttk.Scrollbar(upper, orient="vertical", command=self.ws_tree.yview)
        x = ttk.Scrollbar(upper, orient="horizontal", command=self.ws_tree.xview)

        self.ws_tree.configure(yscrollcommand=y.set, xscrollcommand=x.set)
        self.ws_tree.grid(row=0, column=0, sticky="nsew")
        y.grid(row=0, column=1, sticky="ns")
        x.grid(row=1, column=0, sticky="ew")

        upper.columnconfigure(0, weight=1)
        upper.rowconfigure(0, weight=1)

        self.ws_detail = tk.Text(lower, wrap="none")
        dy = ttk.Scrollbar(lower, orient="vertical", command=self.ws_detail.yview)
        dx = ttk.Scrollbar(lower, orient="horizontal", command=self.ws_detail.xview)

        self.ws_detail.configure(yscrollcommand=dy.set, xscrollcommand=dx.set)
        self.ws_detail.grid(row=0, column=0, sticky="nsew")
        dy.grid(row=0, column=1, sticky="ns")
        dx.grid(row=1, column=0, sticky="ew")

        lower.columnconfigure(0, weight=1)
        lower.rowconfigure(0, weight=1)

        self.ws_tree.bind("<<TreeviewSelect>>", self.on_ws_select)
        self.ws_map = {}

    def include_record(self, r):
        if r.category in ("analytics", "static", "javascript"):
            return False
        if self.only_action.get() and not r.action_window:
            return False
        return r.score >= self.min_score.get()

    def include_discovered(self, d):
        if self.only_action.get() and not d.action_name:
            return False
        return d.score >= self.min_score.get()

    def include_ws(self, f):
        if self.ws_received_only.get() and f.direction != "received":
            return False
        if self.ws_action_only.get() and not f.action_window:
            return False

        q = self.ws_search.get().strip().casefold()
        if q and q not in frame_search_blob(f).casefold():
            return False

        return True

    def refresh_observed(self):
        for iid in self.obs_tree.get_children():
            self.obs_tree.delete(iid)

        self.obs_map.clear()

        for idx, r in enumerate(STORE.snapshot_records()):
            if not self.include_record(r):
                continue

            iid = f"o{idx}"
            self.obs_map[iid] = r

            t = datetime.fromtimestamp(r.ts_start).strftime("%H:%M:%S")

            self.obs_tree.insert("", "end", iid=iid, values=(
                t,
                r.score,
                r.protocol,
                r.method or "",
                r.status if r.status is not None else "",
                r.resource_type or "",
                r.action_name or "",
                r.url or "",
            ))

    def refresh_discovered(self):
        for iid in self.dis_tree.get_children():
            self.dis_tree.delete(iid)

        self.dis_map.clear()

        for idx, d in enumerate(STORE.snapshot_discovered()):
            if not self.include_discovered(d):
                continue

            iid = f"d{idx}"
            self.dis_map[iid] = d

            t = datetime.fromtimestamp(d.first_seen_ts).strftime("%H:%M:%S")

            self.dis_tree.insert("", "end", iid=iid, values=(
                t,
                d.score,
                d.action_name or "",
                d.resolved_url,
                d.source_url,
            ))

    def refresh_ws(self):
        for iid in self.ws_tree.get_children():
            self.ws_tree.delete(iid)

        self.ws_map.clear()

        shown = 0

        for idx, f in enumerate(STORE.snapshot_ws_frames()):
            if not self.include_ws(f):
                continue

            iid = f"w{idx}"
            self.ws_map[iid] = f

            t = datetime.fromtimestamp(f.ts).strftime("%H:%M:%S")

            texts = []
            texts.extend(f.strings[:3])
            texts.extend(
                str(x.get("text", ""))
                for x in f.protobuf_strings[:3]
            )

            for d in f.decompressed[:2]:
                texts.extend((d.get("strings") or [])[:2])
                texts.extend(
                    str(x.get("text", ""))
                    for x in (d.get("protobuf_strings") or [])[:2]
                )

            preview = " | ".join(x.replace("\n", " ") for x in texts if x)[:600]

            self.ws_tree.insert("", "end", iid=iid, values=(
                f.frame_no,
                t,
                f.direction,
                f.opcode if f.opcode is not None else "",
                f.raw_size,
                f.action_name or "",
                preview,
                f.url or "",
            ))

            shown += 1

        self.status.set(
            f"WS frames total: {len(STORE.snapshot_ws_frames())} | shown: {shown}"
        )

    def refresh_all(self):
        self.refresh_observed()
        self.refresh_discovered()
        self.refresh_ws()

    def clear_ws_search(self):
        self.ws_search.set("")
        self.refresh_ws()

    def on_obs_select(self, _=None):
        sel = self.obs_tree.selection()
        if not sel:
            return

        r = self.obs_map.get(sel[0])
        if not r:
            return

        data = asdict(r)

        if r.url:
            try:
                data["query_params"] = dict(
                    parse_qsl(urlparse(r.url).query, keep_blank_values=True)
                )
            except Exception:
                pass

        self.obs_detail.delete("1.0", "end")
        self.obs_detail.insert(
            "1.0",
            json.dumps(data, ensure_ascii=False, indent=2),
        )

    def on_dis_select(self, _=None):
        sel = self.dis_tree.selection()
        if not sel:
            return

        d = self.dis_map.get(sel[0])
        if not d:
            return

        self.dis_detail.delete("1.0", "end")
        self.dis_detail.insert(
            "1.0",
            json.dumps(asdict(d), ensure_ascii=False, indent=2),
        )

    def on_ws_select(self, _=None):
        sel = self.ws_tree.selection()
        if not sel:
            return

        f = self.ws_map.get(sel[0])
        if not f:
            return

        data = asdict(f)

        # For binary frames, payload can be huge base64. Keep detail viewer readable;
        # export still preserves the complete captured payload.
        if f.opcode != 1 and len(data.get("payload", "")) > 12000:
            full_len = len(data["payload"])
            data["payload"] = (
                data["payload"][:12000]
                + f"\n...[GUI preview truncated; export has full frame, {full_len} chars]"
            )

        self.ws_detail.delete("1.0", "end")
        self.ws_detail.insert(
            "1.0",
            json.dumps(data, ensure_ascii=False, indent=2),
        )

    def update_action_label(self):
        if STORE.action_active:
            self.action_label.config(
                text=f"ACTION: {STORE.action_name}",
                bg="#b3261e",
            )
        else:
            self.action_label.config(
                text="ACTION: idle",
                bg="#444",
            )

    def poll_queue(self):
        dirty_obs = False
        dirty_dis = False
        dirty_ws = False
        dirty_action = False

        try:
            while True:
                kind, _obj = GUI_QUEUE.get_nowait()

                if kind == "observed":
                    dirty_obs = True
                elif kind == "discovered":
                    dirty_dis = True
                elif kind == "ws_frame":
                    dirty_ws = True
                elif kind == "marker":
                    dirty_action = True

        except queue.Empty:
            pass

        if dirty_obs:
            self.refresh_observed()
        if dirty_dis:
            self.refresh_discovered()
        if dirty_ws:
            self.refresh_ws()
        if dirty_action:
            self.update_action_label()

        if dirty_obs or dirty_dis or dirty_ws or dirty_action:
            self.status.set(
                f"Observed: {len(STORE.snapshot_records())} | "
                f"Discovered: {len(STORE.snapshot_discovered())} | "
                f"WS frames: {len(STORE.snapshot_ws_frames())}"
            )

        self.root.after(180, self.poll_queue)

    def clear(self):
        STORE.clear()
        self.refresh_all()
        self.update_action_label()

        self.obs_detail.delete("1.0", "end")
        self.dis_detail.delete("1.0", "end")
        self.ws_detail.delete("1.0", "end")

        self.status.set("Cleared.")

    def export(self):
        records = STORE.snapshot_records()
        discovered = STORE.snapshot_discovered()
        markers = STORE.snapshot_markers()
        frames = STORE.snapshot_ws_frames()

        if not records and not discovered and not frames:
            messagebox.showinfo("Export", "Nothing to export.")
            return

        folder = filedialog.askdirectory(title="Choose export folder")
        if not folder:
            return

        out = Path(folder) / datetime.now().strftime("session_%Y%m%d_%H%M%S")
        out.mkdir(parents=True, exist_ok=True)

        with (out / "observed_api.jsonl").open("w", encoding="utf-8") as f:
            for r in records:
                f.write(json.dumps(asdict(r), ensure_ascii=False) + "\n")

        (out / "discovered_api.json").write_text(
            json.dumps(
                [asdict(x) for x in discovered],
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

        (out / "markers.json").write_text(
            json.dumps(
                [asdict(x) for x in markers],
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

        ws_bin = out / "websocket_binary"
        ws_bin.mkdir(exist_ok=True)

        def export_frame_obj(frame):
            obj = asdict(frame)

            if frame.opcode != 1:
                payload = frame.payload
                if "\n...[frame truncated]" in payload:
                    payload = payload.split("\n...[frame truncated]", 1)[0]

                try:
                    raw = base64.b64decode(payload, validate=False)
                    if frame.action_window:
                        name = (
                            f"frame_{frame.frame_no:06d}_"
                            f"{frame.direction}_op{frame.opcode}.bin"
                        )
                        (ws_bin / name).write_bytes(raw)
                        obj["raw_binary_file"] = f"websocket_binary/{name}"
                except Exception:
                    pass

            return obj

        with (out / "websocket_frames.jsonl").open("w", encoding="utf-8") as f:
            for frame in frames:
                f.write(
                    json.dumps(export_frame_obj(frame), ensure_ascii=False)
                    + "\n"
                )

        action_frames = [x for x in frames if x.action_window]

        with (out / "websocket_action_frames.jsonl").open("w", encoding="utf-8") as f:
            for frame in action_frames:
                f.write(
                    json.dumps(export_frame_obj(frame), ensure_ascii=False)
                    + "\n"
                )

        # Human-searchable string index.
        with (out / "websocket_strings.txt").open("w", encoding="utf-8") as f:
            for frame in frames:
                texts = []
                texts.extend(frame.strings)
                texts.extend(str(x.get("text", "")) for x in frame.protobuf_strings)

                for d in frame.decompressed:
                    texts.extend(d.get("strings") or [])
                    texts.extend(
                        str(x.get("text", ""))
                        for x in (d.get("protobuf_strings") or [])
                    )

                if not texts:
                    continue

                f.write(
                    f"\n=== FRAME {frame.frame_no} | {frame.direction} | "
                    f"action={frame.action_name or '-'} | {frame.url or ''} ===\n"
                )

                for text in texts:
                    if text:
                        f.write(text.replace("\x00", "") + "\n")

        candidates = [
            asdict(r)
            for r in records
            if r.category == "api"
            and r.score >= 40
            and not is_analytics(r.url or "")
        ]

        candidates.sort(
            key=lambda x: x.get("score", 0),
            reverse=True,
        )

        ws_summary = []

        for r in records:
            if (r.resource_type or "").lower() != "websocket":
                continue

            ws_summary.append({
                "request_id":r.request_id,
                "request_key":r.request_key,
                "url":r.url,
                "frames_sent":r.websocket_frames_sent,
                "frames_received":r.websocket_frames_received,
                "errors":r.websocket_errors,
                "action_name":r.action_name,
                "action_window":r.action_window,
            })

        summary = {
            "app":"Web API Hunter",
            "version":APP_VERSION,
            "exported_at":datetime.now().isoformat(),
            "observed_count":len(records),
            "discovered_count":len(discovered),
            "websocket_frame_count":len(frames),
            "websocket_action_frame_count":len(action_frames),
            "api_candidates":candidates,
            "websockets":ws_summary,
            "discovered_endpoints":[asdict(x) for x in discovered],
            "markers":[asdict(x) for x in markers],
            "files":{
                "observed":"observed_api.jsonl",
                "discovered":"discovered_api.json",
                "markers":"markers.json",
                "ws_all":"websocket_frames.jsonl",
                "ws_action":"websocket_action_frames.jsonl",
                "ws_strings":"websocket_strings.txt",
                "ws_binary_dir":"websocket_binary/",
            },
        }

        (out / "api_summary.json").write_text(
            json.dumps(summary, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

        messagebox.showinfo(
            "Export",
            f"Saved to:\n{out}\n\n"
            f"WS frames: {len(frames)}\n"
            f"Action WS frames: {len(action_frames)}",
        )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default=DEFAULT_HOST)
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = ap.parse_args()

    server = ThreadingHTTPServer(
        (args.host, args.port),
        ReceiverHandler,
    )

    thread = threading.Thread(
        target=server.serve_forever,
        daemon=True,
    )
    thread.start()

    root = tk.Tk()
    HunterGUI(root, server)

    def close():
        try:
            server.shutdown()
            server.server_close()
        finally:
            root.destroy()

    root.protocol("WM_DELETE_WINDOW", close)
    root.mainloop()


if __name__ == "__main__":
    main()
