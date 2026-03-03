#!/usr/bin/env python3
"""
Minerva DPN Worker (requests edition) — single-file volunteer download client.

Requirements:
    pip install requests rich click

Usage:
    python minerva_requests.py login
    python minerva_requests.py run
    python minerva_requests.py run -c 5 -b 20
    python minerva_requests.py run --proxy proton
    python minerva_requests.py run --proxy proxies.txt
"""

import hashlib
import http.server
import io
import ipaddress
import json
import os
import queue
import random
import re
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.parse
import webbrowser
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import click
import requests
from requests.adapters import HTTPAdapter
from requests.exceptions import RequestException
from rich.console import Console
from rich.progress import BarColumn, DownloadColumn, Progress, TextColumn, TransferSpeedColumn

from proton import ProtonProxyManager
try:
    import fcntl
except Exception:  # pragma: no cover
    fcntl = None

# ── Config ──────────────────────────────────────────────────────────────────

VERSION = "1.2.4-requests"
SERVER_URL = os.environ.get("MINERVA_SERVER", "https://api.minerva-archive.org")
UPLOAD_SERVER_URL = os.environ.get("MINERVA_UPLOAD_SERVER", "https://gate.minerva-archive.org")
TOKEN_FILE = Path.home() / ".minerva-dpn" / "token"
TEMP_DIR = Path.home() / ".minerva-dpn" / "tmp"

MAX_RETRIES = 3
RETRY_DELAY = 5
QUEUE_PREFETCH = 2

ARIA2C_SIZE_THRESHOLD = 5 * 1024 * 1024
DOWNLOAD_CHUNK_SIZE = 4 * 1024 * 1024
DOWNLOAD_PROGRESS_CHUNK_SIZE = 256 * 1024
MULTIPART_MIN_PART_SIZE = 8 * 1024 * 1024

UPLOAD_CHUNK_SIZE = 8 * 1024 * 1024
UPLOAD_START_RETRIES = 12
UPLOAD_CHUNK_RETRIES = 30
UPLOAD_FINISH_RETRIES = 12
REPORT_RETRIES = 20
RETRIABLE_STATUS_CODES = {408, 425, 429, 500, 502, 503, 504, 520, 521, 522, 523, 524}

PROTON_SERVERS_FILE = "proton-servers.txt"
PROTON_CREDENTIALS_FILE = "proton_credentials.txt"
PROTON_PERFORMANCE_FILE = "proton-server-performance.json"
PROXY_PERFORMANCE_SUFFIX = "-performance.json"

HAS_ARIA2C = shutil.which("aria2c") is not None
_STOP = object()

console = Console()


ADAPTIVE_FOCUS_CHOICES = {"slow", "fast", "smallest", "biggest", "auto", "decide"}


def auth_headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "X-Minerva-Worker-Version": VERSION,
    }


_SIZE_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([kmgt]?i?b?)?\s*$", re.IGNORECASE)


def parse_size_to_bytes(value: str | int | None) -> int:
    if value is None:
        return 0
    if isinstance(value, int):
        return max(0, value)
    text = str(value).strip()
    if not text:
        return 0
    m = _SIZE_RE.match(text)
    if not m:
        raise ValueError(f"Invalid size value: {value!r}")
    amount = float(m.group(1))
    unit = (m.group(2) or "").lower()
    multipliers = {
        "": 1,
        "b": 1,
        "k": 1000,
        "kb": 1000,
        "ki": 1024,
        "kib": 1024,
        "m": 1000**2,
        "mb": 1000**2,
        "mi": 1024**2,
        "mib": 1024**2,
        "g": 1000**3,
        "gb": 1000**3,
        "gi": 1024**3,
        "gib": 1024**3,
        "t": 1000**4,
        "tb": 1000**4,
        "ti": 1024**4,
        "tib": 1024**4,
    }
    if unit not in multipliers:
        raise ValueError(f"Invalid size unit in value: {value!r}")
    return max(0, int(amount * multipliers[unit]))


class AdaptiveNetworkingController:
    def __init__(
        self,
        enabled: bool,
        target_bps: int,
        focus: str,
        per_file_cap: int,
        total_budget: int,
    ):
        self.enabled = bool(enabled)
        self.target_bps = max(0, int(target_bps))
        self.focus = (focus or "auto").strip().lower()
        if self.focus == "decide":
            self.focus = "auto"
        if self.focus not in ADAPTIVE_FOCUS_CHOICES:
            self.focus = "auto"
        self.per_file_cap = max(1, int(per_file_cap))
        self.total_budget = max(1, int(total_budget))
        self._lock = threading.Lock()
        self._jobs: dict[int, dict] = {}
        self._last_rebalance = 0.0

    def begin_job(self, file_id: int, known_size: int = 0) -> int:
        if not self.enabled:
            return self.per_file_cap
        now = time.time()
        with self._lock:
            self._jobs[file_id] = {
                "known_size": max(0, int(known_size or 0)),
                "downloaded": 0,
                "speed_bps": 0.0,
                "last_bytes": 0,
                "last_time": now,
                "assigned": 1,
            }
            self._rebalance_locked(force=True)
            return int(self._jobs[file_id].get("assigned", 1))

    def end_job(self, file_id: int):
        if not self.enabled:
            return
        with self._lock:
            self._jobs.pop(file_id, None)
            self._rebalance_locked(force=True)

    def assigned_for(self, file_id: int, default_value: int) -> int:
        if not self.enabled:
            return max(1, int(default_value))
        with self._lock:
            job = self._jobs.get(file_id)
            if not job:
                return max(1, int(default_value))
            return max(1, min(self.per_file_cap, int(job.get("assigned", 1))))

    def update_progress(self, file_id: int, downloaded: int, total: int | None = None):
        if not self.enabled:
            return
        now = time.time()
        with self._lock:
            job = self._jobs.get(file_id)
            if not job:
                return
            downloaded_i = max(0, int(downloaded or 0))
            job["downloaded"] = downloaded_i
            if total is not None and int(total or 0) > 0:
                job["known_size"] = int(total)
            prev_bytes = int(job.get("last_bytes", 0))
            prev_time = float(job.get("last_time", now))
            dt = max(1e-3, now - prev_time)
            dbytes = max(0, downloaded_i - prev_bytes)
            instant = dbytes / dt
            ema = float(job.get("speed_bps", 0.0))
            if ema <= 0.0:
                ema = instant
            else:
                ema = (ema * 0.75) + (instant * 0.25)
            job["speed_bps"] = max(0.0, ema)
            job["last_bytes"] = downloaded_i
            job["last_time"] = now
            # Rebalance at most once per second to avoid lock contention.
            self._rebalance_locked(force=(now - self._last_rebalance) >= 1.0)

    def _job_weight(self, item: dict) -> float:
        known_size = max(0, int(item.get("known_size", 0)))
        downloaded = max(0, int(item.get("downloaded", 0)))
        remaining = max(1, known_size - downloaded) if known_size > 0 else 1
        speed = max(1.0, float(item.get("speed_bps", 0.0)))
        progress = (downloaded / known_size) if known_size > 0 else 0.0

        focus = self.focus
        if focus == "slow":
            return 1.0 / speed
        if focus == "fast":
            return speed
        if focus == "smallest":
            return 1.0 / max(1.0, float(remaining))
        if focus == "biggest":
            return float(remaining)

        # auto/decide: bias toward large remaining files; de-prioritize files already far along.
        size_factor = float(remaining)
        speed_factor = 1.0 / speed
        if progress >= 0.5:
            size_factor *= 0.6
        if self.target_bps > 0 and speed < self.target_bps:
            speed_factor *= 2.0
        return max(1e-6, (size_factor * 0.7) + (speed_factor * 0.3))

    def _rebalance_locked(self, force: bool = False):
        if not force:
            return
        self._last_rebalance = time.time()
        if not self._jobs:
            return
        file_ids = list(self._jobs.keys())
        n = len(file_ids)
        base = {fid: 1 for fid in file_ids}
        extras = max(0, self.total_budget - n)
        if extras <= 0:
            for fid in file_ids:
                self._jobs[fid]["assigned"] = 1
            return

        caps = {fid: max(0, self.per_file_cap - 1) for fid in file_ids}
        total_cap = sum(caps.values())
        if total_cap <= 0:
            for fid in file_ids:
                self._jobs[fid]["assigned"] = 1
            return
        extras = min(extras, total_cap)

        weights = {fid: max(1e-6, self._job_weight(self._jobs[fid])) for fid in file_ids}
        weight_sum = sum(weights.values()) or float(len(file_ids))
        grants = {fid: 0 for fid in file_ids}
        fractions: list[tuple[float, int]] = []
        given = 0
        for fid in file_ids:
            want = extras * (weights[fid] / weight_sum)
            whole = int(want)
            whole = min(whole, caps[fid])
            grants[fid] = whole
            given += whole
            if caps[fid] > whole:
                fractions.append((want - whole, fid))
        rem = extras - given
        if rem > 0:
            fractions.sort(reverse=True, key=lambda x: x[0])
            idx = 0
            while rem > 0 and fractions:
                _, fid = fractions[idx % len(fractions)]
                if grants[fid] < caps[fid]:
                    grants[fid] += 1
                    rem -= 1
                idx += 1
                if idx > len(fractions) * (self.per_file_cap + 2):
                    break

        for fid in file_ids:
            self._jobs[fid]["assigned"] = base[fid] + grants[fid]


def _interface_ipv4_address(ifname: str) -> str | None:
    if not ifname:
        return None
    if fcntl is not None:
        name = ifname.encode("utf-8")
        if len(name) > 15:
            name = name[:15]
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            req = struct.pack("256s", name)
            res = fcntl.ioctl(s.fileno(), 0x8915, req)  # SIOCGIFADDR
            return socket.inet_ntoa(res[20:24])
        except OSError:
            pass
        finally:
            s.close()
    if sys.platform == "darwin":
        try:
            out = subprocess.check_output(["ipconfig", "getifaddr", ifname], text=True, stderr=subprocess.DEVNULL).strip()
            if out:
                return out
        except Exception:
            pass
    try:
        out = subprocess.check_output(["ifconfig", ifname], text=True, stderr=subprocess.DEVNULL)
    except Exception:
        return None
    for line in out.splitlines():
        stripped = line.strip()
        if stripped.startswith("inet "):
            parts = stripped.split()
            if len(parts) >= 2:
                return parts[1]
    return None


def parse_network_split(value: str | None) -> list[tuple[str, tuple[str, int]]]:
    if value is None:
        return []
    text = str(value).strip()
    if not text:
        return []
    routes: list[tuple[str, tuple[str, int]]] = []
    for raw_token in text.split(","):
        token = raw_token.strip()
        if not token:
            continue
        low = token.lower()
        if low in {"inet", "ipv4"}:
            routes.append((token, ("0.0.0.0", 0)))
            continue
        if low in {"inet6", "ipv6"}:
            routes.append((token, ("::", 0)))
            continue
        try:
            ip_obj = ipaddress.ip_address(token)
            routes.append((token, (str(ip_obj), 0)))
            continue
        except ValueError:
            pass
        iface_ip = _interface_ipv4_address(token)
        if iface_ip:
            routes.append((token, (iface_ip, 0)))
            continue
        raise ValueError(
            f"Invalid network split token '{token}'. Use an interface name (e.g. en0), "
            "an IP (e.g. 192.168.1.10 or ::1), or inet/inet6."
        )
    if not routes:
        raise ValueError("network_split cannot be empty")
    return routes


def _expand_proxy_routes(
    proxy_urls: list[str | None],
    proxy_labels: list[str],
    routes: list[tuple[str, tuple[str, int]]],
) -> tuple[list[str | None], list[str], list[tuple[str, int] | None]]:
    if not routes:
        return proxy_urls, proxy_labels, [None] * len(proxy_urls)
    expanded_urls: list[str | None] = []
    expanded_labels: list[str] = []
    expanded_sources: list[tuple[str, int] | None] = []
    for i, proxy_url in enumerate(proxy_urls):
        label = proxy_labels[i] if i < len(proxy_labels) else (proxy_url or "direct")
        for route_name, source in routes:
            expanded_urls.append(proxy_url)
            expanded_labels.append(f"{label} ({route_name})")
            expanded_sources.append(source)
    return expanded_urls, expanded_labels, expanded_sources


class _SourceAddressHTTPAdapter(HTTPAdapter):
    def __init__(self, *args, source_address: tuple[str, int] | None = None, **kwargs):
        self._source_address = source_address
        super().__init__(*args, **kwargs)

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        if self._source_address is not None:
            pool_kwargs.setdefault("source_address", self._source_address)
        return super().init_poolmanager(connections, maxsize, block=block, **pool_kwargs)

    def proxy_manager_for(self, proxy, **proxy_kwargs):
        if self._source_address is not None:
            proxy_kwargs.setdefault("source_address", self._source_address)
        return super().proxy_manager_for(proxy, **proxy_kwargs)


def _job_size_in_range(job: dict, min_job_size: int, max_job_size: int) -> bool:
    if min_job_size <= 0 and max_job_size <= 0:
        return True
    raw_size = job.get("size", 0) if isinstance(job, dict) else 0
    try:
        size = int(raw_size or 0)
    except (TypeError, ValueError):
        size = 0
    if size <= 0:
        return False
    if min_job_size > 0 and size < min_job_size:
        return False
    if max_job_size > 0 and size > max_job_size:
        return False
    return True


def _job_sort_size(job: dict) -> int:
    raw_size = job.get("size", 0) if isinstance(job, dict) else 0
    try:
        return int(raw_size or 0)
    except (TypeError, ValueError):
        return 0


def _detect_job_size_for_filter(
    job: dict,
    download_pool: "RequestsClientPool",
    size_cache: dict[int, int],
) -> int:
    if not isinstance(job, dict):
        return 0
    raw_size = job.get("size", 0)
    try:
        parsed_size = int(raw_size or 0)
    except (TypeError, ValueError):
        parsed_size = 0
    if parsed_size > 0:
        return parsed_size

    file_id = job.get("file_id")
    try:
        fid_int = int(file_id) if file_id is not None else None
    except (TypeError, ValueError):
        fid_int = None
    if fid_int is not None and fid_int in size_cache:
        cached = size_cache[fid_int]
        if cached > 0:
            job["size"] = cached
            return cached
        return 0

    url = job.get("url")
    if not isinstance(url, str) or not url:
        return 0
    try:
        _supports_range, detected_total = _probe_range_support(url, download_pool, known_size=0)
    except Exception:
        return 0
    if detected_total and int(detected_total) > 0:
        detected = int(detected_total)
        job["size"] = detected
        if fid_int is not None:
            size_cache[fid_int] = detected
        return detected
    return 0


class ProtonPerformanceTracker:
    def __init__(self, perf_file: str = PROTON_PERFORMANCE_FILE):
        self.perf_file = perf_file
        self.lock = threading.Lock()
        self.performance_data = self._load()
        self._dirty_updates = 0

    def _load(self) -> dict:
        if os.path.exists(self.perf_file):
            try:
                with open(self.perf_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    return data
            except (json.JSONDecodeError, OSError):
                pass
        return {}

    def _save(self):
        try:
            with open(self.perf_file, "w", encoding="utf-8") as f:
                json.dump(self.performance_data, f, indent=2)
        except OSError:
            pass

    def record(self, server: str, elapsed_seconds: float, success: bool):
        with self.lock:
            perf = self.performance_data.setdefault(
                server,
                {
                    "total_attempts": 0,
                    "successful_attempts": 0,
                    "total_time": 0.0,
                    "avg_time": None,
                    "last_updated": None,
                },
            )
            perf["total_attempts"] += 1
            perf["last_updated"] = time.time()
            if success:
                perf["successful_attempts"] += 1
                perf["total_time"] += float(max(0.0, elapsed_seconds))
                if perf["successful_attempts"] > 0:
                    perf["avg_time"] = perf["total_time"] / perf["successful_attempts"]
            self._dirty_updates += 1
            if self._dirty_updates >= 20:
                self._save()
                self._dirty_updates = 0

    def flush(self):
        with self.lock:
            if self._dirty_updates > 0:
                self._save()
                self._dirty_updates = 0


def _performance_file_for_proxy_list(proxy_file: str) -> str:
    p = Path(proxy_file)
    stem = p.stem or "proxy-list"
    return str(p.with_name(f"{stem}{PROXY_PERFORMANCE_SUFFIX}"))


def select_server(servers: list[str], performance_data: dict, exploration_rate: float = 0.1) -> str:
    if not servers:
        raise ValueError("No servers available")

    tested_servers = [
        s for s in servers
        if s in performance_data and performance_data[s].get("successful_attempts", 0) > 0
    ]
    untested_servers = [s for s in servers if s not in tested_servers]

    if untested_servers and random.random() < exploration_rate:
        return random.choice(untested_servers)

    if tested_servers:
        weighted: list[tuple[str, float]] = []
        for server in tested_servers:
            perf = performance_data[server]
            avg_time = perf.get("avg_time")
            success_rate = perf.get("successful_attempts", 0) / max(perf.get("total_attempts", 1), 1)
            if avg_time and avg_time > 0:
                weight = (success_rate / (avg_time + 0.1)) ** 2
            else:
                weight = 0.1 * success_rate
            weighted.append((server, max(weight, 0.0001)))
        servers_list, weights = zip(*weighted)
        return random.choices(servers_list, weights=weights, k=1)[0]

    return random.choice(servers)


class RequestsClientPool:
    def __init__(
        self,
        sessions: list[requests.Session],
        labels: list[str],
        proxy_urls: list[str | None],
        performance_tracker: ProtonPerformanceTracker | None = None,
        weighted_pick: bool = False,
        rate_limit_cooldown_seconds: int = 0,
    ):
        self.sessions = sessions
        self.labels = labels
        self.proxy_urls = proxy_urls
        self.performance_tracker = performance_tracker
        self.weighted_pick = weighted_pick
        self.rate_limit_cooldown_seconds = max(0, int(rate_limit_cooldown_seconds))
        self._cursor = 0
        self._lock = threading.Lock()
        self._cooldown_until: dict[int, float] = {}

    def _is_cooldown_active(self, idx: int, now: float) -> bool:
        until = self._cooldown_until.get(idx, 0.0)
        return until > now

    def mark_rate_limited(self, idx: int, cooldown_seconds: int | None = None):
        if idx < 0 or idx >= len(self.sessions):
            return
        seconds = self.rate_limit_cooldown_seconds if cooldown_seconds is None else max(0, int(cooldown_seconds))
        if seconds <= 0:
            return
        with self._lock:
            self._cooldown_until[idx] = max(self._cooldown_until.get(idx, 0.0), time.time() + seconds)

    def pick(self, used_indices: set[int] | None = None) -> tuple[int, requests.Session, str]:
        if not self.sessions:
            raise RuntimeError("No sessions configured")
        if used_indices is None:
            used_indices = set()

        with self._lock:
            if self.weighted_pick and self.performance_tracker is not None:
                idx = self._pick_weighted(used_indices)
                return idx, self.sessions[idx], self.labels[idx]

            total = len(self.sessions)
            now = time.time()
            fallback_idx = None
            for _ in range(total):
                idx = self._cursor % total
                self._cursor += 1
                if idx in used_indices:
                    continue
                if fallback_idx is None:
                    fallback_idx = idx
                if not self._is_cooldown_active(idx, now):
                    used_indices.add(idx)
                    return idx, self.sessions[idx], self.labels[idx]

            if fallback_idx is not None:
                used_indices.add(fallback_idx)
                return fallback_idx, self.sessions[fallback_idx], self.labels[fallback_idx]

            used_indices.clear()
            idx = self._cursor % total
            self._cursor += 1
            used_indices.add(idx)
            return idx, self.sessions[idx], self.labels[idx]

    def _pick_weighted(self, used_indices: set[int]) -> int:
        now = time.time()
        available = [
            i for i in range(len(self.sessions))
            if i not in used_indices and not self._is_cooldown_active(i, now)
        ]
        if not available:
            available = [i for i in range(len(self.sessions)) if i not in used_indices]
        if not available:
            used_indices.clear()
            now = time.time()
            available = [i for i in range(len(self.sessions)) if not self._is_cooldown_active(i, now)]
        if not available:
            available = list(range(len(self.sessions)))
        available_labels = [self.labels[i] for i in available]
        chosen_label = select_server(available_labels, self.performance_tracker.performance_data)
        for idx in available:
            if self.labels[idx] == chosen_label:
                used_indices.add(idx)
                return idx
        idx = random.choice(available)
        used_indices.add(idx)
        return idx

    def proxy_for_index(self, idx: int) -> str | None:
        if idx < 0 or idx >= len(self.proxy_urls):
            return None
        return self.proxy_urls[idx]

    def record_result(self, idx: int, elapsed_seconds: float, success: bool):
        if self.performance_tracker is None:
            return
        if idx < 0 or idx >= len(self.labels):
            return
        self.performance_tracker.record(self.labels[idx], elapsed_seconds, success)

    def flush_performance(self):
        if self.performance_tracker is not None:
            self.performance_tracker.flush()


def _retryable_status(code: int) -> bool:
    return code in RETRIABLE_STATUS_CODES


def _retry_sleep(attempt: int, cap: float = 25.0) -> float:
    return min(cap, (0.85 * attempt) + random.random() * 1.25)


def _raise_if_upgrade_required(resp: requests.Response):
    if resp.status_code == 426:
        try:
            detail = resp.json().get("detail")
        except Exception:
            detail = (resp.text or "").strip() or "Worker update required"
        raise RuntimeError(detail)


def _response_detail(resp: requests.Response) -> str:
    try:
        body = resp.json()
        if isinstance(body, dict):
            detail = body.get("detail")
            if detail is not None:
                return str(detail)
    except Exception:
        pass
    return (resp.text or "").strip()


def _sanitize_component(part: str) -> str:
    bad = '<>:"/\\|?*'
    out = []
    for ch in part:
        if ch in bad or ord(ch) < 32:
            out.append("_")
        else:
            out.append(ch)
    cleaned = "".join(out).strip().rstrip(".")
    return cleaned or "_"


def local_path_for_job(temp_dir: Path, url: str, dest_path: str) -> Path:
    parsed = urllib.parse.urlparse(url)
    host = _sanitize_component(parsed.netloc or "unknown-host")
    decoded_dest = urllib.parse.unquote(dest_path).lstrip("/")
    parts = [_sanitize_component(p) for p in decoded_dest.split("/") if p]
    return temp_dir / host / Path(*parts)


def _load_proton_servers(servers_file: str = PROTON_SERVERS_FILE) -> list[str]:
    servers: list[str] = []
    if os.path.exists(servers_file):
        with open(servers_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and "|" in line:
                    host = line.split("|", 1)[0].strip()
                    if host:
                        servers.append(host)
    return servers


def _load_proxy_file(proxy_file: str) -> list[str]:
    if not os.path.exists(proxy_file):
        raise FileNotFoundError(f"Proxy list file not found: {proxy_file}")
    proxies: list[str] = []
    with open(proxy_file, "r", encoding="utf-8") as f:
        for line_num, raw_line in enumerate(f, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            proxy_url = line if "://" in line else f"http://{line}"
            parsed = urllib.parse.urlparse(proxy_url)
            if not parsed.scheme or not parsed.netloc:
                raise ValueError(f"Invalid proxy on line {line_num} in {proxy_file}: {line}")
            if parsed.scheme.lower() not in {"http", "https", "socks4", "socks5", "socks5h"}:
                raise ValueError(f"Unsupported proxy scheme on line {line_num} in {proxy_file}: {parsed.scheme}")
            proxies.append(proxy_url)
    if not proxies:
        raise ValueError(f"No proxies found in {proxy_file}")
    return proxies


def resolve_proxy_config(
    proxy_option: str | None,
) -> tuple[list[str | None], list[str], str, ProtonPerformanceTracker | None, bool]:
    if not proxy_option:
        return [None], ["direct"], "none", None, False

    if proxy_option.lower() == "proton":
        manager = ProtonProxyManager(
            credentials_file=PROTON_CREDENTIALS_FILE,
            proxy_host=None,
            proxy_port=4443,
        )
        manager.refresh_credentials()
        creds = manager.get_credentials()
        username = urllib.parse.quote(creds["username"], safe="")
        password = urllib.parse.quote(creds["password"], safe="")
        hosts = _load_proton_servers()
        if not hosts:
            raise RuntimeError(f"No Proton servers found in {PROTON_SERVERS_FILE}")
        proxies = [f"https://{username}:{password}@{host}:4443" for host in hosts]
        tracker = ProtonPerformanceTracker(PROTON_PERFORMANCE_FILE)
        return proxies, hosts, f"proton ({len(proxies)} servers)", tracker, True

    proxies = _load_proxy_file(proxy_option)
    perf_file = _performance_file_for_proxy_list(proxy_option)
    tracker = ProtonPerformanceTracker(perf_file)
    return proxies, proxies, f"file:{proxy_option} ({len(proxies)} servers)", tracker, True


def _build_session(
    proxy_url: str | None,
    max_pool: int = 256,
    source_address: tuple[str, int] | None = None,
) -> requests.Session:
    s = requests.Session()
    s.trust_env = False
    adapter = _SourceAddressHTTPAdapter(
        pool_connections=max_pool,
        pool_maxsize=max_pool,
        max_retries=0,
        source_address=source_address,
    )
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    if proxy_url:
        s.proxies = {"http": proxy_url, "https": proxy_url}
    return s


def save_token(token: str):
    TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
    TOKEN_FILE.write_text(token)


def load_token() -> str | None:
    if TOKEN_FILE.exists():
        t = TOKEN_FILE.read_text().strip()
        return t if t else None
    return None


def do_login(server_url: str) -> str:
    token = None
    event = threading.Event()

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            nonlocal token
            params = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            if "token" in params:
                token = params["token"][0]
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<h1>Logged in! You can close this tab.</h1>")
                event.set()
            else:
                self.send_response(400)
                self.end_headers()

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 19283), Handler)
    srv.timeout = 120

    url = f"{server_url}/auth/discord/login?worker_callback=http://127.0.0.1:19283/"
    console.print("[bold]Opening browser for Discord login...")
    console.print(f"[dim]If it doesn't open: {url}")
    webbrowser.open(url)

    while not event.is_set():
        srv.handle_request()
    srv.server_close()

    if not token:
        raise RuntimeError("Login failed")
    save_token(token)
    console.print("[bold green]Login successful!")
    return token


def download_file(
    url: str,
    dest: Path,
    download_pool: RequestsClientPool,
    aria2c_connections: int,
    socket_connections: int = 1,
    socket_distinct_ips: bool = False,
    known_size: int = 0,
    on_progress=None,
) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    used: set[int] = set()
    idx, session, _ = download_pool.pick(used)
    proxy_url = download_pool.proxy_for_index(idx)
    use_aria2c = (
        HAS_ARIA2C
        and socket_connections <= 1
        and (known_size == 0 or known_size >= ARIA2C_SIZE_THRESHOLD)
    )
    if use_aria2c:
        args = []
        if proxy_url:
            args.append(f"--all-proxy={proxy_url}")
        started = time.perf_counter()
        proc = subprocess.run(
            [
                "aria2c",
                f"--max-connection-per-server={aria2c_connections}",
                f"--split={aria2c_connections}",
                "--min-split-size=1M",
                "--dir", str(dest.parent),
                "--out", dest.name,
                "--auto-file-renaming=false",
                "--allow-overwrite=true",
                "--console-log-level=warn",
                "--retry-wait=3",
                "--max-tries=5",
                "--timeout=60",
                "--connect-timeout=15",
                *args,
                url,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if proc.returncode != 0:
            download_pool.record_result(idx, time.perf_counter() - started, False)
            raise RuntimeError(f"aria2c exit {proc.returncode}: {(proc.stderr or '')[:200]}")
        download_pool.record_result(idx, time.perf_counter() - started, True)
        if on_progress is not None and dest.exists():
            final_size = dest.stat().st_size
            on_progress(final_size, known_size if known_size > 0 else final_size)
        return dest

    if socket_connections > 1:
        multipart_dest = _download_file_multipart(
            url=url,
            dest=dest,
            download_pool=download_pool,
            max_connections=socket_connections,
            distinct_ips=socket_distinct_ips,
            known_size=known_size,
            on_progress=on_progress,
        )
        if multipart_dest is not None:
            return multipart_dest

    started = time.perf_counter()
    try:
        with session.get(url, stream=True, timeout=(15, 300)) as resp:
            resp.raise_for_status()
            total = int(known_size) if known_size and int(known_size) > 0 else None
            if total is None:
                cl = resp.headers.get("content-length")
                if cl:
                    try:
                        parsed = int(cl)
                        if parsed > 0:
                            total = parsed
                    except ValueError:
                        total = None
            downloaded = 0
            if on_progress is not None:
                on_progress(downloaded, total)
            with open(dest, "wb", buffering=1024 * 1024) as f:
                stream_chunk_size = min(DOWNLOAD_CHUNK_SIZE, DOWNLOAD_PROGRESS_CHUNK_SIZE)
                for chunk in resp.iter_content(chunk_size=stream_chunk_size):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        if on_progress is not None:
                            on_progress(downloaded, total)
        download_pool.record_result(idx, time.perf_counter() - started, True)
    except Exception:
        download_pool.record_result(idx, time.perf_counter() - started, False)
        raise
    return dest


def download_file_to_memory(
    url: str,
    download_pool: RequestsClientPool,
    known_size: int = 0,
    on_progress=None,
) -> bytes:
    used: set[int] = set()
    idx, session, _ = download_pool.pick(used)
    started = time.perf_counter()
    try:
        with session.get(url, stream=True, timeout=(15, 300)) as resp:
            resp.raise_for_status()
            total = int(known_size) if known_size and int(known_size) > 0 else None
            if total is None:
                cl = resp.headers.get("content-length")
                if cl:
                    try:
                        parsed = int(cl)
                        if parsed > 0:
                            total = parsed
                    except ValueError:
                        total = None
            downloaded = 0
            if on_progress is not None:
                on_progress(downloaded, total)
            chunks: list[bytes] = []
            stream_chunk_size = min(DOWNLOAD_CHUNK_SIZE, DOWNLOAD_PROGRESS_CHUNK_SIZE)
            for chunk in resp.iter_content(chunk_size=stream_chunk_size):
                if not chunk:
                    continue
                chunks.append(chunk)
                downloaded += len(chunk)
                if on_progress is not None:
                    on_progress(downloaded, total)
        download_pool.record_result(idx, time.perf_counter() - started, True)
        return b"".join(chunks)
    except Exception:
        download_pool.record_result(idx, time.perf_counter() - started, False)
        raise


def _parse_content_range_total(content_range: str | None) -> int | None:
    if not content_range:
        return None
    text = content_range.strip()
    if not text.lower().startswith("bytes "):
        return None
    value = text[6:]
    if "/" not in value:
        return None
    _, total_text = value.split("/", 1)
    total_text = total_text.strip()
    if total_text == "*":
        return None
    try:
        total = int(total_text)
    except ValueError:
        return None
    return total if total > 0 else None


def _probe_range_support(
    url: str,
    download_pool: RequestsClientPool,
    known_size: int = 0,
) -> tuple[bool, int | None]:
    used: set[int] = set()
    idx, session, _ = download_pool.pick(used)
    started = time.perf_counter()
    try:
        with session.get(
            url,
            headers={"Range": "bytes=0-0"},
            timeout=(15, 120),
            allow_redirects=True,
        ) as resp:
            if resp.status_code == 429:
                download_pool.mark_rate_limited(idx)
            resp.raise_for_status()
            total = int(known_size) if known_size and int(known_size) > 0 else None
            if resp.status_code == 206:
                if total is None:
                    total = _parse_content_range_total(resp.headers.get("content-range"))
                download_pool.record_result(idx, time.perf_counter() - started, True)
                return True, total
            if total is None:
                cl = resp.headers.get("content-length")
                if cl:
                    try:
                        parsed = int(cl)
                        if parsed > 0:
                            total = parsed
                    except ValueError:
                        total = None
            download_pool.record_result(idx, time.perf_counter() - started, True)
            return False, total
    except Exception:
        download_pool.record_result(idx, time.perf_counter() - started, False)
        raise


def _download_file_multipart(
    url: str,
    dest: Path,
    download_pool: RequestsClientPool,
    max_connections: int,
    distinct_ips: bool = False,
    known_size: int = 0,
    on_progress=None,
) -> Path | None:
    supports_ranges, detected_total = _probe_range_support(url, download_pool, known_size=known_size)
    total = int(known_size) if known_size and int(known_size) > 0 else detected_total
    if not supports_ranges or total is None or total <= 1:
        return None

    max_parts_for_size = max(1, total // MULTIPART_MIN_PART_SIZE)
    parts = min(max_connections, max_parts_for_size)
    if parts < 2:
        return None

    ranges: list[tuple[int, int, int]] = []
    for part_idx in range(parts):
        start = (total * part_idx) // parts
        end = ((total * (part_idx + 1)) // parts) - 1
        if start > end:
            continue
        ranges.append((part_idx, start, end))
    if len(ranges) < 2:
        return None

    part_preferred_idx: dict[int, int] = {}
    if distinct_ips and len(download_pool.sessions) > 1:
        used_for_parts: set[int] = set()
        for part_idx, _, _ in ranges:
            idx, _, _ = download_pool.pick(used_for_parts)
            part_preferred_idx[part_idx] = idx

    for part_idx, _, _ in ranges:
        dest.with_name(f"{dest.name}.part{part_idx}").unlink(missing_ok=True)

    progress_lock = threading.Lock()
    bytes_by_part = {part_idx: 0 for part_idx, _, _ in ranges}
    downloaded_total = 0
    if on_progress is not None:
        on_progress(0, total)

    def part_worker(part_idx: int, start: int, end: int, part_path: Path):
        nonlocal downloaded_total
        expected = (end - start) + 1
        preferred_idx = part_preferred_idx.get(part_idx)
        for attempt in range(1, MAX_RETRIES + 1):
            idx = -1
            started = time.perf_counter()
            try:
                with progress_lock:
                    prev = bytes_by_part.get(part_idx, 0)
                    if prev:
                        downloaded_total = max(0, downloaded_total - prev)
                        bytes_by_part[part_idx] = 0
                        if on_progress is not None:
                            on_progress(downloaded_total, total)
                if preferred_idx is not None and attempt == 1:
                    idx = preferred_idx
                    session = download_pool.sessions[idx]
                else:
                    idx, session, _ = download_pool.pick(set())
                with session.get(
                    url,
                    headers={"Range": f"bytes={start}-{end}"},
                    stream=True,
                    timeout=(15, 300),
                ) as resp:
                    if resp.status_code != 206:
                        if resp.status_code == 429:
                            download_pool.mark_rate_limited(idx)
                        raise RuntimeError(f"server did not honor range request (status {resp.status_code})")
                    got = 0
                    with open(part_path, "wb", buffering=1024 * 1024) as f:
                        stream_chunk_size = min(DOWNLOAD_CHUNK_SIZE, DOWNLOAD_PROGRESS_CHUNK_SIZE)
                        for chunk in resp.iter_content(chunk_size=stream_chunk_size):
                            if not chunk:
                                continue
                            f.write(chunk)
                            chunk_len = len(chunk)
                            got += chunk_len
                            with progress_lock:
                                bytes_by_part[part_idx] += chunk_len
                                downloaded_total += chunk_len
                                if on_progress is not None:
                                    on_progress(downloaded_total, total)
                    if got != expected:
                        raise RuntimeError(f"range size mismatch for part {part_idx} (expected {expected}, got {got})")
                download_pool.record_result(idx, time.perf_counter() - started, True)
                return
            except Exception:
                part_path.unlink(missing_ok=True)
                if idx >= 0:
                    download_pool.record_result(idx, time.perf_counter() - started, False)
                if attempt >= MAX_RETRIES:
                    raise
                time.sleep(RETRY_DELAY * attempt)

    try:
        with ThreadPoolExecutor(max_workers=len(ranges)) as executor:
            futures = [
                executor.submit(part_worker, part_idx, start, end, dest.with_name(f"{dest.name}.part{part_idx}"))
                for part_idx, start, end in ranges
            ]
            for fut in as_completed(futures):
                fut.result()

        with open(dest, "wb", buffering=1024 * 1024) as out:
            for part_idx, _, _ in ranges:
                part_path = dest.with_name(f"{dest.name}.part{part_idx}")
                with open(part_path, "rb") as src:
                    shutil.copyfileobj(src, out, length=1024 * 1024)
        if on_progress is not None:
            on_progress(total, total)
        return dest
    finally:
        for part_idx, _, _ in ranges:
            dest.with_name(f"{dest.name}.part{part_idx}").unlink(missing_ok=True)


def validate_download(path: Path, known_size: int = 0, source_hint: str = "") -> int:
    if not path.exists():
        raise RuntimeError("download missing local file")
    size = path.stat().st_size
    if size <= 0:
        raise RuntimeError("download produced empty file")
    if known_size > 0 and size != int(known_size):
        raise RuntimeError(f"download size mismatch (expected {known_size}, got {size})")

    hint = source_hint.lower()
    if hint.endswith(".zip") or path.suffix.lower() == ".zip":
        if not zipfile.is_zipfile(path):
            raise RuntimeError("download is not a valid zip archive")
    return size


def validate_download_bytes(data: bytes, known_size: int = 0, source_hint: str = "") -> int:
    size = len(data)
    if size <= 0:
        raise RuntimeError("download produced empty file")
    if known_size > 0 and size != int(known_size):
        raise RuntimeError(f"download size mismatch (expected {known_size}, got {size})")

    hint = source_hint.lower()
    if hint.endswith(".zip"):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                if zf.testzip() is not None:
                    raise RuntimeError("download is not a valid zip archive")
        except zipfile.BadZipFile as e:
            raise RuntimeError("download is not a valid zip archive") from e
    return size


def upload_file(upload_server_url: str, token: str, file_id: int, path: Path, upload_pool: RequestsClientPool, on_progress=None) -> dict:
    headers = auth_headers(token)
    session_id = None

    used_start: set[int] = set()
    for attempt in range(1, UPLOAD_START_RETRIES + 1):
        idx = -1
        started = time.perf_counter()
        try:
            idx, session, _ = upload_pool.pick(used_start)
            resp = session.post(f"{upload_server_url}/api/upload/{file_id}/start", headers=headers, timeout=(30, 300))
            _raise_if_upgrade_required(resp)
            if _retryable_status(resp.status_code):
                if resp.status_code == 429:
                    upload_pool.mark_rate_limited(idx)
                upload_pool.record_result(idx, time.perf_counter() - started, False)
                if attempt == UPLOAD_START_RETRIES:
                    raise RuntimeError(f"upload start failed ({resp.status_code})")
                time.sleep(_retry_sleep(attempt))
                continue
            resp.raise_for_status()
            upload_pool.record_result(idx, time.perf_counter() - started, True)
            session_id = resp.json()["session_id"]
            break
        except RequestException as e:
            if idx >= 0:
                upload_pool.record_result(idx, time.perf_counter() - started, False)
            if attempt == UPLOAD_START_RETRIES:
                raise RuntimeError(f"upload start failed ({e})") from e
            time.sleep(_retry_sleep(attempt))

    if not session_id:
        raise RuntimeError("Failed to create upload session")

    file_size = path.stat().st_size
    sent = 0
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            data = f.read(UPLOAD_CHUNK_SIZE)
            if not data:
                break
            hasher.update(data)
            used_chunk: set[int] = set()
            for attempt in range(1, UPLOAD_CHUNK_RETRIES + 1):
                idx = -1
                started = time.perf_counter()
                try:
                    idx, session, _ = upload_pool.pick(used_chunk)
                    resp = session.post(
                        f"{upload_server_url}/api/upload/{file_id}/chunk",
                        params={"session_id": session_id},
                        headers={**headers, "Content-Type": "application/octet-stream"},
                        data=data,
                        timeout=(30, 300),
                    )
                    _raise_if_upgrade_required(resp)
                    if _retryable_status(resp.status_code):
                        if resp.status_code == 429:
                            upload_pool.mark_rate_limited(idx)
                        upload_pool.record_result(idx, time.perf_counter() - started, False)
                        if attempt == UPLOAD_CHUNK_RETRIES:
                            raise RuntimeError(f"upload chunk failed ({resp.status_code})")
                        time.sleep(_retry_sleep(attempt, cap=20.0))
                        continue
                    resp.raise_for_status()
                    upload_pool.record_result(idx, time.perf_counter() - started, True)
                    break
                except RequestException as e:
                    if idx >= 0:
                        upload_pool.record_result(idx, time.perf_counter() - started, False)
                    if attempt == UPLOAD_CHUNK_RETRIES:
                        raise RuntimeError(f"upload chunk failed ({e})") from e
                    time.sleep(_retry_sleep(attempt, cap=20.0))
            sent += len(data)
            if on_progress is not None:
                on_progress(sent, file_size)

    expected_sha256 = hasher.hexdigest()
    used_finish: set[int] = set()
    result = {}
    for attempt in range(1, UPLOAD_FINISH_RETRIES + 1):
        idx = -1
        started = time.perf_counter()
        try:
            idx, session, _ = upload_pool.pick(used_finish)
            resp = session.post(
                f"{upload_server_url}/api/upload/{file_id}/finish",
                params={"session_id": session_id, "expected_sha256": expected_sha256},
                headers=headers,
                timeout=(30, 300),
            )
            _raise_if_upgrade_required(resp)
            if _retryable_status(resp.status_code):
                if resp.status_code == 429:
                    upload_pool.mark_rate_limited(idx)
                upload_pool.record_result(idx, time.perf_counter() - started, False)
                if attempt == UPLOAD_FINISH_RETRIES:
                    raise RuntimeError(f"upload finish failed ({resp.status_code})")
                time.sleep(_retry_sleep(attempt, cap=20.0))
                continue
            resp.raise_for_status()
            upload_pool.record_result(idx, time.perf_counter() - started, True)
            result = resp.json()
            break
        except RequestException as e:
            if idx >= 0:
                upload_pool.record_result(idx, time.perf_counter() - started, False)
            if attempt == UPLOAD_FINISH_RETRIES:
                raise RuntimeError(f"upload finish failed ({e})") from e
            time.sleep(_retry_sleep(attempt, cap=20.0))
    return result


def upload_bytes(
    upload_server_url: str,
    token: str,
    file_id: int,
    data: bytes,
    upload_pool: RequestsClientPool,
    on_progress=None,
) -> dict:
    headers = auth_headers(token)
    session_id = None

    used_start: set[int] = set()
    for attempt in range(1, UPLOAD_START_RETRIES + 1):
        idx = -1
        started = time.perf_counter()
        try:
            idx, session, _ = upload_pool.pick(used_start)
            resp = session.post(f"{upload_server_url}/api/upload/{file_id}/start", headers=headers, timeout=(30, 300))
            _raise_if_upgrade_required(resp)
            if _retryable_status(resp.status_code):
                if resp.status_code == 429:
                    upload_pool.mark_rate_limited(idx)
                upload_pool.record_result(idx, time.perf_counter() - started, False)
                if attempt == UPLOAD_START_RETRIES:
                    raise RuntimeError(f"upload start failed ({resp.status_code})")
                time.sleep(_retry_sleep(attempt))
                continue
            resp.raise_for_status()
            upload_pool.record_result(idx, time.perf_counter() - started, True)
            session_id = resp.json()["session_id"]
            break
        except RequestException as e:
            if idx >= 0:
                upload_pool.record_result(idx, time.perf_counter() - started, False)
            if attempt == UPLOAD_START_RETRIES:
                raise RuntimeError(f"upload start failed ({e})") from e
            time.sleep(_retry_sleep(attempt))

    if not session_id:
        raise RuntimeError("Failed to create upload session")

    file_size = len(data)
    sent = 0
    hasher = hashlib.sha256()
    offset = 0
    while offset < file_size:
        chunk = data[offset: offset + UPLOAD_CHUNK_SIZE]
        offset += len(chunk)
        hasher.update(chunk)
        used_chunk: set[int] = set()
        for attempt in range(1, UPLOAD_CHUNK_RETRIES + 1):
            idx = -1
            started = time.perf_counter()
            try:
                idx, session, _ = upload_pool.pick(used_chunk)
                resp = session.post(
                    f"{upload_server_url}/api/upload/{file_id}/chunk",
                    params={"session_id": session_id},
                    headers={**headers, "Content-Type": "application/octet-stream"},
                    data=chunk,
                    timeout=(30, 300),
                )
                _raise_if_upgrade_required(resp)
                if _retryable_status(resp.status_code):
                    if resp.status_code == 429:
                        upload_pool.mark_rate_limited(idx)
                    upload_pool.record_result(idx, time.perf_counter() - started, False)
                    if attempt == UPLOAD_CHUNK_RETRIES:
                        raise RuntimeError(f"upload chunk failed ({resp.status_code})")
                    time.sleep(_retry_sleep(attempt, cap=20.0))
                    continue
                resp.raise_for_status()
                upload_pool.record_result(idx, time.perf_counter() - started, True)
                break
            except RequestException as e:
                if idx >= 0:
                    upload_pool.record_result(idx, time.perf_counter() - started, False)
                if attempt == UPLOAD_CHUNK_RETRIES:
                    raise RuntimeError(f"upload chunk failed ({e})") from e
                time.sleep(_retry_sleep(attempt, cap=20.0))
        sent += len(chunk)
        if on_progress is not None:
            on_progress(sent, file_size)

    expected_sha256 = hasher.hexdigest()
    used_finish: set[int] = set()
    result = {}
    for attempt in range(1, UPLOAD_FINISH_RETRIES + 1):
        idx = -1
        started = time.perf_counter()
        try:
            idx, session, _ = upload_pool.pick(used_finish)
            resp = session.post(
                f"{upload_server_url}/api/upload/{file_id}/finish",
                params={"session_id": session_id, "expected_sha256": expected_sha256},
                headers=headers,
                timeout=(30, 300),
            )
            _raise_if_upgrade_required(resp)
            if _retryable_status(resp.status_code):
                if resp.status_code == 429:
                    upload_pool.mark_rate_limited(idx)
                upload_pool.record_result(idx, time.perf_counter() - started, False)
                if attempt == UPLOAD_FINISH_RETRIES:
                    raise RuntimeError(f"upload finish failed ({resp.status_code})")
                time.sleep(_retry_sleep(attempt))
                continue
            resp.raise_for_status()
            upload_pool.record_result(idx, time.perf_counter() - started, True)
            result = resp.json()
            break
        except RequestException as e:
            if idx >= 0:
                upload_pool.record_result(idx, time.perf_counter() - started, False)
            if attempt == UPLOAD_FINISH_RETRIES:
                raise RuntimeError(f"upload finish failed ({e})") from e
            time.sleep(_retry_sleep(attempt))
    return result


def report_job(server_url: str, token: str, file_id: int, status: str, report_pool: RequestsClientPool, bytes_downloaded: int | None = None, error: str | None = None):
    used: set[int] = set()
    for attempt in range(1, REPORT_RETRIES + 1):
        idx = -1
        started = time.perf_counter()
        try:
            idx, session, _ = report_pool.pick(used)
            resp = session.post(
                f"{server_url}/api/jobs/report",
                headers=auth_headers(token),
                json={
                    "file_id": file_id,
                    "status": status,
                    "bytes_downloaded": bytes_downloaded,
                    "error": error,
                },
                timeout=(30, 300),
            )
            _raise_if_upgrade_required(resp)
            if resp.status_code == 401:
                report_pool.record_result(idx, time.perf_counter() - started, False)
                raise RuntimeError("Token expired. Run: python minerva_requests.py login")
            if resp.status_code == 409 and status == "completed":
                detail = _response_detail(resp).lower()
                if "not finalized" in detail or "upload" in detail:
                    report_pool.record_result(idx, time.perf_counter() - started, False)
                    if attempt == REPORT_RETRIES:
                        resp.raise_for_status()
                    time.sleep(min(2.0, 0.25 + attempt * 0.1))
                    continue
            if _retryable_status(resp.status_code):
                if resp.status_code == 429:
                    report_pool.mark_rate_limited(idx)
                report_pool.record_result(idx, time.perf_counter() - started, False)
                if attempt == REPORT_RETRIES:
                    resp.raise_for_status()
                time.sleep(_retry_sleep(attempt, cap=20.0))
                continue
            resp.raise_for_status()
            report_pool.record_result(idx, time.perf_counter() - started, True)
            return
        except RequestException:
            if idx >= 0:
                report_pool.record_result(idx, time.perf_counter() - started, False)
            if attempt == REPORT_RETRIES:
                raise
            time.sleep(_retry_sleep(attempt, cap=20.0))


def process_job(
    server_url: str,
    upload_server_url: str,
    token: str,
    job: dict,
    temp_dir: Path,
    progress: Progress,
    progress_lock: threading.Lock,
    keep_files: bool,
    aria2c_connections: int,
    socket_connections: int,
    socket_distinct_ips: bool,
    upload_from_ram: bool,
    ram_max_size: int,
    download_pool: RequestsClientPool,
    upload_pool: RequestsClientPool,
    report_pool: RequestsClientPool,
    adaptive_controller: AdaptiveNetworkingController | None = None,
):
    file_id = job["file_id"]
    url = job["url"]
    dest_path = job["dest_path"]
    label = dest_path[:60] if len(dest_path) <= 60 else "..." + dest_path[-57:]
    known_size = job.get("size", 0) or 0
    with progress_lock:
        tid = progress.add_task(f"[cyan]DL {label}", total=(known_size if known_size > 0 else None))
    local_path = local_path_for_job(temp_dir, url, dest_path)
    adaptive_file_id = int(file_id)
    adaptive_socket_connections = max(1, int(socket_connections))
    if adaptive_controller is not None:
        adaptive_socket_connections = adaptive_controller.begin_job(adaptive_file_id, known_size=known_size)

    last_err = None
    file_size = 0
    uploaded = False
    try:
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                if adaptive_controller is not None:
                    adaptive_socket_connections = adaptive_controller.assigned_for(
                        adaptive_file_id, adaptive_socket_connections
                    )
                if upload_from_ram and known_size <= 0:
                    try:
                        _, probed_total = _probe_range_support(url, download_pool, known_size=0)
                        if probed_total and probed_total > 0:
                            known_size = int(probed_total)
                            progress.update(tid, total=known_size)
                            if adaptive_controller is not None:
                                adaptive_controller.update_progress(adaptive_file_id, 0, known_size)
                    except Exception:
                        pass
                use_ram = bool(upload_from_ram and ram_max_size > 0 and known_size > 0 and known_size <= ram_max_size)

                def _dl_progress(downloaded, total):
                    progress.update(
                        tid,
                        completed=downloaded,
                        total=total,
                    )
                    if adaptive_controller is not None:
                        adaptive_controller.update_progress(adaptive_file_id, downloaded, total)

                if use_ram:
                    payload = download_file_to_memory(
                        url,
                        download_pool,
                        known_size=known_size,
                        on_progress=_dl_progress,
                    )
                    file_size = validate_download_bytes(payload, known_size=known_size, source_hint=dest_path)
                else:
                    download_file(
                        url,
                        local_path,
                        download_pool,
                        aria2c_connections,
                        adaptive_socket_connections,
                        socket_distinct_ips,
                        known_size,
                        on_progress=_dl_progress,
                    )
                    file_size = validate_download(local_path, known_size=known_size, source_hint=dest_path)
                with progress_lock:
                    progress.update(tid, description=f"[yellow]UL {label}", total=file_size)
                if use_ram:
                    upload_bytes(
                        upload_server_url,
                        token,
                        file_id,
                        payload,
                        upload_pool,
                        on_progress=lambda sent, total: progress.update(tid, completed=sent, total=total),
                    )
                else:
                    upload_file(
                        upload_server_url,
                        token,
                        file_id,
                        local_path,
                        upload_pool,
                        on_progress=lambda sent, total: progress.update(tid, completed=sent, total=total),
                    )
                uploaded = True
                break
            except Exception as e:
                last_err = e
                local_path.unlink(missing_ok=True)
                if attempt < MAX_RETRIES:
                    err = str(e).splitlines()[0][:72]
                    with progress_lock:
                        progress.update(tid, description=f"[yellow]RETRY {attempt}/{MAX_RETRIES} {label}")
                    console.print(f"[yellow]  {dest_path}: retry {attempt}/{MAX_RETRIES} ({err})")
                    time.sleep(RETRY_DELAY * attempt)
    finally:
        if adaptive_controller is not None:
            adaptive_controller.end_job(adaptive_file_id)

    if not uploaded:
        with progress_lock:
            progress.update(tid, description=f"[red]FAIL {label}")
        try:
            report_job(server_url, token, file_id, "failed", report_pool=report_pool, error=str(last_err)[:500])
        except Exception:
            pass
        console.print(f"[red]  {dest_path}: {last_err}")
        return

    with progress_lock:
        progress.update(tid, description=f"[green]OK {label}", completed=file_size)
    if not keep_files:
        local_path.unlink(missing_ok=True)
    try:
        report_job(server_url, token, file_id, "completed", report_pool=report_pool, bytes_downloaded=file_size)
    except Exception as e:
        console.print(f"[yellow]  {dest_path}: uploaded but report delayed ({str(e)[:120]})")


def worker_loop(
    server_url: str,
    upload_server_url: str,
    token: str,
    temp_dir: Path,
    concurrency: int,
    batch_size: int,
    aria2c_connections: int,
    socket_connections: int,
    socket_distinct_ips: bool,
    upload_from_ram: bool,
    ram_max_size: int,
    min_job_size: int,
    max_job_size: int,
    job_order: str,
    keep_files: bool,
    proxy_urls: list[str | None],
    proxy_labels: list[str],
    proxy_mode: str,
    performance_tracker: ProtonPerformanceTracker | None,
    weighted_proxy_pick: bool,
    proton_429_timeout: bool,
    network_split_routes: list[tuple[str, tuple[str, int]]],
    adaptive_networking: bool,
    adaptive_target_speed: int,
    adaptive_focus: str,
):
    console.print("[bold green]Minerva DPN Worker (requests edition)")
    console.print(f"  Server:      {server_url}")
    console.print(f"  Upload API:  {upload_server_url}")
    console.print(f"  Concurrency: {concurrency}")
    console.print(f"  Retries:     {MAX_RETRIES}")
    console.print(f"  Keep files:  {'yes' if keep_files else 'no'}")
    console.print(f"  Proxy mode:  {proxy_mode}")
    console.print(f"  Proxy pool:  {len(proxy_urls)} endpoint(s)")
    console.print(f"  aria2c:      {'yes' if HAS_ARIA2C else 'no (using requests)'}")
    if HAS_ARIA2C:
        console.print(f"  aria2c conns:{aria2c_connections} (requests for files < 5MB)")
    console.print(f"  socket conns/file: {max(1, socket_connections)}")
    console.print(f"  socket distinct ips: {'yes' if socket_distinct_ips else 'no'}")
    if upload_from_ram:
        console.print(f"  upload from ram: yes (max {ram_max_size} bytes)")
    if min_job_size > 0 or max_job_size > 0:
        min_txt = str(min_job_size) if min_job_size > 0 else "0"
        max_txt = str(max_job_size) if max_job_size > 0 else "inf"
        console.print(f"  job size filter: {min_txt}..{max_txt} bytes")
    if job_order != "default":
        console.print(f"  job order:  {job_order} first")
    if proton_429_timeout and proxy_mode.startswith("proton"):
        console.print("  proton 429 timeout: 60s")
    if network_split_routes:
        route_names = ", ".join(route for route, _ in network_split_routes)
        console.print(f"  network split: {route_names}")
    if adaptive_networking:
        console.print(
            f"  adaptive networking: on (target {adaptive_target_speed} B/s, focus={adaptive_focus})"
        )
    if performance_tracker is not None:
        tested = sum(
            1
            for server in proxy_labels
            if server in performance_tracker.performance_data
            and performance_tracker.performance_data[server].get("successful_attempts", 0) > 0
        )
        if tested > 0:
            console.print(f"  Perf data:  loaded {tested} tested Proton server(s)")
    console.print()

    temp_dir.mkdir(parents=True, exist_ok=True)
    q: queue.Queue = queue.Queue(maxsize=max(1, concurrency * QUEUE_PREFETCH))
    stop_event = threading.Event()
    seen_ids: set[int] = set()
    seen_lock = threading.Lock()
    progress_lock = threading.Lock()
    size_probe_cache: dict[int, int] = {}
    adaptive_controller = AdaptiveNetworkingController(
        enabled=adaptive_networking,
        target_bps=adaptive_target_speed,
        focus=adaptive_focus,
        per_file_cap=max(1, int(socket_connections)),
        total_budget=max(1, int(socket_connections)) * max(1, int(concurrency)),
    )

    expanded_proxy_urls, expanded_proxy_labels, expanded_source_addrs = _expand_proxy_routes(
        proxy_urls, proxy_labels, network_split_routes
    )
    sessions_dl = [
        _build_session(
            p,
            max_pool=max(128, concurrency * 8),
            source_address=expanded_source_addrs[i],
        )
        for i, p in enumerate(expanded_proxy_urls)
    ]
    sessions_ul = [
        _build_session(
            p,
            max_pool=max(64, concurrency * 4),
            source_address=expanded_source_addrs[i],
        )
        for i, p in enumerate(expanded_proxy_urls)
    ]
    sessions_rp = [
        _build_session(
            p,
            max_pool=max(64, concurrency * 4),
            source_address=expanded_source_addrs[i],
        )
        for i, p in enumerate(expanded_proxy_urls)
    ]
    sessions_ctl = [
        _build_session(
            p,
            max_pool=max(64, concurrency * 2),
            source_address=expanded_source_addrs[i],
        )
        for i, p in enumerate(expanded_proxy_urls)
    ]

    cooldown_seconds = 60 if (proton_429_timeout and proxy_mode.startswith("proton")) else 0
    download_pool = RequestsClientPool(
        sessions_dl,
        expanded_proxy_labels,
        expanded_proxy_urls,
        performance_tracker,
        weighted_proxy_pick,
        cooldown_seconds,
    )
    upload_pool = RequestsClientPool(
        sessions_ul,
        expanded_proxy_labels,
        expanded_proxy_urls,
        performance_tracker,
        weighted_proxy_pick,
        cooldown_seconds,
    )
    report_pool = RequestsClientPool(
        sessions_rp,
        expanded_proxy_labels,
        expanded_proxy_urls,
        performance_tracker,
        weighted_proxy_pick,
        cooldown_seconds,
    )
    control_pool = RequestsClientPool(
        sessions_ctl,
        expanded_proxy_labels,
        expanded_proxy_urls,
        performance_tracker,
        weighted_proxy_pick,
        cooldown_seconds,
    )

    def producer():
        no_jobs_warned = False
        last_filter_warn = 0.0
        while not stop_event.is_set():
            try:
                if q.qsize() >= concurrency:
                    time.sleep(0.5)
                    continue
                added_this_cycle = 0
                tries = 0
                target_to_fill = min(q.maxsize, max(concurrency, q.qsize() + max(1, batch_size)))
                while not stop_event.is_set() and q.qsize() < target_to_fill:
                    tries += 1
                    idx = -1
                    started = time.perf_counter()
                    try:
                        idx, session, _ = control_pool.pick()
                        resp = session.get(
                            f"{server_url}/api/jobs",
                            params={"count": min(batch_size, max(1, q.maxsize - q.qsize()))},
                            headers=auth_headers(token),
                            timeout=(30, 300),
                        )
                        if resp.status_code == 426:
                            _raise_if_upgrade_required(resp)
                        if resp.status_code == 401:
                            control_pool.record_result(idx, time.perf_counter() - started, False)
                            console.print("[red]Token expired. Run: python minerva_requests.py login")
                            stop_event.set()
                            break
                        if resp.status_code == 429:
                            control_pool.mark_rate_limited(idx)
                        resp.raise_for_status()
                        control_pool.record_result(idx, time.perf_counter() - started, True)
                        jobs = resp.json().get("jobs", [])
                        if not jobs:
                            if added_this_cycle <= 0:
                                if not no_jobs_warned:
                                    console.print("[dim]No jobs available, waiting 30s...")
                                    no_jobs_warned = True
                                time.sleep(8 + random.random() * 4)
                            break

                        no_jobs_warned = False
                        total_jobs = len(jobs)
                        matched_jobs = []
                        for j in jobs:
                            if not isinstance(j, dict):
                                continue
                            if min_job_size > 0 or max_job_size > 0 or job_order != "default":
                                _detect_job_size_for_filter(j, download_pool, size_probe_cache)
                            if _job_size_in_range(j, min_job_size, max_job_size):
                                matched_jobs.append(j)
                        if job_order == "biggest":
                            matched_jobs.sort(key=_job_sort_size, reverse=True)
                        elif job_order == "smallest":
                            matched_jobs.sort(key=_job_sort_size)
                        for job in matched_jobs:
                            file_id = job.get("file_id") if isinstance(job, dict) else None
                            if file_id is None:
                                continue
                            with seen_lock:
                                if file_id in seen_ids:
                                    continue
                                seen_ids.add(file_id)
                            while not stop_event.is_set():
                                try:
                                    q.put(job, timeout=0.5)
                                    added_this_cycle += 1
                                    break
                                except queue.Full:
                                    continue

                        if (
                            (min_job_size > 0 or max_job_size > 0)
                            and added_this_cycle <= 0
                            and total_jobs > 0
                            and (time.time() - last_filter_warn) > 15
                        ):
                            console.print(
                                f"[dim]No jobs matched size filter ({min_job_size or 0}..{max_job_size or 'inf'} bytes); continuing to poll..."
                            )
                            last_filter_warn = time.time()

                        if min_job_size > 0 or max_job_size > 0:
                            # Keep requesting until we have enough in-range jobs for worker pressure.
                            if q.qsize() >= target_to_fill:
                                break
                            if tries < 8:
                                continue
                        break
                    except RequestException as e:
                        if idx >= 0:
                            control_pool.record_result(idx, time.perf_counter() - started, False)
                        console.print(f"[red]Server error: {e}. Retrying in 10s...")
                        time.sleep(6 + random.random() * 4)
                        break
            except Exception as e:
                # Keep producer alive on malformed payloads or edge-case parsing issues.
                console.print(f"[yellow]Producer loop error: {str(e)[:160]}")
                time.sleep(1.0)
        for _ in range(concurrency):
            q.put(_STOP)

    def worker(progress: Progress):
        while True:
            job = q.get()
            if job is _STOP:
                q.task_done()
                return
            try:
                process_job(
                    server_url,
                    upload_server_url,
                    token,
                    job,
                    temp_dir,
                    progress,
                    progress_lock,
                    keep_files,
                    aria2c_connections,
                    socket_connections,
                    socket_distinct_ips,
                    upload_from_ram,
                    ram_max_size,
                    download_pool,
                    upload_pool,
                    report_pool,
                    adaptive_controller=adaptive_controller if adaptive_networking else None,
                )
            finally:
                with seen_lock:
                    seen_ids.discard(job["file_id"])
                q.task_done()

    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        DownloadColumn(),
        TransferSpeedColumn(),
        console=console,
    ) as progress:
        producer_t = threading.Thread(target=producer, daemon=True)
        workers = [threading.Thread(target=worker, args=(progress,), daemon=True) for _ in range(concurrency)]
        producer_t.start()
        for t in workers:
            t.start()
        try:
            while producer_t.is_alive():
                producer_t.join(timeout=0.5)
        except KeyboardInterrupt:
            console.print("\n[yellow]Shutting down...")
            stop_event.set()
            for _ in range(concurrency):
                q.put(_STOP)
        finally:
            q.join()
            download_pool.flush_performance()
            upload_pool.flush_performance()
            report_pool.flush_performance()
            control_pool.flush_performance()
            for s in sessions_dl + sessions_ul + sessions_rp + sessions_ctl:
                s.close()


def check_for_update():
    return


@click.group()
def cli():
    """Minerva DPN Worker (requests edition)."""
    check_for_update()


@cli.command()
@click.option("--server", default=SERVER_URL, help="Manager server URL")
def login(server):
    """Authenticate with Discord."""
    do_login(server)


@cli.command()
@click.option("--server", default=SERVER_URL, help="Manager server URL")
@click.option("--upload-server", default=UPLOAD_SERVER_URL, help="Upload API URL")
@click.option("-c", "--concurrency", default=2, help="Concurrent workers")
@click.option("-b", "--batch-size", default=10, help="Files per batch")
@click.option("-a", "--aria2c-connections", default=8, help="aria2c connections per file")
@click.option("--socket-connections", default=1, help="Downloader connections per file via HTTP Range")
@click.option(
    "--socket-distinct-ips",
    is_flag=True,
    help="For multipart downloads, try different proxy IPs per part when available",
)
@click.option(
    "--proton-429-timeout",
    is_flag=True,
    help="In proton mode, put proxies that return HTTP 429 into a 60s cooldown",
)
@click.option(
    "--upload-from-ram",
    is_flag=True,
    help="Keep downloads in memory and upload directly without writing to disk (size-limited)",
)
@click.option("--ram-max-size", default="512MB", help="Maximum file size eligible for RAM upload mode")
@click.option("--min-job-size", default="", help="Minimum accepted job size (e.g. 500MB, 2GiB, bytes)")
@click.option("--max-job-size", default="", help="Maximum accepted job size (e.g. 2GB, 10GiB, bytes)")
@click.option(
    "--job-order",
    type=click.Choice(["default", "biggest", "smallest", "largest"], case_sensitive=False),
    default="default",
    help="Order accepted jobs before enqueueing",
)
@click.option(
    "--adaptive-networking",
    is_flag=True,
    help="Dynamically rebalance multipart socket connections across active downloads",
)
@click.option(
    "--adaptive-target-speed",
    default="20MB",
    help="Target per-file download speed for adaptive mode (bytes/s, e.g. 20MB, 100MiB)",
)
@click.option(
    "--adaptive-focus",
    type=click.Choice(["auto", "decide", "slow", "fast", "smallest", "biggest"], case_sensitive=False),
    default="auto",
    help="Adaptive prioritization mode",
)
@click.option("--network-split", default="", help="Split connections across routes, e.g. en0,inet6 or 192.168.1.10,::")
@click.option("--temp-dir", default=str(TEMP_DIR), help="Temp download dir")
@click.option("--keep-files", is_flag=True, help="Keep downloaded files after upload")
@click.option("--proxy", default=None, help="Proxy mode: 'proton' or a proxy list file path (e.g. proxies.txt)")
def run(
    server,
    upload_server,
    concurrency,
    batch_size,
    aria2c_connections,
    socket_connections,
    socket_distinct_ips,
    proton_429_timeout,
    upload_from_ram,
    ram_max_size,
    min_job_size,
    max_job_size,
    job_order,
    adaptive_networking,
    adaptive_target_speed,
    adaptive_focus,
    network_split,
    temp_dir,
    keep_files,
    proxy,
):
    """Start downloading and uploading files."""
    token = load_token()
    if not token:
        console.print("[red]Not logged in. Run: python minerva_requests.py login")
        return
    try:
        proxy_urls, proxy_labels, proxy_mode, performance_tracker, weighted_proxy_pick = resolve_proxy_config(proxy)
    except Exception as e:
        console.print(f"[red]Invalid proxy configuration: {e}")
        return
    try:
        ram_max_size_bytes = parse_size_to_bytes(ram_max_size)
        min_job_size_bytes = parse_size_to_bytes(min_job_size)
        max_job_size_bytes = parse_size_to_bytes(max_job_size)
        adaptive_target_bps = parse_size_to_bytes(adaptive_target_speed)
    except ValueError as e:
        console.print(f"[red]Invalid size option: {e}")
        return
    if upload_from_ram and ram_max_size_bytes <= 0:
        console.print("[red]Invalid RAM option: --ram-max-size must be greater than 0 when --upload-from-ram is enabled")
        return
    if max_job_size_bytes > 0 and min_job_size_bytes > max_job_size_bytes:
        console.print("[red]Invalid job size filter: min-job-size cannot be greater than max-job-size")
        return
    normalized_job_order = str(job_order).strip().lower()
    if normalized_job_order == "largest":
        normalized_job_order = "biggest"
    normalized_adaptive_focus = str(adaptive_focus).strip().lower()
    if normalized_adaptive_focus == "decide":
        normalized_adaptive_focus = "auto"
    if normalized_adaptive_focus not in ADAPTIVE_FOCUS_CHOICES:
        console.print(
            "[red]Invalid adaptive focus. Choose one of: auto, decide, slow, fast, smallest, biggest"
        )
        return
    if adaptive_networking and adaptive_target_bps <= 0:
        console.print("[red]Invalid adaptive networking option: --adaptive-target-speed must be > 0")
        return
    try:
        network_split_routes = parse_network_split(network_split)
    except ValueError as e:
        console.print(f"[red]Invalid network split: {e}")
        return
    worker_loop(
        server,
        upload_server,
        token,
        Path(temp_dir),
        concurrency,
        batch_size,
        aria2c_connections,
        max(1, int(socket_connections)),
        bool(socket_distinct_ips),
        bool(upload_from_ram),
        ram_max_size_bytes,
        min_job_size_bytes,
        max_job_size_bytes,
        normalized_job_order,
        keep_files,
        proxy_urls,
        proxy_labels,
        proxy_mode,
        performance_tracker,
        weighted_proxy_pick,
        bool(proton_429_timeout),
        network_split_routes,
        bool(adaptive_networking),
        adaptive_target_bps,
        normalized_adaptive_focus,
    )


@cli.command()
def status():
    """Show login status."""
    token = load_token()
    console.print("[green]Logged in" if token else "[red]Not logged in")


if __name__ == "__main__":
    cli()


