"""Traffic-rate baselining and evidence-based flood detection for SIS."""

from __future__ import annotations

import hashlib
import math
import os
import re
import time
from collections import Counter, deque

import numpy as np
from sklearn.ensemble import IsolationForest

_STRONG_DOS_RE = re.compile(
    r"\b(?:dos\s+attack|critical\s+flood|flood\s+(?:attack|detected)|inundaci[oó]n\s+de\s+red)\b",
    re.IGNORECASE,
)


def _positive_float(name: str, default: float) -> float:
    try:
        value = float(os.getenv(name, default))
        return value if value > 0 else default
    except (TypeError, ValueError):
        return default


def _positive_int(name: str, default: int) -> int:
    try:
        value = int(os.getenv(name, default))
        return value if value > 0 else default
    except (TypeError, ValueError):
        return default


def traffic_key(doc: dict) -> tuple[str, str, str]:
    return (
        str(doc.get("src_ip", "unknown")),
        str(doc.get("dst_ip", "unknown")),
        str(doc.get("protocol", "unknown")),
    )


def has_strong_dos_signature(doc: dict) -> bool:
    text = f"{doc.get('message', '')} {doc.get('raw_log', '')}"
    return bool(_STRONG_DOS_RE.search(text))


class EventReplayGuard:
    """Drops exact duplicate sensor records delivered through replayed ingestion paths."""

    def __init__(self, ttl_seconds: float | None = None, max_entries: int = 100_000):
        self.ttl_seconds = ttl_seconds or _positive_float("SIS_EVENT_DEDUP_TTL_SECONDS", 600.0)
        self.max_entries = max_entries
        self.seen = {}
        self.order = deque()

    @staticmethod
    def fingerprint(raw_event: str) -> str:
        return hashlib.sha256(raw_event.encode("utf-8", errors="replace")).hexdigest()

    def accept(self, raw_event: str, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        cutoff = now - self.ttl_seconds
        while self.order and (self.order[0][0] < cutoff or len(self.seen) > self.max_entries):
            observed_at, fingerprint = self.order.popleft()
            if self.seen.get(fingerprint) == observed_at:
                self.seen.pop(fingerprint, None)
        fingerprint = self.fingerprint(raw_event)
        if fingerprint in self.seen:
            return False
        self.seen[fingerprint] = now
        self.order.append((now, fingerprint))
        return True

    def reset(self) -> None:
        self.seen.clear()
        self.order.clear()


class TrafficRateMonitor:
    """Tracks fresh source-timed events and marks only concentrated floods."""

    def __init__(
        self,
        window_seconds: float | None = None,
        flow_min_events: int | None = None,
        flow_min_eps: float | None = None,
        destination_min_events: int | None = None,
        destination_min_eps: float | None = None,
        icmp_min_events: int | None = None,
        icmp_min_eps: float | None = None,
        max_event_lag_seconds: float | None = None,
    ):
        self.window_seconds = window_seconds or _positive_float("SIS_FLOOD_WINDOW_SECONDS", 5.0)
        self.flow_min_events = flow_min_events or _positive_int("SIS_FLOOD_FLOW_MIN_EVENTS", 120)
        self.flow_min_eps = flow_min_eps or _positive_float("SIS_FLOOD_FLOW_MIN_EPS", 20.0)
        self.destination_min_events = destination_min_events or _positive_int(
            "SIS_FLOOD_DESTINATION_MIN_EVENTS", 250
        )
        self.destination_min_eps = destination_min_eps or _positive_float(
            "SIS_FLOOD_DESTINATION_MIN_EPS", 40.0
        )
        self.icmp_min_events = icmp_min_events or _positive_int("SIS_FLOOD_ICMP_MIN_EVENTS", 1000)
        self.icmp_min_eps = icmp_min_eps or _positive_float("SIS_FLOOD_ICMP_MIN_EPS", 150.0)
        self.max_event_lag_seconds = max_event_lag_seconds or _positive_float(
            "SIS_FLOOD_MAX_EVENT_LAG_SECONDS", 30.0
        )
        self.events = deque()

    @staticmethod
    def _is_icmp_key(key: tuple[str, str, str]) -> bool:
        return key[2].lower() in {"icmp", "icmpv4", "icmp6", "icmpv6"}

    def observe(self, docs: list[dict], now: float | None = None) -> dict:
        now = time.time() if now is None else now
        cutoff = now - self.window_seconds
        while self.events and self.events[0][0] < cutoff:
            self.events.popleft()

        explicit_keys = set()
        fresh_docs = []
        stale_events = 0
        for doc in docs:
            event_time = float(doc.get("_event_epoch", now))
            if event_time < now - self.max_event_lag_seconds or event_time > now + 5:
                stale_events += 1
                continue
            fresh_docs.append(doc)
            key = traffic_key(doc)
            self.events.append((event_time, key, str(doc.get("source", "unknown"))))
            if has_strong_dos_signature(doc):
                explicit_keys.add(key)

        # An out-of-order fresh event may have entered behind newer events.
        if self.events:
            self.events = deque(sorted(self.events, key=lambda item: item[0]))
            while self.events and self.events[0][0] < cutoff:
                self.events.popleft()

        flow_counts = Counter(key for _, key, _ in self.events)
        destination_counts = Counter(
            key[1] for _, key, _ in self.events if not self._is_icmp_key(key)
        )
        flood_keys = set(explicit_keys)
        reasons = {key: "signature" for key in explicit_keys}

        for key, count in flow_counts.items():
            eps = count / self.window_seconds
            if self._is_icmp_key(key):
                if count >= self.icmp_min_events and eps >= self.icmp_min_eps:
                    flood_keys.add(key)
                    reasons[key] = "icmp_flood"
            elif count >= self.flow_min_events and eps >= self.flow_min_eps:
                flood_keys.add(key)
                reasons[key] = "concentrated_flow"

        flooded_destinations = {
            destination
            for destination, count in destination_counts.items()
            if count >= self.destination_min_events
            and count / self.window_seconds >= self.destination_min_eps
        }
        for key in flow_counts:
            if not self._is_icmp_key(key) and key[1] in flooded_destinations:
                flood_keys.add(key)
                reasons.setdefault(key, "destination_flood")

        unique_pairs = len({(key[0], key[1]) for key in flow_counts})
        snort_events = sum(1 for _, _, source in self.events if source == "snort")
        max_flow_count = max(flow_counts.values(), default=0)
        return {
            "accepted_eps": len(self.events) / self.window_seconds,
            "batch_events": len(docs),
            "fresh_events": len(fresh_docs),
            "stale_events": stale_events,
            "max_flow_eps": max_flow_count / self.window_seconds,
            "unique_pairs": unique_pairs,
            "snort_ratio": snort_events / len(self.events) if self.events else 0.0,
            "flood_keys": flood_keys,
            "reasons": reasons,
        }

    def is_flood(self, doc: dict, metrics: dict) -> bool:
        return traffic_key(doc) in metrics["flood_keys"]

    def reset(self) -> None:
        self.events.clear()


class TrafficBaselineModel:
    """IsolationForest over stable rate features; anomalies inform but never prove DoS."""

    def __init__(self, min_samples: int | None = None, history_size: int | None = None):
        self.min_samples = min_samples or _positive_int("SIS_AI_MIN_BASELINE_SAMPLES", 30)
        self.history_size = history_size or _positive_int("SIS_AI_BASELINE_WINDOW", 300)
        contamination = _positive_float("SIS_AI_CONTAMINATION", 0.02)
        contamination = min(max(contamination, 0.001), 0.2)
        self.model = IsolationForest(
            contamination=contamination,
            n_estimators=150,
            random_state=42,
            n_jobs=-1,
        )
        self.history = deque(maxlen=self.history_size)
        self.trained = False
        self.samples_since_fit = 0

    @staticmethod
    def feature_vector(metrics: dict) -> list[float]:
        return [
            math.log1p(max(float(metrics.get("accepted_eps", 0.0)), 0.0)),
            math.log1p(max(float(metrics.get("max_flow_eps", 0.0)), 0.0)),
            math.log1p(max(float(metrics.get("unique_pairs", 0.0)), 0.0)),
            min(max(float(metrics.get("snort_ratio", 0.0)), 0.0), 1.0),
        ]

    def score(self, metrics: dict, learn: bool = True) -> float:
        vector = self.feature_vector(metrics)
        score = 0.5
        if self.trained:
            score = float(self.model.decision_function(np.asarray([vector]))[0])

        # Never teach confirmed attack windows as normal baseline traffic.
        if learn and not metrics.get("flood_keys"):
            self.history.append(vector)
            self.samples_since_fit += 1
            if len(self.history) >= self.min_samples and (
                not self.trained or self.samples_since_fit >= 30
            ):
                self.model.fit(np.asarray(self.history))
                self.trained = True
                self.samples_since_fit = 0
        return score

    def reset(self) -> None:
        self.history.clear()
        self.trained = False
        self.samples_since_fit = 0
