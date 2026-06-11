"""Traffic-rate baselining and evidence-based flood detection for SIS."""

from __future__ import annotations

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


class TrafficRateMonitor:
    """Tracks accepted events in a fixed window and marks only concentrated floods."""

    def __init__(
        self,
        window_seconds: float | None = None,
        flow_min_events: int | None = None,
        flow_min_eps: float | None = None,
        destination_min_events: int | None = None,
        destination_min_eps: float | None = None,
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
        self.events = deque()

    def observe(self, docs: list[dict], now: float | None = None) -> dict:
        now = time.monotonic() if now is None else now
        cutoff = now - self.window_seconds
        while self.events and self.events[0][0] < cutoff:
            self.events.popleft()

        explicit_keys = set()
        for doc in docs:
            key = traffic_key(doc)
            self.events.append((now, key, str(doc.get("source", "unknown"))))
            if has_strong_dos_signature(doc):
                explicit_keys.add(key)

        flow_counts = Counter(key for _, key, _ in self.events)
        destination_counts = Counter(key[1] for _, key, _ in self.events)
        flood_keys = set(explicit_keys)
        reasons = {key: "signature" for key in explicit_keys}

        for key, count in flow_counts.items():
            eps = count / self.window_seconds
            if count >= self.flow_min_events and eps >= self.flow_min_eps:
                flood_keys.add(key)
                reasons[key] = "concentrated_flow"

        flooded_destinations = {
            destination
            for destination, count in destination_counts.items()
            if count >= self.destination_min_events
            and count / self.window_seconds >= self.destination_min_eps
        }
        for key in flow_counts:
            if key[1] in flooded_destinations:
                flood_keys.add(key)
                reasons.setdefault(key, "destination_flood")

        unique_pairs = len({(key[0], key[1]) for key in flow_counts})
        snort_events = sum(1 for _, _, source in self.events if source == "snort")
        max_flow_count = max(flow_counts.values(), default=0)
        metrics = {
            "accepted_eps": len(self.events) / self.window_seconds,
            "batch_events": len(docs),
            "max_flow_eps": max_flow_count / self.window_seconds,
            "unique_pairs": unique_pairs,
            "snort_ratio": snort_events / len(self.events) if self.events else 0.0,
            "flood_keys": flood_keys,
            "reasons": reasons,
        }
        return metrics

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
