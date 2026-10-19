"""Robust network traffic anomaly detection using median absolute deviation."""
from __future__ import annotations

import argparse
import csv
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

FEATURES = ("bytes_per_second", "packets_per_second", "unique_destinations")


@dataclass(frozen=True)
class TrafficWindow:
    bytes_per_second: float
    packets_per_second: float
    unique_destinations: float

    def vector(self) -> list[float]:
        return [self.bytes_per_second, self.packets_per_second, self.unique_destinations]


def median(values: Sequence[float]) -> float:
    if not values:
        raise ValueError("Cannot calculate the median of an empty sequence")
    ordered = sorted(values)
    midpoint = len(ordered) // 2
    return ordered[midpoint] if len(ordered) % 2 else (ordered[midpoint - 1] + ordered[midpoint]) / 2


def median_absolute_deviation(values: Sequence[float]) -> float:
    center = median(values)
    return median([abs(value - center) for value in values])


class MADAnomalyDetector:
    """Flags a row when any feature's robust z-score exceeds the threshold."""

    def __init__(self, threshold: float = 3.5) -> None:
        self.threshold = threshold

    def fit(self, rows: Sequence[Sequence[float]]) -> "MADAnomalyDetector":
        if not rows:
            raise ValueError("At least one baseline row is required")
        self.centers = [median([row[i] for row in rows]) for i in range(len(rows[0]))]
        self.scales = [median_absolute_deviation([row[i] for row in rows]) or 1.0 for i in range(len(rows[0]))]
        return self

    def scores(self, rows: Sequence[Sequence[float]]) -> list[float]:
        return [max(abs(0.6745 * (value - center) / scale) for value, center, scale in zip(row, self.centers, self.scales)) for row in rows]

    def predict(self, rows: Sequence[Sequence[float]]) -> list[int]:
        return [int(score >= self.threshold) for score in self.scores(rows)]


def load_csv(path: str | Path) -> tuple[list[list[float]], list[int]]:
    with Path(path).open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        rows, labels = [], []
        for item in reader:
            rows.append([float(item[name]) for name in FEATURES])
            labels.append(int(item["is_anomaly"]))
    return rows, labels


def precision_recall(actual: Sequence[int], predicted: Sequence[int]) -> tuple[float, float]:
    true_positive = sum(a == p == 1 for a, p in zip(actual, predicted))
    false_positive = sum(a == 0 and p == 1 for a, p in zip(actual, predicted))
    false_negative = sum(a == 1 and p == 0 for a, p in zip(actual, predicted))
    precision = true_positive / (true_positive + false_positive) if true_positive + false_positive else 0.0
    recall = true_positive / (true_positive + false_negative) if true_positive + false_negative else 0.0
    return precision, recall


def detect(data_path: str | Path, threshold: float = 3.5) -> tuple[list[int], list[float], tuple[float, float]]:
    rows, labels = load_csv(data_path)
    detector = MADAnomalyDetector(threshold).fit(rows)
    predictions = detector.predict(rows)
    return predictions, detector.scores(rows), precision_recall(labels, predictions)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Detect unusual network traffic windows.")
    parser.add_argument("--data", default="data/network_traffic.csv")
    parser.add_argument("--threshold", type=float, default=3.5)
    args = parser.parse_args()
    predictions, scores, (precision, recall) = detect(args.data, args.threshold)
    for index, (prediction, score) in enumerate(zip(predictions, scores), start=1):
        label = "ANOMALY" if prediction else "NORMAL"
        print(f"Window {index:02d}: {label} (robust score={score:.2f})")
    print(f"Precision: {precision:.1%}")
    print(f"Recall: {recall:.1%}")
