# Network Traffic Anomaly Detector

A robust, dependency-free machine-learning mini-project that detects unusual network traffic windows using the median absolute deviation (MAD), a statistic that is less sensitive to extreme values than mean-based z-scores.

## Overview

Security and operations teams need a lightweight way to surface traffic spikes for investigation. This project models normal traffic using three interpretable features—bytes per second, packets per second, and unique destinations—and flags windows whose robust z-score exceeds a configurable threshold.

## Problem statement

Given short network traffic summaries, identify windows that differ sharply from the normal baseline. The detector is intended for triage and learning; an alert is not proof of malicious activity.

## Features

- Robust feature scoring with median and MAD.
- Configurable anomaly threshold, defaulting to 3.5.
- CSV input with reproducible sample data.
- Precision and recall reporting when labels are available.
- Unit tests and a standard-library-only implementation.

## Technology stack

- Python 3.10+
- Robust statistics: median absolute deviation
- CSV and `argparse` from the standard library
- `unittest` for testing

## Installation

```bash
git clone https://github.com/mohan843/network-traffic-anomaly-detector.git
cd network-traffic-anomaly-detector
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\\Scripts\\activate
pip install -r requirements.txt
```

There are no third-party runtime dependencies.

## Execution

```bash
python detector.py
```

Use a stricter threshold when you want fewer alerts:

```bash
python detector.py --threshold 5.0
```

## Testing

```bash
python -m unittest discover -s tests -v
```

## Sample output

```text
Window 01: NORMAL (robust score=0.67)
...
Window 21: ANOMALY (robust score=100.00)
...
Precision: 100.0%
Recall: 100.0%
```

## Limitations and ethical use

The included dataset is small and illustrative. Real deployments should learn baselines by host, service, and time-of-day; account for seasonality; evaluate false positives; and avoid treating an anomaly as a security verdict without human investigation.

## Future improvements

- Add rolling, time-aware baselines and drift monitoring.
- Support per-host and per-service thresholds.
- Add precision-recall curves and alert severity levels.
- Stream events from a log or message queue.
- Compare MAD with Isolation Forest and autoencoder baselines.
