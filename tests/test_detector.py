import unittest
from pathlib import Path

from detector import MADAnomalyDetector, detect, load_csv, median, median_absolute_deviation, precision_recall

DATA = Path(__file__).parents[1] / "data" / "network_traffic.csv"


class DetectorTests(unittest.TestCase):
    def test_median_and_mad(self):
        self.assertEqual(median([1, 5, 2]), 2)
        self.assertEqual(median([1, 2, 3, 4]), 2.5)
        self.assertEqual(median_absolute_deviation([1, 2, 3, 4, 100]), 1)

    def test_csv_has_expected_rows(self):
        rows, labels = load_csv(DATA)
        self.assertEqual(len(rows), 30)
        self.assertEqual(sum(labels), 4)

    def test_detector_flags_large_spikes(self):
        rows, _ = load_csv(DATA)
        detector = MADAnomalyDetector().fit(rows)
        predictions = detector.predict(rows)
        self.assertEqual(sum(predictions), 4)
        self.assertEqual(predictions[20], 1)
        self.assertEqual(predictions[21], 0)

    def test_metrics(self):
        precision, recall = precision_recall([0, 1, 1, 0], [0, 1, 0, 1])
        self.assertAlmostEqual(precision, 0.5)
        self.assertAlmostEqual(recall, 0.5)

    def test_end_to_end_metrics_are_perfect_on_sample(self):
        predictions, _, (precision, recall) = detect(DATA)
        self.assertEqual(len(predictions), 30)
        self.assertEqual(precision, 1.0)
        self.assertEqual(recall, 1.0)


if __name__ == "__main__":
    unittest.main()
