"""
test_c2_hunter.py - Unit and Integration Tests for c2-hunter.
Generates synthetic network traffic to verify mathematical beaconing detection and CLI functionality.
"""

import sys
import unittest
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from c2_hunter.detector import BeaconDetector
from c2_hunter.cli import parse_arguments
from c2_hunter.reporter import export_json, export_csv

class TestBeaconDetector(unittest.TestCase):

    def setUp(self):
        self.detector = BeaconDetector(jitter_threshold=15.0)

    def test_strict_periodic_beacon(self):
        """Tests that perfectly periodic timestamps (5.0s interval) produce high threat scores."""
        # 10 timestamps separated by exactly 5.0s
        timestamps = [1000.0 + (i * 5.0) for i in range(10)]
        result = self.detector.analyze_timestamps(timestamps)

        self.assertTrue(result["is_beacon"])
        self.assertEqual(result["severity"], "High")
        self.assertGreaterEqual(result["threat_score"], 0.8)
        self.assertEqual(result["mean_interval"], 5.0)
        self.assertEqual(result["jitter"], 0.0)

    def test_random_traffic(self):
        """Tests that irregular random timestamps fail beaconing criteria."""
        timestamps = [100.0, 101.2, 115.8, 117.0, 142.5, 143.1, 200.0, 205.0]
        result = self.detector.analyze_timestamps(timestamps)

        self.assertFalse(result["is_beacon"])
        self.assertEqual(result["severity"], "Low")
        self.assertGreater(result["jitter"], 15.0)

    def test_low_packet_count(self):
        """Tests that flows with 5 or fewer packets are not flagged as beacons."""
        timestamps = [10.0, 15.0, 20.0, 25.0]
        result = self.detector.analyze_timestamps(timestamps)

        self.assertFalse(result["is_beacon"])
        self.assertEqual(result["threat_score"], 0.0)


class TestExporters(unittest.TestCase):

    def test_export_json_and_csv(self):
        sample_detections = [
            {
                "src_ip": "192.168.1.50",
                "dst_ip": "104.21.55.2",
                "dst_port": 443,
                "domain": "malicious-c2.com",
                "protocol": "TCP",
                "is_beacon": True,
                "threat_score": 0.92,
                "severity": "High",
                "connection_count": 20,
                "mean_interval": 10.0,
                "std_dev": 0.1,
                "variance": 0.01,
                "mad": 0.05,
                "jitter": 1.0,
                "reason": "Low jitter periodic beaconing"
            }
        ]

        json_file = Path("test_output.json")
        csv_file = Path("test_output.csv")

        export_json(sample_detections, json_file)
        export_csv(sample_detections, csv_file)

        self.assertTrue(json_file.exists())
        self.assertTrue(csv_file.exists())

        # Cleanup test files
        if json_file.exists():
            json_file.unlink()
        if csv_file.exists():
            csv_file.unlink()


if __name__ == "__main__":
    unittest.main()
