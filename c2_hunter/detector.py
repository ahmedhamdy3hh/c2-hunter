"""
detector.py - Mathematical Beacon Detection Engine for c2-hunter.
Calculates statistical metrics (Mean, StdDev, Variance, MAD, Jitter %) and computes threat scores.
"""

import math
import statistics
from typing import List, Dict, Any


class BeaconDetector:
    """
    Analyzes timestamp intervals of a network session flow to detect periodic C2 beaconing.
    """

    def __init__(self, jitter_threshold: float = 15.0):
        """
        Args:
            jitter_threshold (float): Jitter threshold percentage below which activity is flagged as beaconing.
        """
        self.jitter_threshold = float(jitter_threshold)

    def analyze_timestamps(self, timestamps: List[float]) -> Dict[str, Any]:
        """
        Computes statistical beacon metrics for a given list of timestamps.

        Args:
            timestamps (List[float]): Sorted list of packet timestamps.

        Returns:
            Dict[str, Any]: Analysis result including threat_score, is_beacon, and statistical metrics.
        """
        total_connections = len(timestamps)

        # Baseline result if insufficient packet data
        if total_connections <= 5:
            return {
                "is_beacon": False,
                "threat_score": 0.0,
                "severity": "Low",
                "reason": "Insufficient connections (<= 5 requests)",
                "connection_count": total_connections,
                "mean_interval": 0.0,
                "std_dev": 0.0,
                "variance": 0.0,
                "mad": 0.0,
                "jitter": 0.0
            }

        # Calculate interval differences: delta_t_i = t_{i+1} - t_i
        intervals = [timestamps[i + 1] - timestamps[i] for i in range(total_connections - 1)]

        # Filter out negative or zero intervals if any clock glitch occurs
        intervals = [dt for dt in intervals if dt >= 0.0001]

        if not intervals or len(intervals) < 4:
            return {
                "is_beacon": False,
                "threat_score": 0.0,
                "severity": "Low",
                "reason": "Invalid or zero-interval packets",
                "connection_count": total_connections,
                "mean_interval": 0.0,
                "std_dev": 0.0,
                "variance": 0.0,
                "mad": 0.0,
                "jitter": 0.0
            }

        # 1. Mean Interval (mu)
        mean_interval = statistics.mean(intervals)

        # 2. Standard Deviation (sigma) & Variance (sigma^2)
        std_dev = statistics.stdev(intervals) if len(intervals) > 1 else 0.0
        variance = statistics.variance(intervals) if len(intervals) > 1 else 0.0

        # 3. Median Absolute Deviation (MAD)
        median_val = statistics.median(intervals)
        absolute_deviations = [abs(x - median_val) for x in intervals]
        mad = statistics.median(absolute_deviations)

        # 4. Jitter percentage: (sigma / mu) * 100
        jitter = (std_dev / mean_interval * 100.0) if mean_interval > 0 else 999.0

        # 5. Flag condition: Jitter < threshold AND requests > 5
        is_beacon = (jitter <= self.jitter_threshold) and (total_connections > 5)

        # 6. Threat Score Calculation (0.0 to 1.0)
        threat_score = self._calculate_threat_score(
            jitter=jitter,
            connection_count=total_connections,
            is_beacon=is_beacon,
            mad=mad,
            mean_interval=mean_interval
        )

        # Severity level classification
        if threat_score >= 0.70:
            severity = "High"
        elif threat_score >= 0.40:
            severity = "Medium"
        else:
            severity = "Low"

        return {
            "is_beacon": is_beacon,
            "threat_score": round(threat_score, 2),
            "severity": severity,
            "reason": "Low jitter periodic beaconing detected" if is_beacon else "Normal irregular traffic pattern",
            "connection_count": total_connections,
            "mean_interval": round(mean_interval, 3),
            "std_dev": round(std_dev, 4),
            "variance": round(variance, 4),
            "mad": round(mad, 4),
            "jitter": round(jitter, 2)
        }

    def _calculate_threat_score(self, jitter: float, connection_count: int, is_beacon: bool, mad: float, mean_interval: float) -> float:
        """
        Derives a threat score between 0.0 and 1.0 based on statistical signals.
        """
        if not is_beacon:
            # Low score for non-beacons, slight increase if jitter is close to threshold
            if jitter < self.jitter_threshold * 1.5 and connection_count > 5:
                return 0.35
            return min(0.2, jitter / 100.0)

        # Base score for satisfying beaconing criteria
        base_score = 0.60

        # Bonus for lower jitter relative to threshold (up to +0.25)
        jitter_factor = max(0.0, (self.jitter_threshold - jitter) / self.jitter_threshold) * 0.25

        # Bonus for high connection count (up to +0.15)
        count_factor = min(0.15, (connection_count / 100.0) * 0.15)

        total_score = base_score + jitter_factor + count_factor
        return min(1.0, max(0.0, total_score))
