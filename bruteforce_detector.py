import json
from collections import defaultdict, deque
from datetime import datetime


class BruteForceDetector:
    def __init__(self, threshold=5, window_minutes=2, track_by="ip"):
        """
        threshold: number of failed attempts required
        window_minutes: time window in minutes
        track_by: "ip" or "username"
        """
        self.threshold = threshold
        self.window_seconds = window_minutes * 60
        self.track_by = track_by
        self.failed_attempts = defaultdict(deque)

    def process_event(self, event):
        """
        Process one login event and return an alert if brute force is detected.
        Expected event format:
        {
            "timestamp": "2026-03-28T10:01:00",
            "username": "ali",
            "ip": "192.168.1.100",
            "status": "failed"
        }
        """
        if event.get("status") != "failed":
            return None

        key = event.get(self.track_by)
        timestamp = event.get("timestamp")

        if not key or not timestamp:
            return None

        try:
            current_time = datetime.fromisoformat(timestamp)
        except ValueError:
            return None

        attempts = self.failed_attempts[key]
        attempts.append(current_time)

        while attempts and (current_time - attempts[0]).total_seconds() > self.window_seconds:
            attempts.popleft()

        if len(attempts) >= self.threshold:
            return {
                "alert": "Brute force detected",
                "track_by": self.track_by,
                "value": key,
                "failed_attempts": len(attempts),
                "threshold": self.threshold,
                "time_window_seconds": self.window_seconds,
                "timestamp": timestamp,
                "severity": "high"
            }

        return None


def load_logs(file_path):
    with open(file_path, "r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                print(f"[WARNING] Invalid JSON on line {line_number}")


def main():
    log_file = "sample_logs.jsonl"

    detector_by_ip = BruteForceDetector(threshold=5, window_minutes=2, track_by="ip")
    detector_by_user = BruteForceDetector(threshold=5, window_minutes=2, track_by="username")

    alerts = []

    for event in load_logs(log_file):
        ip_alert = detector_by_ip.process_event(event)
        if ip_alert:
            alerts.append(ip_alert)

        user_alert = detector_by_user.process_event(event)
        if user_alert:
            alerts.append(user_alert)

    print("\n=== BRUTE FORCE ALERTS ===\n")
    if not alerts:
        print("No brute force activity detected.")
        return

    for alert in alerts:
        print(json.dumps(alert, indent=4))


if __name__ == "__main__":
    main()