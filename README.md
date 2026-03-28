# Brute-Force-Detection-with-Threshold-and-Time-Window
Brute Force Detection with Threshold and Time Window

This Python tool detects brute-force login attempts by checking:

- A threshold of failed login attempts
- A time window in which those attempts happen

If 5 or more failed login attempts occur within 2 minutes for the same IP or username, an alert is generated.

## Run

```bash
python bruteforce_detector.py
```