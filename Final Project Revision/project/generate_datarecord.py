#!/usr/bin/env python3
"""
generate_datarecord.py
======================
Generates 100,000 simulated IIoT sensor records and saves them to Datarecord.csv.
Uses the same data schema as benchmark_paper.py gen_data().

Record schema: id, machine, sensor, value, timestamp_str, t_slot
"""

import os, random, csv, time
# numpy not needed for data generation — uses only stdlib random
from datetime import datetime, timedelta

TOTAL_RECORDS = 100_000
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_FILE = os.path.join(BASE_DIR, "Datarecord.csv")

KEYWORD_POOL = [
    "Temp", "Humidity", "Pressure", "Vibration", "Voltage",
    "Current", "Power", "Flow", "Level", "Speed",
    "Torque", "RPM", "Weight", "Density", "pH"
]
MACHINES = ["A", "B", "C"]


def gen_data(n, seed=42):
    """Generate n IIoT records. Matches benchmark_paper.py gen_data() schema."""
    random.seed(seed)
    # deterministic with stdlib random.seed only
    base = datetime(2024, 1, 1, 0, 0, 0)
    recs = []
    for i in range(n):
        m = random.choice(MACHINES)
        k = random.choice(KEYWORD_POOL)
        v = random.randint(0, 100)
        t_obj = base + timedelta(seconds=i * 3.6)   # spread evenly
        recs.append({
            "id":            i,
            "machine":       m,
            "sensor":        k,
            "value":         v,
            "timestamp_str": t_obj.strftime("%Y-%m-%d %H:%M:%S"),
            "t_slot":        t_obj.strftime("%Y-%m-%d %H"),
        })
    return recs


def main():
    print("=" * 60)
    print("  Datarecord.csv Generator")
    print(f"  Target: {TOTAL_RECORDS:,} records")
    print(f"  Output: {OUTPUT_FILE}")
    print("=" * 60)

    t_start = time.perf_counter()
    print(f"\n[1/2] Generating {TOTAL_RECORDS:,} records (seed=42)...", flush=True)
    records = gen_data(TOTAL_RECORDS)
    gen_time = time.perf_counter() - t_start
    print(f"      Done in {gen_time:.2f}s  ({TOTAL_RECORDS/gen_time:,.0f} rec/s)")

    print(f"\n[2/2] Writing to CSV...", flush=True)
    t_write = time.perf_counter()
    fieldnames = ["id", "machine", "sensor", "value", "timestamp_str", "t_slot"]
    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(records)
    write_time = time.perf_counter() - t_write
    print(f"      Done in {write_time:.2f}s")

    size_mb = os.path.getsize(OUTPUT_FILE) / (1024 * 1024)
    total_time = time.perf_counter() - t_start

    print(f"\n{'='*60}")
    print(f"  ✅ Datarecord.csv generated successfully!")
    print(f"     Rows:       {TOTAL_RECORDS:,}")
    print(f"     File size:  {size_mb:.2f} MB")
    print(f"     Path:       {OUTPUT_FILE}")
    print(f"     Total time: {total_time:.2f}s")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
