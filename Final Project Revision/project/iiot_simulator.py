#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════════════
  IIoT Data Simulator — Simulated Industrial IoT Sensor Data
═══════════════════════════════════════════════════════════════════════

Purpose:
  Generate realistic IIoT sensor data for TESTING the Trinity algorithm.
  This is the ONLY simulated component — all cryptographic operations
  in the Trinity implementation use real primitives.

Data Model (per IIoT record):
  - device_id:    Unique sensor identifier
  - latitude:     GPS latitude of the sensor (float)
  - longitude:    GPS longitude of the sensor (float)
  - timestamp:    Unix timestamp of measurement (int)
  - temperature:  Sensor reading — temperature (float)
  - humidity:     Sensor reading — humidity (float)
  - pressure:     Sensor reading — barometric pressure (float)
  - keywords:     List of keyword tags (e.g., "factory_A", "line_3")

Scenarios:
  1. Smart Factory:  Sensors on assembly lines
  2. Smart Grid:     Power distribution sensors
  3. Environmental:  Environmental monitoring stations
"""
import random
import time
import math


class IIoTSimulator:
    """
    Generate realistic IIoT sensor data for testing Trinity.
    """

    def __init__(self, scenario='factory', seed=42):
        """
        Args:
            scenario: 'factory', 'grid', or 'environmental'
            seed: Random seed for reproducibility
        """
        random.seed(seed)
        self.scenario = scenario
        self._configure_scenario()

    def _configure_scenario(self):
        """Configure parameters based on scenario."""
        if self.scenario == 'factory':
            # Smart factory in industrial zone
            self.lat_center = 13.7563     # Bangkok latitude
            self.lon_center = 100.5018    # Bangkok longitude
            self.lat_spread = 0.05        # ~5 km spread
            self.lon_spread = 0.05
            self.num_devices = 50
            self.keywords_pool = [
                'factory_A', 'factory_B', 'factory_C',
                'line_1', 'line_2', 'line_3', 'line_4',
                'zone_assembly', 'zone_welding', 'zone_paint',
                'zone_quality', 'zone_warehouse',
                'sensor_temp', 'sensor_humid', 'sensor_press',
                'sensor_vibration', 'sensor_power',
                'priority_high', 'priority_medium', 'priority_low',
                'shift_morning', 'shift_afternoon', 'shift_night',
            ]
            self.temp_range = (18.0, 85.0)    # Factory can be hot
            self.humid_range = (20.0, 90.0)
            self.press_range = (990.0, 1030.0)

        elif self.scenario == 'grid':
            # Smart grid across city
            self.lat_center = 13.7563
            self.lon_center = 100.5018
            self.lat_spread = 0.2         # Wider spread
            self.lon_spread = 0.2
            self.num_devices = 100
            self.keywords_pool = [
                'substation_north', 'substation_south',
                'substation_east', 'substation_west', 'substation_central',
                'transformer_A', 'transformer_B', 'transformer_C',
                'feeder_main', 'feeder_backup',
                'voltage_high', 'voltage_medium', 'voltage_low',
                'phase_A', 'phase_B', 'phase_C',
                'load_peak', 'load_normal', 'load_off_peak',
                'meter_smart', 'meter_legacy',
            ]
            self.temp_range = (25.0, 120.0)   # Transformer temps
            self.humid_range = (30.0, 85.0)
            self.press_range = (985.0, 1025.0)

        else:  # environmental
            self.lat_center = 13.7563
            self.lon_center = 100.5018
            self.lat_spread = 0.5
            self.lon_spread = 0.5
            self.num_devices = 30
            self.keywords_pool = [
                'station_urban', 'station_suburban', 'station_industrial',
                'station_riverside', 'station_highway',
                'pollutant_pm25', 'pollutant_pm10', 'pollutant_co2',
                'pollutant_no2', 'pollutant_so2', 'pollutant_o3',
                'quality_good', 'quality_moderate', 'quality_poor',
                'wind_north', 'wind_south', 'wind_calm',
                'rain_none', 'rain_light', 'rain_heavy',
            ]
            self.temp_range = (22.0, 42.0)
            self.humid_range = (40.0, 98.0)
            self.press_range = (1000.0, 1020.0)

        # Pre-generate device locations (fixed per device)
        self.devices = []
        for i in range(self.num_devices):
            self.devices.append({
                'device_id': f"DEV-{self.scenario[:3].upper()}-{i:04d}",
                'base_lat': self.lat_center + random.uniform(
                    -self.lat_spread, self.lat_spread
                ),
                'base_lon': self.lon_center + random.uniform(
                    -self.lon_spread, self.lon_spread
                ),
                'keywords': random.sample(
                    self.keywords_pool,
                    k=random.randint(3, 8)
                ),
            })

    def generate_records(self, n, time_start=None, time_span_hours=24):
        """
        Generate n IIoT sensor records.

        Args:
            n: Number of records to generate.
            time_start: Start timestamp (default: current time - time_span).
            time_span_hours: Time range in hours.

        Returns:
            List of record dicts, each containing:
              - device_id, latitude, longitude, timestamp
              - temperature, humidity, pressure
              - keywords (list of string tags)
        """
        if time_start is None:
            time_start = int(time.time()) - int(time_span_hours * 3600)

        time_end = time_start + int(time_span_hours * 3600)

        records = []
        for i in range(n):
            # Pick a random device
            device = random.choice(self.devices)

            # Slightly jitter location (GPS noise)
            lat = device['base_lat'] + random.gauss(0, 0.001)
            lon = device['base_lon'] + random.gauss(0, 0.001)

            # Random timestamp in range
            ts = random.randint(time_start, time_end)

            # Sensor readings with realistic noise
            hour = (ts % 86400) / 3600.0  # Hour of day
            temp_base = (
                self.temp_range[0] +
                (self.temp_range[1] - self.temp_range[0]) *
                (0.3 + 0.4 * math.sin(hour / 24.0 * 2 * math.pi - math.pi / 2))
            )
            temperature = temp_base + random.gauss(0, 2.0)

            humidity = random.uniform(*self.humid_range)
            pressure = random.uniform(*self.press_range)

            records.append({
                'record_id': i,
                'device_id': device['device_id'],
                'latitude': round(lat, 6),
                'longitude': round(lon, 6),
                'timestamp': ts,
                'temperature': round(temperature, 2),
                'humidity': round(humidity, 2),
                'pressure': round(pressure, 2),
                'keywords': device['keywords'],
            })

        return records

    def generate_range_query(self, records=None):
        """
        Generate a realistic spatio-temporal range query.

        Returns:
            Dict with lat_range, lon_range, time_range, keywords.
        """
        # Select a subset of the area
        lat_lo = self.lat_center + random.uniform(
            -self.lat_spread * 0.8, self.lat_spread * 0.3
        )
        lat_hi = lat_lo + random.uniform(0.01, self.lat_spread * 0.5)

        lon_lo = self.lon_center + random.uniform(
            -self.lon_spread * 0.8, self.lon_spread * 0.3
        )
        lon_hi = lon_lo + random.uniform(0.01, self.lon_spread * 0.5)

        # Time range: random window within the data
        base_time = int(time.time()) - random.randint(0, 86400)
        time_lo = base_time
        time_hi = base_time + random.randint(3600, 14400)  # 1-4 hours

        # Select some keywords
        query_keywords = random.sample(
            self.keywords_pool,
            k=random.randint(1, 4)
        )

        return {
            'lat_range': (round(lat_lo, 6), round(lat_hi, 6)),
            'lon_range': (round(lon_lo, 6), round(lon_hi, 6)),
            'time_range': (time_lo, time_hi),
            'keywords': query_keywords,
        }


# ═══════════════════════════════════════════════════════════════
#  Standalone test
# ═══════════════════════════════════════════════════════════════
if __name__ == '__main__':
    print("═══ IIoT Data Simulator Test ═══\n")

    for scenario in ['factory', 'grid', 'environmental']:
        sim = IIoTSimulator(scenario=scenario)
        records = sim.generate_records(5)
        print(f"  [{scenario}] Generated {len(records)} records:")
        for r in records:
            print(f"    {r['device_id']} | "
                  f"({r['latitude']:.4f}, {r['longitude']:.4f}) | "
                  f"T={r['temperature']:.1f}°C | "
                  f"kw={r['keywords'][:3]}")

        query = sim.generate_range_query()
        print(f"    Query: lat={query['lat_range']}, "
              f"lon={query['lon_range']}, kw={query['keywords']}\n")
