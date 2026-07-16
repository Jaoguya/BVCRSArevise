"""
Generate spatial data and insert into MongoDB.
Based on: ECGRQ-LI paper (Geolife GPS / GeoNames style datasets)
"""
import numpy as np
import hashlib
import hmac
import time
import os
import sys
from pymongo import MongoClient, ASCENDING
from config import *


# ─── Z-order curve encoding ───
def interleave_bits(x, y, bits=Z_BITS):
    z = 0
    for i in range(bits):
        z |= ((x >> i) & 1) << (2 * i + 1)
        z |= ((y >> i) & 1) << (2 * i)
    return z

def lat_lon_to_grid(lat, lon, bits=Z_BITS):
    max_val = (1 << bits) - 1
    gx = int((lat - LAT_MIN) / (LAT_MAX - LAT_MIN) * max_val)
    gy = int((lon - LON_MIN) / (LON_MAX - LON_MIN) * max_val)
    return max(0, min(max_val, gx)), max(0, min(max_val, gy))

def compute_z_code(lat, lon):
    gx, gy = lat_lon_to_grid(lat, lon)
    return interleave_bits(gx, gy)

# ─── Pseudorandom function (PRF) for encryption ───
def prf_encrypt(key: bytes, z_code: int) -> int:
    h = hmac.new(key, z_code.to_bytes(8, 'big'), hashlib.sha256).digest()
    return int.from_bytes(h[:8], 'big')

# ─── Generate synthetic spatial dataset ───
def generate_geolife_style(m, seed=42):
    """Generate m points clustered around Beijing (similar to Geolife GPS)."""
    rng = np.random.RandomState(seed)
    centers = [(39.9, 116.3), (40.0, 116.4), (39.8, 116.5),
               (40.1, 116.2), (39.95, 116.35)]
    labels = rng.randint(0, len(centers), m)
    lats = np.array([centers[l][0] for l in labels]) + rng.normal(0, 0.15, m)
    lons = np.array([centers[l][1] for l in labels]) + rng.normal(0, 0.2, m)
    lats = np.clip(lats, LAT_MIN, LAT_MAX)
    lons = np.clip(lons, LON_MIN, LON_MAX)
    return lats, lons

def generate_geonames_style(m, seed=123):
    """Generate m points spread globally (similar to GeoNames)."""
    rng = np.random.RandomState(seed)
    lats = LAT_MIN + rng.random(m) * (LAT_MAX - LAT_MIN)
    lons = LON_MIN + rng.random(m) * (LON_MAX - LON_MIN)
    return lats, lons

def generate_attributes(m, s=NUM_ATTRS, seed=42):
    """Generate s random attributes per point (simulating Enron keywords)."""
    rng = np.random.RandomState(seed)
    keywords = [f"attr_{i}" for i in range(20)]
    attrs = []
    for _ in range(m):
        chosen = rng.choice(keywords, size=s, replace=False).tolist()
        attrs.append(chosen)
    return attrs

# ─── Insert into MongoDB ───
def insert_dataset(db, dataset_name, m, style="geolife"):
    col = db[COL_SPATIAL]
    col.drop()

    print(f"[*] Generating {m:,} points ({style} style)...")
    if style == "geolife":
        lats, lons = generate_geolife_style(m)
    else:
        lats, lons = generate_geonames_style(m)

    attrs = generate_attributes(m)
    key = os.urandom(32)

    docs = []
    for i in range(m):
        z = compute_z_code(lats[i], lons[i])
        enc_z = prf_encrypt(key, z)
        docs.append({
            "dataset": dataset_name,
            "point_id": i,
            "latitude": float(lats[i]),
            "longitude": float(lons[i]),
            "z_code": z,
            "encrypted_z_code": enc_z,
            "attributes": attrs[i],
            "grid_x": int(lat_lon_to_grid(lats[i], lons[i])[0]),
            "grid_y": int(lat_lon_to_grid(lats[i], lons[i])[1]),
        })
        if len(docs) >= 10000:
            col.insert_many(docs)
            docs = []
            print(f"  Inserted {i+1:,}/{m:,}...", end="\r")

    if docs:
        col.insert_many(docs)
    print(f"\n[+] Inserted {m:,} points into '{COL_SPATIAL}'")

    col.create_index([("z_code", ASCENDING)])
    col.create_index([("encrypted_z_code", ASCENDING)])
    col.create_index([("dataset", ASCENDING)])

    # Store the key in models collection
    db[COL_MODELS].update_one(
        {"dataset": dataset_name},
        {"$set": {"prf_key": key.hex(), "size": m, "style": style}},
        upsert=True
    )
    return key


def main():
    if "<db_password>" in MONGO_URI:
        print("ERROR: Please set your MongoDB password in config.py (replace <db_password>)")
        sys.exit(1)

    client = MongoClient(MONGO_URI)
    db = client[DB_NAME]

    # Test connection
    try:
        client.admin.command("ping")
        print("[+] Connected to MongoDB Atlas successfully!")
    except Exception as e:
        print(f"[-] Connection failed: {e}")
        sys.exit(1)

    # Generate datasets of varying sizes for experiments
    sizes_to_gen = [200_000]  # Start small; change to DATASET_SIZES for full test
    for m in sizes_to_gen:
        insert_dataset(db, f"geolife_{m}", m, "geolife")
        insert_dataset(db, f"geonames_{m}", m, "geonames")

    print("\n[+] Data generation complete!")
    print(f"    Database: {DB_NAME}")
    print(f"    Collections: {db.list_collection_names()}")

    client.close()


if __name__ == "__main__":
    main()
