═══════════════════════════════════════════════════════════════════
  AC-SCRAT — How to Run & Test
  Blockchain Edge Node + ABSE Access Control
═══════════════════════════════════════════════════════════════════

PREREQUISITES
─────────────
  • Python 3.10+
  • pip install flask pymongo[srv] dnspython pycryptodome requests phe


═══════════════════════════════════════════════════════════════════
  1. START THE SERVER
═══════════════════════════════════════════════════════════════════

  cd project
  python3 main.py

  Server runs at http://localhost:5000


═══════════════════════════════════════════════════════════════════
  2. INGEST DATA (IIoT Sensor Simulator)
═══════════════════════════════════════════════════════════════════

  python3 iiot_simulator.py

  Options:
    python3 iiot_simulator.py --records 200
    python3 iiot_simulator.py --machine Machine_A --keyword temperature
    python3 iiot_simulator.py --burst 10 --interval 0.5


═══════════════════════════════════════════════════════════════════
  3. CHECK BLOCKCHAIN STATUS
═══════════════════════════════════════════════════════════════════

  curl http://localhost:5000/api/blockchain


═══════════════════════════════════════════════════════════════════
  4. RESET DATA
═══════════════════════════════════════════════════════════════════

  curl -X POST http://localhost:5000/reset


═══════════════════════════════════════════════════════════════════
  FULL TEST (step by step)
═══════════════════════════════════════════════════════════════════

  Terminal 1:   python3 main.py
  Terminal 2:   python3 iiot_simulator.py --records 200


═══════════════════════════════════════════════════════════════════
  TROUBLESHOOTING
═══════════════════════════════════════════════════════════════════

  Port in use:        fuser -k 5000/tcp
  Module not found:   Run from project/ directory
  Slow ingestion:     Normal (~90s for 200 records, ABSE+blockchain)
