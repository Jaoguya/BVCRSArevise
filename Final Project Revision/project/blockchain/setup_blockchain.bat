@echo off
echo.
echo ============================================================
echo   BVCRSA — Real Blockchain Setup (Ganache + Ethereum)
echo ============================================================
echo.

REM Step 1: Install Python dependencies
echo   Step 1: Installing Python packages...
pip install web3 py-solc-x
echo.

REM Step 2: Check if Node.js/npm is available
echo   Step 2: Checking Node.js...
where node >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo   WARNING: Node.js not found!
    echo   Please install Node.js from https://nodejs.org/
    echo   Then re-run this script.
    pause
    exit /b 1
)
node --version
echo.

REM Step 3: Start Ganache in a new window
echo   Step 3: Starting Ganache (local Ethereum blockchain)...
echo   A new terminal window will open with Ganache running.
echo.
start "Ganache - Local Ethereum" cmd /k "npx -y ganache --deterministic --port 8545"

REM Wait for Ganache to start
echo   Waiting for Ganache to start (5 seconds)...
timeout /t 5 /nobreak >nul
echo.

REM Step 4: Deploy the smart contract
echo   Step 4: Deploying BVCRSALedger smart contract...
python deploy_contract.py
echo.

echo ============================================================
echo   Setup complete! You can now run:
echo     python main.py
echo     python iiot_simulator.py --records 5
echo     curl http://localhost:5000/api/blockchain
echo ============================================================
pause
