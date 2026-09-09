#!/bin/bash

echo "========================================"
echo "  Cyber Threat Monitoring System"
echo "  Starting All Components..."
echo "========================================"
echo ""

# Go to project folder
cd ~/projects/behavioral-cyber-platform

# 1. Start Docker backend (if not running)
echo "[1/5] Checking Docker backend..."
if ! docker ps | grep -q sentinel-backend; then
    echo "Starting Docker containers..."
    docker-compose up -d
    sleep 5
else
    echo "✓ Docker backend already running"
fi

# Wait for backend to be ready
echo "Waiting for backend to be ready..."
sleep 3

# 2. Activate venv
source venv/bin/activate

# 3. Start Network Monitor
echo "[2/5] Starting Network Monitor..."
python3 agents/network_monitor.py &
sleep 2

# 4. Start File Monitor
echo "[3/5] Starting File Monitor..."
python3 agents/file_monitor.py &
sleep 2

# 5. Start Dashboard
echo "[4/5] Starting Dashboard..."
cd dashboard
streamlit run app.py --server.port 8501 --server.address 0.0.0.0 &
sleep 3

# 6. Open browser
echo "[5/5] Opening dashboard in browser..."
sleep 2
xdg-open http://localhost:8501 2>/dev/null || echo "Dashboard: http://localhost:8501"

echo ""
echo "========================================"
echo "  ✅ All Components Started!"
echo "========================================"
echo ""
echo "  Dashboard: http://localhost:8501"
echo "  Backend:   http://localhost:18000"
echo "  Network Monitor: Running"
echo "  File Monitor: Running"
echo ""
echo "  Browser Extension:"
echo "  1. Open Edge"
echo "  2. Go to: edge://extensions"
echo "  3. Enable 'Developer Mode'"
echo "  4. Click 'Load unpacked'"
echo "  5. Select: ~/projects/behavioral-cyber-platform/extension"
echo ""
echo "  Press Ctrl+C to stop all services"
echo "========================================"

# Keep running
wait
