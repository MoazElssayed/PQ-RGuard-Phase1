#!/bin/bash

set -e

echo "          PQ-RGuard+ Phase 1 - Complete Setup                "
echo ""

# Check if running on Raspberry Pi
if ! grep -q "Raspberry Pi" /proc/cpuinfo 2>/dev/null; then
    echo "⚠️  Warning: Not running on Raspberry Pi"
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Update system
echo "📦 Updating system packages..."
sudo apt update
sudo apt upgrade -y

# Install dependencies
echo "📦 Installing dependencies..."
sudo apt install -y \
    build-essential cmake git \
    libssl-dev pkg-config ninja-build \
    mosquitto mosquitto-clients \
    astyle uncrustify \
    python3 python3-pip

echo "✓ Dependencies installed"

# Install liboqs with optimizations
echo "🔐 Building optimized liboqs..."
cd /tmp
rm -rf liboqs
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build

cmake -DCMAKE_BUILD_TYPE=Release \
      -DOQS_ENABLE_KEM_kyber_512=ON \
      -DCMAKE_C_FLAGS="-O3 -march=native -mtune=native -flto -ffast-math" \
      ..

make -j$(nproc)
sudo make install
sudo ldconfig

echo "✓ liboqs installed"

# Verify liboqs
echo "🔍 Verifying liboqs installation..."
pkg-config --modversion liboqs

# Build PQ-RGuard+
echo "🔨 Building PQ-RGuard+..."
cd "$(dirname "$0")/../.."
cd src
make clean && make all

echo "✓ Build complete"

# Start Mosquitto
echo "🦟 Configuring Mosquitto..."
sudo systemctl enable mosquitto
sudo systemctl start mosquitto

echo "                   ✅ Setup Complete!                         "
echo ""
echo "Next steps:"
echo "  1. Run broker:  ./scripts/test/run-broker.sh"
echo "  2. Run client:  ./scripts/test/run-client.sh <broker_ip>"
echo "  3. Run benchmarks: cd benchmarks && ./run-all-benchmarks.sh"
echo ""
