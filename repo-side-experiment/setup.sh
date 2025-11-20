#!/bin/bash
# Setup script for Sigstore + KAM experiment

set -e

echo "🔧 Setting up Sigstore + KAM Supply Chain Security Experiment"
echo "============================================================="

echo "📋 Checking prerequisites..."
if ! command -v docker &> /dev/null; then
    echo "❌ Docker not found. Please install Docker first."
    exit 1
fi
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose not found. Please install Docker Compose first."
    exit 1
fi
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 not found. Please install Python 3.8+ first."
    exit 1
fi
echo "✅ Prerequisites check passed"

echo "📦 Installing Python dependencies..."
pip3 install -r requirements.txt

if command -v cosign &> /dev/null; then
    echo "✅ Cosign found: $(cosign version --short 2>/dev/null || echo 'unknown')"
else
    echo "⚠️  Cosign not found - using simulation mode"
    echo "   For full functionality, install cosign: https://docs.sigstore.dev/cosign/installation/"
fi

echo "📁 Creating directories..."
mkdir -p data/rekor
mkdir -p data/verdaccio/storage
mkdir -p data/kam
mkdir -p logs
mkdir -p results

chmod 755 data/rekor data/verdaccio/storage data/kam logs results

echo "🚀 Starting services..."
docker-compose up -d

echo "⏳ Waiting for services to start..."
sleep 10

echo "🔍 Checking service health..."
if curl -f -s http://localhost:3000/api/v1/log > /dev/null; then
    echo "✅ Rekor server is healthy"
else
    echo "⚠️  Rekor server not responding"
fi
if curl -f -s http://localhost:4873/-/ping > /dev/null; then
    echo "✅ Verdaccio registry is healthy"
else
    echo "⚠️  Verdaccio registry not responding"
fi
if curl -f -s http://localhost:8000/all > /dev/null; then
    echo "✅ KAM service is healthy"
else
    echo "⚠️  KAM service not responding"
fi

echo "🔑 Initializing KAM with test authorization..."
python3 -c "
from kam_client import KAMService
import time
try:
    kam = KAMService()
    result = kam.authorize_key('example_package', 'publisher@example.com', 7200)
    print('✅ KAM initialized successfully')
    print(f'   Authorized: publisher@example.com for example_package')
except Exception as e:
    print(f'⚠️  KAM initialization failed: {e}')
"

echo "🎉 Setup complete!"

echo ""
echo "Quick Start:"
echo "  • Run single trial:    python3 run_trial.py --config defense --trials 5"
echo "  • Run full experiment: python3 run_trial.py --trials 10"
echo "  • View logs:           docker-compose logs -f"
echo "  • Stop services:       docker-compose down"
echo ""
echo "Services running at:"
echo "  • Rekor:     http://localhost:3000"
echo "  • Verdaccio: http://localhost:4873"
echo "  • KAM:       http://localhost:8000"
echo ""
echo "For detailed instructions, see: experiment_documentation.md"
