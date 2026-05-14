#!/bin/bash
# AI Agent Risk Evaluator - Start Script
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "🛡️  AI Agent 风险评估平台"
echo "================================"

# Check Python
if ! command -v python3 &>/dev/null; then
  echo "❌ 需要 Python 3.10+"
  exit 1
fi

# Install deps if needed
if ! python3 -c "import fastapi, uvicorn, httpx" &>/dev/null 2>&1; then
  echo "📦 安装依赖..."
  pip3 install -r requirements.txt -q
fi

PORT=${PORT:-9999}
echo "🚀 启动服务: http://localhost:$PORT"
echo "   按 Ctrl+C 停止"
echo ""

python3 -m uvicorn main:app --host 127.0.0.1 --port "$PORT" --reload
