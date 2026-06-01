#!/bin/bash
# deploy.sh — 一键更新并重启 AI Agent Risk Evaluation 服务
# 用法：bash deploy.sh

set -e
APP_DIR="$(cd "$(dirname "$0")" && pwd)"
PORT=9999
LOG=/tmp/uvicorn.log

echo "===> 拉取最新代码..."
cd "$APP_DIR"
git pull origin main

echo "===> 安装/更新依赖..."
# Use a virtual environment to avoid externally-managed-environment errors on Debian/Ubuntu
if [ ! -d ".venv" ]; then
    python3 -m venv .venv
fi
.venv/bin/pip install -q -r requirements.txt

echo "===> 停止旧进程..."
OLD_PID=$(ss -tlnp 2>/dev/null | grep ":$PORT " | grep -oP 'pid=\K[0-9]+' | head -1)
if [ -n "$OLD_PID" ]; then
    kill "$OLD_PID" && echo "    已停止 PID $OLD_PID"
    sleep 2
else
    echo "    没有运行中的旧进程"
fi

echo "===> 启动新服务..."
nohup .venv/bin/python -m uvicorn main:app --host 0.0.0.0 --port $PORT > "$LOG" 2>&1 &
sleep 3

echo "===> 验证服务..."
STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:$PORT/api/health)
if [ "$STATUS" = "200" ]; then
    echo "✅ 部署成功，服务运行在端口 $PORT"
else
    echo "❌ 启动失败，查看日志："
    tail -20 "$LOG"
    exit 1
fi
