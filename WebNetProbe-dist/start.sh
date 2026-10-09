#!/bin/bash
echo "============================================================"
echo "  WebNetProbe 内网流量探针平台 v2.0"
echo "============================================================"
echo ""
echo "[+] 正在启动服务..."
echo "[+] 服务端口: 8090"
echo ""

# 检测python
if command -v python3 &> /dev/null; then
    PYTHON=python3
else
    PYTHON=python
fi

# 自动打开浏览器
if command -v xdg-open &> /dev/null; then
    xdg-open http://localhost:8090 &
elif command -v open &> /dev/null; then
    open http://localhost:8090 &
fi

$PYTHON server.py
