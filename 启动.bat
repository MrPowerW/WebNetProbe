@echo off
chcp 65001 >nul
echo ============================================================
echo   WebNetProbe 内网流量探针平台 v2.0
echo ============================================================
echo.
echo [+] 正在启动服务...
echo [+] 请不要关闭此窗口
echo.
start http://localhost:8090
python server.py
pause
