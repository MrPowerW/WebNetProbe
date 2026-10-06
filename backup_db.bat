@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo ============================================
echo  WebNetProbe 数据库备份（回滚镜像）
echo ============================================
python backup_db.py %*
echo.
pause
