@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo ============================================
echo  WebNetProbe 数据库回滚
echo  用法1: 双击本文件查看镜像列表
echo  用法2: 命令行执行 rollback.bat 序号
echo ============================================
python rollback.py %*
echo.
pause
