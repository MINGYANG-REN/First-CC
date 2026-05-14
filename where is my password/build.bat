@echo off
chcp 65001 >nul
echo ========================================
echo   密码管理器 - 打包工具
echo ========================================
echo.

REM 找到 Python
set PYTHON=C:\Users\%USERNAME%\AppData\Local\Programs\Python\Python312\python.exe
if not exist "%PYTHON%" (
    set PYTHON=python
)

echo [1/2] 安装依赖...
"%PYTHON%" -m pip install cryptography pyinstaller --quiet
if %errorlevel% neq 0 (
    echo 依赖安装失败！
    pause
    exit /b 1
)

echo [2/2] 打包成 exe（可能需要几分钟）...
"%PYTHON%" -m PyInstaller --onefile --windowed --name "密码管理器" --clean "密码管理器.py"
if %errorlevel% neq 0 (
    echo 打包失败！
    pause
    exit /b 1
)

echo.
echo ========================================
echo   打包完成！
echo   exe 文件在: dist\密码管理器.exe
echo ========================================
echo.
pause
