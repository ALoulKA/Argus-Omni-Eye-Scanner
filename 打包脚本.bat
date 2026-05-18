@echo off
chcp 65001 >nul 2>&1
echo ========================================
echo   Argus · 明日之眼 - 一键打包脚本
echo ========================================
echo.

cd /d "%~dp0"

echo [1/2] 清理旧构建...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
if exist *.spec del /q *.spec

echo [2/2] 开始打包...
python -m PyInstaller --noconfirm --onefile --windowed ^
  --icon=logo.ico ^
  --add-data "logo.ico;." ^
  --add-data "wordlists;wordlists" ^
  --exclude-module matplotlib ^
  --exclude-module IPython ^
  --exclude-module jedi ^
  --exclude-module parso ^
  --exclude-module pygments ^
  --exclude-module rich ^
  --exclude-module numpy ^
  --exclude-module PIL ^
  --exclude-module scipy ^
  --exclude-module lxml ^
  --exclude-module cryptography ^
  --name "Argus · 明日之眼" ^
  wildcard_gui.py

if %errorlevel% neq 0 (
    echo.
    echo [错误] 打包失败！
    pause
    exit /b 1
)

echo.
echo ========================================
echo   打包完成！
echo   输出: dist\Argus · 明日之眼.exe
echo ========================================
echo.
echo 清理构建文件...
rmdir /s /q build
del /q *.spec

pause