@echo off
REM rebuild_archipelago.bat - Clean rebuild with Archipelago

echo ==========================================
echo Clean rebuild with Archipelago support
echo ==========================================

cd "C:\Users\Skuldier\Documents\SelacoFreshSource"

REM Clean the build directory
echo Cleaning build directory...
cd build
if exist _deps rd /s /q _deps
if exist CMakeCache.txt del CMakeCache.txt

REM Reconfigure
echo Configuring...
cmake ..\src -G "Visual Studio 17 2022" -A x64 -DENABLE_ARCHIPELAGO=ON

if %errorlevel% neq 0 (
    echo Configuration failed!
    pause
    exit /b 1
)

REM Build
echo Building...
cmake --build . --config Release

if %errorlevel% neq 0 (
    echo Build failed!
    pause
    exit /b 1
)

echo.
echo Build completed!
echo Executable: build\Release\Selaco.exe
pause
