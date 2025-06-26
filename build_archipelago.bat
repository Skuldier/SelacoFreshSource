@echo off
REM build_archipelago.bat - Build Selaco with Archipelago support

echo ========================================
echo Building Selaco with Archipelago Support
echo ========================================
echo.

REM Check if we're in the right directory
if not exist "src\CMakeLists.txt" (
    echo ERROR: src\CMakeLists.txt not found!
    echo Please run this script from the Selaco root directory.
    pause
    exit /b 1
)

REM Create build directory
if not exist "build-archipelago" mkdir build-archipelago
cd build-archipelago

REM Configure with CMake
echo Configuring with CMake...
cmake -G "Visual Studio 17 2022" -A x64 ^
    -DENABLE_ARCHIPELAGO=ON ^
    -DCMAKE_BUILD_TYPE=Release ^
    ..\src

if %errorlevel% neq 0 (
    echo.
    echo ERROR: CMake configuration failed!
    pause
    exit /b 1
)

REM Build
echo.
echo Building Selaco...
cmake --build . --config Release --parallel

if %errorlevel% neq 0 (
    echo.
    echo ERROR: Build failed!
    pause
    exit /b 1
)

echo.
echo ========================================
echo Build completed successfully!
echo ========================================
echo.
echo Executable location: build-archipelago\Release\zdoom.exe
echo.
echo To test Archipelago support:
echo 1. Run zdoom.exe
echo 2. Open console with ~ key
echo 3. Type: ap_connect archipelago.gg
echo 4. Type: ap_auth YourSlotName
echo.
pause
