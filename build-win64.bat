@echo off
setlocal

REM === Configuration ===
set QT_PATH=C:\Qt\6.9.1\msvc2022_64
set BUILD_TYPE=Release
set BUILD_DIR=build

REM Optional: clear previous build
if exist %BUILD_DIR% (
    echo Removing old build directory...
    rmdir /s /q %BUILD_DIR%
)

REM Run Visual Studio 2022 compiler
CALL "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat"

REM Create build directory
mkdir %BUILD_DIR%
cd %BUILD_DIR%

REM === Set CMAKE_PREFIX_PATH environment variable ===
set CMAKE_PREFIX_PATH=%QT_PATH%

REM === Run CMake configure/generate ===
echo Running CMake configuration...
cmake -G "NMake Makefiles" ^
    -DCMAKE_BUILD_TYPE=%BUILD_TYPE% ^
    ..

if ERRORLEVEL 1 (
    echo CMake configuration failed.
    pause
    exit /b 1
)

REM === Build the project ===
echo Building project with nmake...
nmake

if ERRORLEVEL 1 (
    echo Build failed.
    pause
    exit /b 1
)

echo Build complete.
pause