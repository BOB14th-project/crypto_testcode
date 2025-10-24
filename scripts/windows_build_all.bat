@echo off
setlocal enabledelayedexpansion

set ROOT_DIR=%~dp0..
set BUILD_DIR=%ROOT_DIR%\build\cmake
set BUILD_TYPE=%1
if "%BUILD_TYPE%"=="" set BUILD_TYPE=Release

echo [CMake] Generating build files (config: %BUILD_TYPE%)
cmake -S "%ROOT_DIR%" -B "%BUILD_DIR%" -DCMAKE_BUILD_TYPE=%BUILD_TYPE%
if errorlevel 1 goto :error

echo [CMake] Building targets
cmake --build "%BUILD_DIR%" --config %BUILD_TYPE%
if errorlevel 1 goto :error

echo [Java] Compiling sources
call "%ROOT_DIR%\scripts\windows_build_java.bat"
if errorlevel 1 goto :error

echo.
echo Build completed (config: %BUILD_TYPE%). Binaries under %ROOT_DIR%\build\bin
exit /b 0

:error
echo Build failed.
exit /b 1
