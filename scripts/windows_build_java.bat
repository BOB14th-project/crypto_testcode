@echo off
setlocal enabledelayedexpansion

set ROOT_DIR=%~dp0..
set OUTPUT_DIR=%ROOT_DIR%\build\java

if not exist "%OUTPUT_DIR%" (
    mkdir "%OUTPUT_DIR%"
)

for /f "delims=" %%i in ('dir /b /s "%ROOT_DIR%\tests\*.java"') do (
    set SOURCES=!SOURCES! "%%i"
)

if "%SOURCES%"=="" (
    echo No Java sources found under tests/.
    exit /b 0
)

echo Compiling Java sources...
javac -d "%OUTPUT_DIR%" %SOURCES%
if errorlevel 1 goto :error
echo Java classes written to %OUTPUT_DIR%
exit /b 0

:error
echo Java compilation failed.
exit /b 1
