@echo off
REM Build DARKWATCH (single file). Works with old and new MinGW gcc, or MSVC Developer Command Prompt.
where gcc >nul 2>nul
if %errorlevel%==0 (
  gcc -std=gnu99 -Wall -O2 -o darkwatch.exe darkwatch.c -lws2_32
  goto done
)
where cl >nul 2>nul
if %errorlevel%==0 (
  cl /nologo /O2 /W3 /Fe:darkwatch.exe darkwatch.c ws2_32.lib
  goto done
)
echo No compiler found. Install MinGW-w64 (gcc) or Visual Studio Build Tools.
:done
