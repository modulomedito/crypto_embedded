@echo off
rem Build and run tests in debug mode (MSYS2 MinGW)
xmake f -p mingw --mingw=C:/msys64/mingw64 -m debug -c
xmake build testsuite
if %ERRORLEVEL% neq 0 exit /b %ERRORLEVEL%
xmake run testsuite
