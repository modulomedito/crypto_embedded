@echo off
rem Build and run tests in debug mode
rem Reconfigure only if no .xmake dir exists or mode changed
if not exist .xmake\xmake.lua (
    xmake f -p mingw -m debug
)
xmake build testsuite
if %ERRORLEVEL% neq 0 exit /b %ERRORLEVEL%
xmake run testsuite
