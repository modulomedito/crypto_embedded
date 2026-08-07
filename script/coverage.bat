@echo off
cd /d "%~dp0.."
echo === Building with MSYS2 GCC 15 ===
xmake f -p mingw --mingw=C:/msys64/mingw64 -m coverage -c
rem force clean rebuild to avoid stale cached .o files
rmdir /s /q build 2>nul
xmake build testsuite
if %ERRORLEVEL% neq 0 exit /b %ERRORLEVEL%

echo === Running tests ===
xmake run testsuite
if %ERRORLEVEL% neq 0 exit /b %ERRORLEVEL%

echo === Generating coverage reports ===
gcovr --gcov-executable C:/msys64/mingw64/bin/gcov.exe ^
  --gcov-ignore-errors no_working_dir_found ^
  -r . --html-details docs/coverage/index.html --txt docs/coverage/summary.txt ^
  --decisions ^
  --filter "crypto_embedded/*" ^
  --exclude "test/*" ^
  --fail-under-line 100 --fail-under-branch 100 --fail-under-decision 100
if %ERRORLEVEL% neq 0 (
    echo Coverage thresholds NOT met! Check docs/coverage/index.html
    exit /b %ERRORLEVEL%
)
echo === 100%% line, branch, and decision coverage achieved! ===
echo HTML report: docs/coverage/index.html
