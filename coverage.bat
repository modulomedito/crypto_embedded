@echo off
echo === Building with MSYS2 GCC 15 ===
xmake f -p mingw --mingw=C:/msys64/mingw64 -m coverage -c
xmake build -r testsuite
if %ERRORLEVEL% neq 0 exit /b %ERRORLEVEL%

echo === Running tests ===
xmake run testsuite
if %ERRORLEVEL% neq 0 exit /b %ERRORLEVEL%

echo === Generating coverage reports ===
gcovr --gcov-executable C:/msys64/mingw64/bin/gcov.exe ^
  --gcov-ignore-errors no_working_dir_found ^
  -r . --html-details coverage/index.html --txt coverage/summary.txt ^
  --decisions ^
  --fail-under-line 100 --fail-under-branch 100 --fail-under-decision 100
if %ERRORLEVEL% neq 0 (
    echo Coverage thresholds NOT met! Check coverage/index.html
    exit /b %ERRORLEVEL%
)
echo === 100%% line, branch, and decision coverage achieved! ===
echo HTML report: coverage/index.html
