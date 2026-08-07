@echo off
echo === Building with coverage mode ===
xmake f -m coverage -c
xmake build testsuite
if %ERRORLEVEL% neq 0 exit /b %ERRORLEVEL%

echo === Running tests ===
xmake run testsuite
if %ERRORLEVEL% neq 0 exit /b %ERRORLEVEL%

echo === Generating coverage reports ===
gcovr -r . --html-details coverage/index.html --txt coverage/summary.txt ^
  --decisions ^
  --fail-under-line 100 --fail-under-branch 100 --fail-under-decision 100
if %ERRORLEVEL% neq 0 (
    echo Coverage thresholds NOT met! Check coverage/index.html
    exit /b %ERRORLEVEL%
)
echo === 100%% line, branch, and decision (MC/DC) coverage achieved! ===
echo HTML report: coverage/index.html
