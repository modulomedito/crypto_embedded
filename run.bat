@echo off
echo ========================================
echo  crypto_embedded : Test + Coverage
echo ========================================
echo.

echo [1/2] Running tests...
call "%~dp0script\test.bat"
if %ERRORLEVEL% neq 0 (
    echo.
    echo TESTS FAILED -- skipping coverage
    pause
    exit /b %ERRORLEVEL%
)

echo.
echo [2/2] Running coverage...
call "%~dp0script\coverage.bat"
echo.
echo ========================================
echo  Done: tests passed + coverage 100%%
echo ========================================
pause
