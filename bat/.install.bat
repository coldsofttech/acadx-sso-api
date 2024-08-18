@echo off
setlocal

REM Install packages
echo Installing packages...
npm install
if %ERRORLEVEL% neq 0 (
    echo Error during npm install.
    exit /b 1
)

npm install eslint --save-dev

endlocal