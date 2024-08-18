@echo off
setlocal

REM Display warning about potential issues
echo WARNING: Running 'npm audit fix --force' will upgrade underlying packages and could potentially break your application if not properly analyzed.
echo Proceeding with this command without a thorough review may lead to unexpected issues.
set /p userInput=Do you still want to proceed (Y/N)? 

REM Check user input
if /I "%userInput%"=="Y" (
    echo Running audit with force fixes...
    npm audit fix --force
) else (
    echo Operation canceled. No audit changes were made.
)

endlocal