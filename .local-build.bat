@echo off
setlocal

REM Default values
set "audit=False"
set "start=False"

REM Check if the first parameter is provided and set start to True if so
if "%~1"=="True" (
    set "start=True"
)

REM Check if the second parameter is provided and set audit to True if so
if "%~2"=="True" (
    set "audit=True"
)

REM Define the files and directories to be checked
echo Verifying if all mandatory files exist...
set "CHECK_FILES_DIRS=.github\workflows\pipeline.yml src package.json .gitignore CHANGELOG.md LICENSE README.md"

REM Check for the existence of each required file or directory
for %%f in (%CHECK_FILES_DIRS%) do (
    if not exist "%%f" (
        echo Error: Required file or directory %%f is missing.
        exit /b 1
    )
)

echo Executing clean batch script...
call bat\.clean.bat

echo Executing install batch script...
call bat\.install.bat

if "%audit%"=="True" (
    echo Executing audit batch script...
    call bat\.audit-fix.bat
)

echo Executing lint batch script...
call bat\.lint.bat

if "%start%"=="True" (
    echo Executing start batch script...
    call bat\.start.bat
)

endlocal