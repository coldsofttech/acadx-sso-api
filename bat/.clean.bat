@echo off
setlocal

REM Define the files to be deleted
set "BUILD=build"
set "NODE_MODULES=node_modules"
set "PACKAGE_LOCK=package-lock.json"

REM Delete build folder
if exist "%BUILD%" (
    echo Deleting folder %BUILD% and its contents...
    rd /s /q "%BUILD%"
)

REM Delete node_modules folder
if exist "%NODE_MODULES%" (
    echo Deleting folder %NODE_MODULES% and its contents...
    rd /s /q "%NODE_MODULES%"
)

REM Delete package-lock file
if exist "%PACKAGE_LOCK%" (
    echo Deleting %PACKAGE_LOCK%...
    del "%PACKAGE_LOCK%"
)

endlocal