@echo off
setlocal

REM Execute linting
echo Running linting on src folder...
npx eslint src

endlocal