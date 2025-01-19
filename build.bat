@echo off

REM Set the source and output files
set SOURCE_FILES=main.cpp
set OUTPUT_FILE=output.exe

REM Compile the source file with g++ for x64 architecture
g++ -m86 -o %OUTPUT_FILE% %SOURCE_FILES% -luser32 -lkernel32

REM Check if the build was successful
if %ERRORLEVEL% neq 0 (
    echo Build failed!
    exit /b %ERRORLEVEL%
) else (
    echo Build succeeded!
)