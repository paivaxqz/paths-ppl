@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 exit /b 1
set ROOT=%~dp0
set YARA=%ROOT%deps\yara
set INC=/I"%YARA%\include" /I"%YARA%" /I"%ROOT%src\paths-parser"
set LIBS="%YARA%\lib\libyara.lib" advapi32.lib crypt32.lib wintrust.lib winhttp.lib ws2_32.lib bcrypt.lib
cd /d "%ROOT%src\paths-parser"
cl /nologo /EHsc /std:c++17 /O2 /MD /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN %INC% main.cpp Utils.cpp rules.cpp /Fe:paths.exe /link /DYNAMICBASE /NXCOMPAT %LIBS%
if errorlevel 1 exit /b 1
echo paths.exe pronto
copy /Y paths.exe "%ROOT%release\paths.exe"
