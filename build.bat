@echo off
rem Full HZProtect pipeline (MSVC x64):
rem   tools -> per-build keys -> encrypt asset -> build+stamp demo
setlocal
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 (echo vcvars64 failed & exit /b 1)

set ROOT=%~dp0
if not exist "%ROOT%build" mkdir "%ROOT%build"
pushd "%ROOT%build"
set CL=/nologo /std:c++17 /EHsc /O2 /W4 /permissive-

echo [1/6] building tools (hzkeygen, hzblob, hzstamp)
cl %CL% /Fe:hzkeygen.exe "%ROOT%src\tools\hzkeygen.cpp" /link /SUBSYSTEM:CONSOLE >nul || (echo   hzkeygen FAILED & popd & exit /b 1)
cl %CL% /Fe:hzblob.exe   "%ROOT%src\tools\hzblob.cpp"   /link /SUBSYSTEM:CONSOLE >nul || (echo   hzblob FAILED & popd & exit /b 1)
cl %CL% /Fe:hzstamp.exe  "%ROOT%src\tools\hzstamp.cpp"  /link /SUBSYSTEM:CONSOLE >nul || (echo   hzstamp FAILED & popd & exit /b 1)

echo [2/6] generating per-build keys
".\hzkeygen.exe" hz_build_keys.h hz_build_key.bin || (echo   keygen FAILED & popd & exit /b 1)

echo [3/6] encrypting asset config.json
".\hzblob.exe" "%ROOT%test\assets\config.json" config_blob.h config_blob hz_build_key.bin || (echo   blob FAILED & popd & exit /b 1)

echo [4/6] building hzdemo.exe
cl %CL% /I. /Fe:hzdemo.exe "%ROOT%test\demo.cpp" /link /SUBSYSTEM:CONSOLE >nul || (echo   demo FAILED & popd & exit /b 1)

echo [5/6] stamping hzdemo.exe
".\hzstamp.exe" hzdemo.exe || (echo   stamp FAILED & popd & exit /b 1)

echo [6/6] done
popd
exit /b 0
