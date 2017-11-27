@echo off

cls

set PATH=%PATH%;C:\Python35-32\swigwin-3.0.12

rmdir build /s /q 2>nul
rmdir dist /s /q 2>nul

if x%1 == x (
    echo %0 [build_ext, hdns, dnsprobe, dnsresolver]
    exit /b
)

if x%1 == xbuild_ext (
    python setup.py build_ext --inplace
)
if x%1 == xhdns (
    pyinstaller --icon App-browser.ico --clean --noupx --noconfirm --console --paths homedns --onefile hdns.py
)

if x%1 == xdnsprobe (
    pyinstaller --icon App-browser.ico --clean --noupx --noconfirm --console --paths homedns --onefile dnsprobe.py
)

if x%1 == xdnsresolver (
    pyinstaller --icon App-browser.ico --clean --noupx --noconfirm --console --paths homedns --onefile dnsresolver.py
)
