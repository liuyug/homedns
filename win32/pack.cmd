@echo off

cls

pushd ..

rmdir build /s /q 2>nul
rmdir dist /s /q 2>nul

pyinstaller --icon App-browser.ico --clean --noupx --noconfirm --console --paths homedns --onefile hdns.py

del *.spec /q
popd
