cls

rmdir build /s /q

pyinstaller --icon App-browser.ico --clean --noupx --noconfirm --console --paths homedns --onefile homedns.py
