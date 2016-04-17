cls

rmdir build /s /q

python setup.py build_ext --inplace

pyinstaller --icon App-browser.ico --clean --noupx --noconfirm --console --paths homedns --onefile hdns.py
pyinstaller --icon App-browser.ico --clean --noupx --noconfirm --console --paths homedns --onefile dnsprobe.py
pyinstaller --icon App-browser.ico --clean --noupx --noconfirm --console --paths homedns --onefile dnsresolver.py

rem pyinstaller --icon App-browser.ico --clean --noupx --noconfirm --console --paths homedns hdns.py dnsprobe.py
