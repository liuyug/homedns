cls

rmdir build /s /q

python setup.py build_ext --inplace
pyinstaller --icon App-browser.ico --clean --noupx --noconfirm --console --paths homedns --onefile homedns.py
