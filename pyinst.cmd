cls

rmdir build /s /q

pyinstaller --clean --noupx -y -c -p homedns -F homedns.py
