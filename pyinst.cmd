

rmdir build /s /q

pyinstaller --clean --noupx -c -p homedns -F homedns.py

