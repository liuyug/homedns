

rmdir build /s /q

pyinstaller --clean --noupx -y -c -p homedns -F homedns.py

copy default.rules dist /y
copy black.rules dist /y
copy hosts.homedns dist /y
