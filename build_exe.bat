@echo off
echo ========================================
echo Messenger Server - Static Build
echo ========================================
echo.

set MSYS2_PATH=C:\msys64\mingw64\bin
set PATH=%MSYS2_PATH%;%PATH%

if not exist build mkdir build

echo [1/3] Компиляция SQLite (C)...
gcc -c sqlite3/sqlite3.c -o build/sqlite3.o -O2 -DSQLITE_THREADSAFE=1
if %errorlevel% neq 0 (
    echo [ERROR] SQLite компиляция провалилась!
    pause
    exit /b 1
)

echo.
echo [2/3] Компиляция основного проекта (C++)...
g++ -std=c++17 -O2 -Wall ^
    -Isrc -Isqlite3 ^
    -c src/main.cpp src/Packet.cpp src/User.cpp ^
       src/Message.cpp src/Database.cpp src/MessengerServer.cpp
if %errorlevel% neq 0 (
    echo [ERROR] Компиляция C++ провалилась!
    del *.o 2>nul
    pause
    exit /b 1
)

echo.
echo [3/3] Линковка со статическими библиотеками...
g++ -o build/MessengerServer.exe ^
    main.o Packet.o User.o Message.o Database.o MessengerServer.o ^
    build/sqlite3.o ^
    -lssl ^
    -lcrypto ^
    -lws2_32 ^
    -lcrypt32 ^
    -lws2_32 ^
    -static-libgcc ^
    -static-libstdc++ ^
    -static ^
    -pthread
if %errorlevel% neq 0 (
    echo [ERROR] Линковка провалилась!
    pause
    exit /b 1
)

del *.o 2>nul

echo.
echo ========================================
echo [SUCCESS] Сборка завершена успешно!
echo ========================================
echo Исполняемый файл: build\MessengerServer.exe
echo.
echo dir build*.exe | findstr "MessengerServer.exe"
echo.
echo cd build ^& MessengerServer.exe 5555
echo.
pause
