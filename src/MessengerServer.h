#pragma once

#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN
    #include <winsock2.h>
    #include <ws2tcpip.h>
     #ifdef _MSC_VER
        #pragma comment(lib, "ws2_32.lib")
    #endif
    typedef SOCKET SocketType;
    #define INVALID_SOCKET_VALUE INVALID_SOCKET
    #define SOCKET_ERROR_VALUE SOCKET_ERROR
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    typedef int SocketType;
    #define INVALID_SOCKET_VALUE -1
    #define SOCKET_ERROR_VALUE -1
    #define closesocket close
#endif

#include "Database.h"
#include "Packet.h"
#include <map>
#include <mutex>
#include <thread>

class MessengerServer {
private:
    SocketType serverSocket;
    std::map<int64_t, SocketType> userSockets; // user_id -> socket
    std::mutex usersMutex;
    bool running;
    Database database;

    struct ClientState {
        bool authed = false;
        int64_t user_id = -1;
        std::string username;
        std::string token;
    };

    std::mutex statesMutex;
    std::map<SocketType, ClientState> states;

public:
    MessengerServer();
    ~MessengerServer();

    bool start(int port);
    void stop();

private:
    void acceptLoop();
    void clientThread(SocketType clientSocket);

    // Отправка пакетов
    void sendPacket(SocketType socket, const Packet& packet);
    void sendErrorPacket(SocketType socket, ErrorCode code, const std::string& message);

    // Обработчики команд
    void handleRegister(SocketType socket, const std::vector<uint8_t>& data);
    void handleLogin(SocketType socket, const std::vector<uint8_t>& data);
    void handleAuthToken(SocketType socket, const std::vector<uint8_t>& data);
    void handleSendMessage(SocketType socket, const std::vector<uint8_t>& data);
    void handleHistoryRequest(SocketType socket, const std::vector<uint8_t>& data);
    void handlePing(SocketType socket);

    // Управление состоянием
    void setAuthed(SocketType socket, int64_t userId, const std::string& username, const std::string& token);
    ClientState getState(SocketType socket);
    void afterAuthJoin(int64_t userId, SocketType socket);

    // Утилиты
    void broadcastUserList();
    void sendHistoryFor(int64_t userId, SocketType socket);

    // v1.1
    void handleSearchUsers(SocketType socket, const std::vector<uint8_t>& data);
    void handleLogout(SocketType socket);
    bool isUserOnline(int64_t userId);
    void broadcastUserStatus(int64_t userId, bool isOnline);

    // v1.2
    void handleUserListRequest(SocketType socket);
    void handleHistoryResponse(SocketType socket, const std::vector<uint8_t>& data);
};
