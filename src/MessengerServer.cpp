#include "MessengerServer.h"
#include <iostream>
#include <cstring>

using namespace std;

MessengerServer::MessengerServer() : serverSocket(INVALID_SOCKET_VALUE), running(false) {
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        throw runtime_error("WSAStartup failed");
    }
#endif
    if (!database.open("messages.db")) {
        throw runtime_error("Database open failed");
    }
    if (!database.initSchema()) {
        throw runtime_error("Database schema initialization failed");
    }
}

MessengerServer::~MessengerServer() {
    stop();
    database.close();
#ifdef _WIN32
    WSACleanup();
#endif
}

bool MessengerServer::start(int port) {
    serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (serverSocket == INVALID_SOCKET_VALUE) {
        cerr << "Error creating socket" << endl;
        return false;
    }

    int opt = 1;
    setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt));

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(port);

    if (bind(serverSocket, reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr)) == SOCKET_ERROR_VALUE) {
        cerr << "Bind failed" << endl;
        return false;
    }

    if (listen(serverSocket, SOMAXCONN) == SOCKET_ERROR_VALUE) {
        cerr << "Listen failed" << endl;
        return false;
    }

    running = true;
    thread(&MessengerServer::acceptLoop, this).detach();
    cout << "Server started on port " << port << endl;
    return true;
}

void MessengerServer::stop() {
    if (!running) return;
    running = false;
    closesocket(serverSocket);
    serverSocket = INVALID_SOCKET_VALUE;

    lock_guard<mutex> lk(usersMutex);
    for (auto& kv : userSockets) {
        closesocket(kv.second);
    }
    userSockets.clear();
}

void MessengerServer::acceptLoop() {
    while (running) {
        sockaddr_in clientAddr{};
        socklen_t len = sizeof(clientAddr);
        SocketType clientSocket = accept(serverSocket, reinterpret_cast<sockaddr*>(&clientAddr), &len);
        if (clientSocket == INVALID_SOCKET_VALUE) {
            if (!running) break;
            continue;
        }

        {
            lock_guard<mutex> g(statesMutex);
            states[clientSocket] = ClientState{};
        }

        thread(&MessengerServer::clientThread, this, clientSocket).detach();
    }
}

void MessengerServer::sendPacket(SocketType socket, const Packet& packet) {
    vector<uint8_t> data = packet.serialize();
    send(socket, reinterpret_cast<const char*>(data.data()), static_cast<int>(data.size()), 0);
}

void MessengerServer::sendErrorPacket(SocketType socket, ErrorCode code, const string& message) {
    ErrorPacket errorPacket(code, message);
    sendPacket(socket, errorPacket);
}

void MessengerServer::handleRegister(SocketType socket, const vector<uint8_t>& data) {
    size_t offset = 6; // Skip length and packetId
    if (data.size() < offset + 4) {
        sendErrorPacket(socket, ErrorCode::INVALID_PACKET, "Invalid registration packet");
        return;
    }

    uint16_t usernameLen = Packet::readUint16(data.data(), offset);
    if (data.size() < offset + usernameLen + 2) {
        sendErrorPacket(socket, ErrorCode::INVALID_PACKET, "Invalid registration packet");
        return;
    }
    string username = Packet::readString(data.data(), offset, usernameLen);

    uint16_t passwordLen = Packet::readUint16(data.data(), offset);
    if (data.size() < offset + passwordLen) {
        sendErrorPacket(socket, ErrorCode::INVALID_PACKET, "Invalid registration packet");
        return;
    }
    string password = Packet::readString(data.data(), offset, passwordLen);

    if (database.userExists(username)) {
        sendErrorPacket(socket, ErrorCode::USER_EXISTS, "User already exists");
        return;
    }

    if (!database.createUser(username, password)) {
        sendErrorPacket(socket, ErrorCode::DATABASE_ERROR, "Registration failed");
        return;
    }

    int64_t userId = database.getUserId(username);
    if (userId == -1) {
        sendErrorPacket(socket, ErrorCode::DATABASE_ERROR, "User ID retrieval failed");
        return;
    }

    string token = database.issueToken(userId);
    if (token.empty()) {
        sendErrorPacket(socket, ErrorCode::DATABASE_ERROR, "Token generation failed");
        return;
    }

    setAuthed(socket, userId, username, token);
    RegisterResponsePacket response(true, userId, token);
    sendPacket(socket, response);
    afterAuthJoin(userId, socket);
}

void MessengerServer::handleLogin(SocketType socket, const vector<uint8_t>& data) {
    size_t offset = 6;
    if (data.size() < offset + 4) {
        sendErrorPacket(socket, ErrorCode::INVALID_PACKET, "Invalid login packet");
        return;
    }

    uint16_t usernameLen = Packet::readUint16(data.data(), offset);
    if (data.size() < offset + usernameLen + 2) {
        sendErrorPacket(socket, ErrorCode::INVALID_PACKET, "Invalid login packet");
        return;
    }
    string username = Packet::readString(data.data(), offset, usernameLen);

    uint16_t passwordLen = Packet::readUint16(data.data(), offset);
    if (data.size() < offset + passwordLen) {
        sendErrorPacket(socket, ErrorCode::INVALID_PACKET, "Invalid login packet");
        return;
    }
    string password = Packet::readString(data.data(), offset, passwordLen);

    if (!database.validatePassword(username, password)) {
        sendErrorPacket(socket, ErrorCode::AUTH_FAILED, "Invalid credentials");
        return;
    }

    int64_t userId = database.getUserId(username);
    if (userId == -1) {
        sendErrorPacket(socket, ErrorCode::USER_NOT_FOUND, "User not found");
        return;
    }

    string token = database.issueToken(userId);
    if (token.empty()) {
        sendErrorPacket(socket, ErrorCode::DATABASE_ERROR, "Token generation failed");
        return;
    }

    setAuthed(socket, userId, username, token);
    LoginResponsePacket response(true, userId, token);
    sendPacket(socket, response);
    afterAuthJoin(userId, socket);
}

void MessengerServer::handleAuthToken(SocketType socket, const vector<uint8_t>& data) {
    size_t offset = 6;
    if (data.size() < offset + 2) {
        sendErrorPacket(socket, ErrorCode::INVALID_PACKET, "Invalid auth packet");
        return;
    }

    uint16_t tokenLen = Packet::readUint16(data.data(), offset);
    if (data.size() < offset + tokenLen) {
        sendErrorPacket(socket, ErrorCode::INVALID_PACKET, "Invalid auth packet");
        return;
    }
    string token = Packet::readString(data.data(), offset, tokenLen);

    database.cleanExpiredTokens();
    int64_t userId;
    if (!database.validateToken(token, userId)) {
        sendErrorPacket(socket, ErrorCode::INVALID_TOKEN, "Invalid or expired token");
        return;
    }

    string username = database.getUsername(userId);
    if (username.empty()) {
        sendErrorPacket(socket, ErrorCode::USER_NOT_FOUND, "User not found");
        return;
    }

    setAuthed(socket, userId, username, token);
    AuthResponsePacket response(true, userId);
    sendPacket(socket, response);
    afterAuthJoin(userId, socket);
}

// 1.3v
void MessengerServer::handleSendMessage(SocketType socket, const vector<uint8_t>& data) {
    ClientState state = getState(socket);
    if (!state.authed) {
        sendErrorPacket(socket, ErrorCode::UNAUTHORIZED, "Not authenticated");
        return;
    }

    size_t offset = 6;
    if (data.size() < offset + 8 + 2) {
        sendErrorPacket(socket, ErrorCode::INVALID_PACKET, "Invalid message packet");
        return;
    }

    int64_t recipientId = Packet::readInt64(data.data(), offset);
    uint16_t bodyLen = Packet::readUint16(data.data(), offset);
    if (data.size() < offset + bodyLen) {
        sendErrorPacket(socket, ErrorCode::INVALID_PACKET, "Invalid message packet");
        return;
    }

    string body = Packet::readString(data.data(), offset, bodyLen);
    
    // Сохраняем сообщение и получаем его ID
    int64_t msgId = database.saveMessage(state.user_id, recipientId, body);
    if (msgId == -1) {
        sendErrorPacket(socket, ErrorCode::DATABASE_ERROR, "Failed to save message");
        return;
    }

    //v1.5
    SendMessageResponsePacket response(msgId);
    sendPacket(socket, response);

    // Отправляем сообщение получателю, если он онлайн
    SocketType recipientSocket = INVALID_SOCKET_VALUE;
    {
        lock_guard<mutex> lock(usersMutex);
        auto it = userSockets.find(recipientId);
        if (it != userSockets.end()) {
            recipientSocket = it->second;
        }
    }
    
    if (recipientSocket != INVALID_SOCKET_VALUE) {
        int64_t timestamp = chrono::duration_cast<chrono::seconds>(
            chrono::system_clock::now().time_since_epoch()).count();
        ReceiveMessagePacket msgPacket(msgId, timestamp, state.user_id, recipientId, body);
        sendPacket(recipientSocket, msgPacket);
    }
}


void MessengerServer::handleHistoryRequest(SocketType socket, const vector<uint8_t>& data) {
    ClientState state = getState(socket);
    if (!state.authed) {
        sendErrorPacket(socket, ErrorCode::UNAUTHORIZED, "Not authenticated");
        return;
    }

    size_t offset = 6;
    if (data.size() < offset + 8 + 4) {
        sendErrorPacket(socket, ErrorCode::INVALID_PACKET, "Invalid history request");
        return;
    }

    int64_t peerId = Packet::readInt64(data.data(), offset);
    uint32_t limit = Packet::readUint32(data.data(), offset);
    vector<Message> messages = database.getHistoryWithUser(state.user_id, peerId, limit);
    
    // Формируем HistoryResponsePacket
    vector<ReceiveMessagePacket> msgPackets;
    for (const auto& msg : messages) {
        msgPackets.emplace_back(msg.getMessageId(), msg.getTimestamp(),
                                msg.getSenderId(), msg.getRecipientId(), msg.getBody());
    }
    
    HistoryResponsePacket response(msgPackets);
    sendPacket(socket, response);
}

void MessengerServer::handlePing(SocketType socket) {
    PongPacket pong;
    sendPacket(socket, pong);
}

void MessengerServer::clientThread(SocketType clientSocket) {
    uint8_t buffer[4096];
    bool connected = true;

    while (connected && running) {
        int bytesReceived = recv(clientSocket, reinterpret_cast<char*>(buffer), sizeof(buffer), 0);
        if (bytesReceived <= 0) break;

        // Парсинг пакета
        if (bytesReceived < 6) continue; // Минимальный размер пакета

        size_t offset = 0;
        uint32_t length = Packet::readUint32(buffer, offset);
        uint16_t packetIdRaw = Packet::readUint16(buffer, offset);

        if (length > sizeof(buffer) || length > static_cast<uint32_t>(bytesReceived)) {
            sendErrorPacket(clientSocket, ErrorCode::INVALID_PACKET, "Packet size mismatch");
            continue;
        }

        PacketType packetId = static_cast<PacketType>(packetIdRaw);
        vector<uint8_t> packetData(buffer, buffer + length);

        // Обработка по типу пакета
        switch (packetId) {
            case PacketType::REGISTER_REQUEST:
                handleRegister(clientSocket, packetData);
                break;
            case PacketType::LOGIN_REQUEST:
                handleLogin(clientSocket, packetData);
                break;
            case PacketType::AUTH_TOKEN_REQUEST:
                handleAuthToken(clientSocket, packetData);
                break;
            case PacketType::SEND_MESSAGE:
                handleSendMessage(clientSocket, packetData);
                break;
            case PacketType::HISTORY_REQUEST:
                handleHistoryRequest(clientSocket, packetData);
                break;
            case PacketType::PING:
                handlePing(clientSocket);
                break;
            case PacketType::SEARCH_USERS_REQUEST:
                handleSearchUsers(clientSocket, packetData);
                break;
            case PacketType::LOGOUT_REQUEST:
                handleLogout(clientSocket);
                connected = false; // Закрываем соединение
                break;
            case PacketType::USER_LIST_REQUEST:
                handleUserListRequest(clientSocket);
                break;
            case PacketType::HISTORY_RESPONSE:
                // Обычно клиент не отправляет этот пакет, но можно добавить заглушку
                sendErrorPacket(clientSocket, ErrorCode::INVALID_PACKET, "Server-only packet");
                break;
            default:
                sendErrorPacket(clientSocket, ErrorCode::INVALID_PACKET, "Unknown packet type");
                break;
        }
    }

    // Отключение клиента
    ClientState state = getState(clientSocket);
    if (state.authed && state.user_id != -1) {
        lock_guard<mutex> lock(usersMutex);
        auto it = userSockets.find(state.user_id);
        if (it != userSockets.end() && it->second == clientSocket) {
            userSockets.erase(it);
        }
    }

    {
        lock_guard<mutex> g(statesMutex);
        states.erase(clientSocket);
    }

    closesocket(clientSocket);
    broadcastUserList();
}

void MessengerServer::setAuthed(SocketType socket, int64_t userId, const string& username, const string& token) {
    {
        lock_guard<mutex> g(statesMutex);
        auto& state = states[socket];
        state.authed = true;
        state.user_id = userId;
        state.username = username;
        state.token = token;
    }

    lock_guard<mutex> lock(usersMutex);
    userSockets[userId] = socket;
}

MessengerServer::ClientState MessengerServer::getState(SocketType socket) {
    lock_guard<mutex> g(statesMutex);
    auto it = states.find(socket);
    if (it != states.end()) return it->second;
    return ClientState{};
}

void MessengerServer::afterAuthJoin(int64_t userId, SocketType socket) {
    broadcastUserList();
    sendHistoryFor(userId, socket);
}

void MessengerServer::broadcastUserList() {
    // Упрощенная реализация - в продакшене нужен отдельный пакет USER_LIST_RESPONSE
    // Здесь просто логируем
    cout << "Broadcasting user list..." << endl;
}

void MessengerServer::sendHistoryFor(int64_t userId, SocketType socket) {
    vector<Message> messages = database.getHistory(userId);
    for (const auto& msg : messages) {
        ReceiveMessagePacket msgPacket(msg.getMessageId(), msg.getTimestamp(),
                                       msg.getSenderId(), msg.getRecipientId(), msg.getBody());
        sendPacket(socket, msgPacket);
    }
}


// v1.1 / 1.2-fix
// Поиск пользователей
void MessengerServer::handleSearchUsers(SocketType socket, const std::vector<uint8_t>& data) {
    ClientState state = getState(socket);
    if (!state.authed) {
        sendErrorPacket(socket, ErrorCode::UNAUTHORIZED, "Not authenticated");
        return;
    }

    size_t offset = 6;
    uint16_t queryLen = Packet::readUint16(data.data(), offset);
    std::string query = Packet::readString(data.data(), offset, queryLen);
    auto results = database.searchUsers(query);
    
    // Формируем список пользователей с онлайн-статусом
    std::vector<std::tuple<int64_t, std::string, bool>> userList;
    for (const auto& [userId, username] : results) {
        bool online = isUserOnline(userId);
        userList.emplace_back(userId, username, online);
    }
    
    SearchUsersResponsePacket response(userList);
    sendPacket(socket, response);
}

// Выход из системы
void MessengerServer::handleLogout(SocketType socket) {
    ClientState state = getState(socket);
    if (state.authed && !state.token.empty()) {
        database.revokeToken(state.token);
    }
    
    // Удаляем из онлайн-пользователей
    if (state.user_id != -1) {
        std::lock_guard<std::mutex> lock(usersMutex);
        auto it = userSockets.find(state.user_id);
        if (it != userSockets.end()) {
            userSockets.erase(it);
        }
    }
    
    // Оповещаем других пользователей об оффлайн статусе
    broadcastUserStatus(state.user_id, false);
}

// Проверка онлайн статуса
bool MessengerServer::isUserOnline(int64_t userId) {
    std::lock_guard<std::mutex> lock(usersMutex);
    return userSockets.find(userId) != userSockets.end();
}

// Рассылка изменения статуса
void MessengerServer::broadcastUserStatus(int64_t userId, bool isOnline) {
    UserStatusUpdatePacket packet(userId, isOnline);
    std::vector<uint8_t> data = packet.serialize();
    
    std::lock_guard<std::mutex> lock(usersMutex);
    for (const auto& [uid, sock] : userSockets) {
        if (uid != userId) {
            send(sock, reinterpret_cast<const char*>(data.data()), data.size(), 0);
        }
    }
}


void MessengerServer::handleUserListRequest(SocketType socket) {
    ClientState state = getState(socket);
    if (!state.authed) {
        sendErrorPacket(socket, ErrorCode::UNAUTHORIZED, "Not authenticated");
        return;
    }

    vector<tuple<int64_t, string, bool>> userList;
    
    lock_guard<mutex> lock(usersMutex);
    for (const auto& [userId, sock] : userSockets) {
        if (userId != state.user_id) {
            string username = database.getUsername(userId);
            if (!username.empty()) {
                userList.emplace_back(userId, username, true);
            }
        }
    }
    
    UserListResponsePacket response(userList);
    sendPacket(socket, response);
}
