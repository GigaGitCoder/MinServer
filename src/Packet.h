#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <cstring>

// ========== ТИПЫ ПАКЕТОВ (Протокол мессенджера v1.5) ==========
// Enum класс для идентификации типа пакета по сети
// Каждый тип имеет уникальный 16-битный ID (uint16_t)
// Используется Little-Endian формат (младший байт первым)
enum class PacketType : uint16_t {
    // === СИСТЕМНЫЕ ПАКЕТЫ ===
    PACKET_ERROR = 0x0001,  // Сообщение об ошибке (переименовано из ERROR для совместимости с Windows)
    PING = 0x000E,          // Проверка соединения (клиент → сервер)
    PONG = 0x000F,          // Ответ на PING (сервер → клиент)
    
    // === АУТЕНТИФИКАЦИЯ ===
    REGISTER_REQUEST = 0x0002,   // Запрос регистрации нового пользователя
    REGISTER_RESPONSE = 0x0003,  // Ответ на регистрацию (успех/неудача + токен)
    LOGIN_REQUEST = 0x0004,      // Запрос входа в систему
    LOGIN_RESPONSE = 0x0005,     // Ответ на вход (успех/неудача + токен)
    AUTH_TOKEN_REQUEST = 0x0006, // Запрос авторизации по токену (автовход)
    AUTH_RESPONSE = 0x0007,      // Ответ на авторизацию по токену
    LOGOUT_REQUEST = 0x0012,     // Запрос выхода из системы
    
    // === ОБМЕН СООБЩЕНИЯМИ ===
    SEND_MESSAGE = 0x0008,          // Отправка сообщения от клиента
    SEND_MESSAGE_RESPONSE = 0x0014, // Подтверждение отправки (v1.5 - возвращает ID сообщения)
    RECEIVE_MESSAGE = 0x0009,       // Получение сообщения клиентом (push от сервера)
    HISTORY_REQUEST = 0x000A,       // Запрос истории переписки с пользователем
    HISTORY_RESPONSE = 0x000B,      // Ответ с историей сообщений
    
    // === РАБОТА С ПОЛЬЗОВАТЕЛЯМИ ===
    USER_LIST_REQUEST = 0x000C,      // Запрос списка всех пользователей
    USER_LIST_RESPONSE = 0x000D,     // Ответ со списком пользователей
    SEARCH_USERS_REQUEST = 0x0010,   // Поиск пользователей по имени
    SEARCH_USERS_RESPONSE = 0x0011,  // Результаты поиска
    USER_STATUS_UPDATE = 0x0013      // Уведомление об изменении статуса (онлайн/офлайн)
};

// ========== КОДЫ ОШИБОК ==========
// Используются в ErrorPacket для передачи информации об ошибках
// Структура кодов: 1xxx - ошибки аутентификации, 2xxx - БД, 3xxx - протокол
enum class ErrorCode : uint16_t {
    // ОШИБКИ АУТЕНТИФИКАЦИИ (1000-1999)
    AUTH_FAILED = 1000,     // Неверный логин или пароль
    USER_EXISTS = 1001,     // Пользователь с таким именем уже существует
    INVALID_TOKEN = 1002,   // Недействительный или истекший токен
    UNAUTHORIZED = 1003,    // Попытка действия без авторизации
    USER_NOT_FOUND = 1004,  // Пользователь не найден
    
    // ОШИБКИ БАЗЫ ДАННЫХ (2000-2999)
    DATABASE_ERROR = 2000,  // Общая ошибка при работе с БД
    
    // ОШИБКИ ПРОТОКОЛА (3000-3999)
    INVALID_PACKET = 3000   // Невалидная структура пакета (битый пакет)
};

// Базовый класс пакета
class Packet {
protected:
    uint32_t length;
    PacketType packetId;

public:
    Packet(PacketType type);
    virtual ~Packet() = default;

    // Сериализация в байты
    virtual std::vector<uint8_t> serialize() const = 0;

    // Десериализация из байтов
    static Packet* deserialize(const std::vector<uint8_t>& data);

    PacketType getType() const { return packetId; }
    uint32_t getLength() const { return length; }

    // ПУБЛИЧНЫЕ утилиты для работы с байтами (используются в PacketBuilder и MessengerServer)
    static void writeUint16(std::vector<uint8_t>& buffer, uint16_t value);
    static void writeUint32(std::vector<uint8_t>& buffer, uint32_t value);
    static void writeInt64(std::vector<uint8_t>& buffer, int64_t value);
    static void writeString(std::vector<uint8_t>& buffer, const std::string& str);

    static uint16_t readUint16(const uint8_t* data, size_t& offset);
    static uint32_t readUint32(const uint8_t* data, size_t& offset);
    static int64_t readInt64(const uint8_t* data, size_t& offset);
    static std::string readString(const uint8_t* data, size_t& offset, uint16_t length);
};

// PacketBuilder - класс для упрощения создания пакетов
class PacketBuilder {
private:
    std::vector<uint8_t> buffer;
    PacketType type;

public:
    explicit PacketBuilder(PacketType packetType);

    PacketBuilder& addUint8(uint8_t value);
    PacketBuilder& addUint16(uint16_t value);
    PacketBuilder& addUint32(uint32_t value);
    PacketBuilder& addInt64(int64_t value);
    PacketBuilder& addString(const std::string& str);

    std::vector<uint8_t> build();
};

// Конкретные типы пакетов
class ErrorPacket : public Packet {
private:
    ErrorCode errorCode;
    std::string errorMessage;

public:
    ErrorPacket(ErrorCode code, const std::string& message);
    std::vector<uint8_t> serialize() const override;

    ErrorCode getErrorCode() const { return errorCode; }
    std::string getErrorMessage() const { return errorMessage; }
};

class RegisterRequestPacket : public Packet {
private:
    std::string username;
    std::string password;

public:
    RegisterRequestPacket(const std::string& user, const std::string& pass);
    std::vector<uint8_t> serialize() const override;

    std::string getUsername() const { return username; }
    std::string getPassword() const { return password; }
};

class RegisterResponsePacket : public Packet {
private:
    bool success;
    int64_t userId;
    std::string token;

public:
    RegisterResponsePacket(bool succ, int64_t uid, const std::string& tok);
    std::vector<uint8_t> serialize() const override;

    bool isSuccess() const { return success; }
    int64_t getUserId() const { return userId; }
    std::string getToken() const { return token; }
};

class LoginRequestPacket : public Packet {
private:
    std::string username;
    std::string password;

public:
    LoginRequestPacket(const std::string& user, const std::string& pass);
    std::vector<uint8_t> serialize() const override;

    std::string getUsername() const { return username; }
    std::string getPassword() const { return password; }
};

class LoginResponsePacket : public Packet {
private:
    bool success;
    int64_t userId;
    std::string token;

public:
    LoginResponsePacket(bool succ, int64_t uid, const std::string& tok);
    std::vector<uint8_t> serialize() const override;

    bool isSuccess() const { return success; }
    int64_t getUserId() const { return userId; }
    std::string getToken() const { return token; }
};

class AuthTokenRequestPacket : public Packet {
private:
    std::string token;

public:
    explicit AuthTokenRequestPacket(const std::string& tok);
    std::vector<uint8_t> serialize() const override;

    std::string getToken() const { return token; }
};

class AuthResponsePacket : public Packet {
private:
    bool success;
    int64_t userId;

public:
    AuthResponsePacket(bool succ, int64_t uid);
    std::vector<uint8_t> serialize() const override;

    bool isSuccess() const { return success; }
    int64_t getUserId() const { return userId; }
};

class SendMessagePacket : public Packet {
private:
    int64_t recipientId;
    std::string body;

public:
    SendMessagePacket(int64_t recipient, const std::string& msg);
    std::vector<uint8_t> serialize() const override;

    int64_t getRecipientId() const { return recipientId; }
    std::string getBody() const { return body; }
};

//v1.5
class SendMessageResponsePacket : public Packet {
private:
    int64_t messageId;
public:
    explicit SendMessageResponsePacket(int64_t msgId);
    std::vector<uint8_t> serialize() const override;
    int64_t getMessageId() const { return messageId; }
};

class ReceiveMessagePacket : public Packet {
private:
    int64_t messageId;
    int64_t timestamp;
    int64_t senderId;
    int64_t recipientId;
    std::string body;

public:
    ReceiveMessagePacket(int64_t msgId, int64_t ts, int64_t sender, int64_t recipient, const std::string& msg);
    std::vector<uint8_t> serialize() const override;

    int64_t getMessageId() const { return messageId; }
    int64_t getTimestamp() const { return timestamp; }
    int64_t getSenderId() const { return senderId; }
    int64_t getRecipientId() const { return recipientId; }
    std::string getBody() const { return body; }
};

class HistoryRequestPacket : public Packet {
private:
    int64_t peerId;
    uint32_t limit;

public:
    HistoryRequestPacket(int64_t peer, uint32_t lim);
    std::vector<uint8_t> serialize() const override;

    int64_t getPeerId() const { return peerId; }
    uint32_t getLimit() const { return limit; }
};

class PingPacket : public Packet {
public:
    PingPacket();
    std::vector<uint8_t> serialize() const override;
};

class PongPacket : public Packet {
public:
    PongPacket();
    std::vector<uint8_t> serialize() const override;
};

// =============== HistoryResponsePacket ===============
class HistoryResponsePacket : public Packet {
private:
    std::vector<ReceiveMessagePacket> messages;
public:
    explicit HistoryResponsePacket(const std::vector<ReceiveMessagePacket>& msgs);
    std::vector<uint8_t> serialize() const override;
    const std::vector<ReceiveMessagePacket>& getMessages() const { return messages; }
};

// =============== UserListRequestPacket ===============
class UserListRequestPacket : public Packet {
public:
    UserListRequestPacket();
    std::vector<uint8_t> serialize() const override;
};

// =============== UserListResponsePacket ===============
class UserListResponsePacket : public Packet {
private:
    struct UserInfo {
        int64_t userId;
        std::string username;
        bool isOnline;
    };
    std::vector<UserInfo> users;
public:
    explicit UserListResponsePacket(const std::vector<std::tuple<int64_t, std::string, bool>>& userList);
    std::vector<uint8_t> serialize() const override;
};

// =============== SearchUsersRequestPacket ===============
class SearchUsersRequestPacket : public Packet {
private:
    std::string query;
public:
    explicit SearchUsersRequestPacket(const std::string& q);
    std::vector<uint8_t> serialize() const override;
    std::string getQuery() const { return query; }
};

// =============== SearchUsersResponsePacket ===============
class SearchUsersResponsePacket : public Packet {
private:
    struct UserInfo {
        int64_t userId;
        std::string username;
        bool isOnline;
    };
    std::vector<UserInfo> users;
public:
    explicit SearchUsersResponsePacket(const std::vector<std::tuple<int64_t, std::string, bool>>& results);
    std::vector<uint8_t> serialize() const override;
};

// =============== LogoutRequestPacket ===============
class LogoutRequestPacket : public Packet {
public:
    LogoutRequestPacket();
    std::vector<uint8_t> serialize() const override;
};

// =============== UserStatusUpdatePacket ===============
class UserStatusUpdatePacket : public Packet {
private:
    int64_t userId;
    bool isOnline;
public:
    UserStatusUpdatePacket(int64_t uid, bool online);
    std::vector<uint8_t> serialize() const override;
    int64_t getUserId() const { return userId; }
    bool getIsOnline() const { return isOnline; }
};
