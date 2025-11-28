#include "Packet.h"
#include <cstring>

// =============== Packet Base ===============

Packet::Packet(PacketType type) : length(6), packetId(type) {}

// Записывает 16-битное число в формате X
//
// Пример: число 300 (0x012C) станет двумя байтами: [0x2C, 0x01]
void Packet::writeUint16(std::vector<uint8_t>& buffer, uint16_t value) {
    buffer.push_back(value & 0xFF);
    buffer.push_back((value >> 8) & 0xFF);
}

// 4 байта
void Packet::writeUint32(std::vector<uint8_t>& buffer, uint32_t value) {
    buffer.push_back(value & 0xFF);
    buffer.push_back((value >> 8) & 0xFF);
    buffer.push_back((value >> 16) & 0xFF);
    buffer.push_back((value >> 24) & 0xFF);
}

// 8 байт
void Packet::writeInt64(std::vector<uint8_t>& buffer, int64_t value) {
    for (int i = 0; i < 8; ++i) {
        buffer.push_back((value >> (i * 8)) & 0xFF);
    }
}

// Выводит длину буффера, а потом сами байты [2 bytes length][N bytes text]
void Packet::writeString(std::vector<uint8_t>& buffer, const std::string& str) {
    uint16_t len = static_cast<uint16_t>(str.size());
    writeUint16(buffer, len);
    buffer.insert(buffer.end(), str.begin(), str.end());
}


// Читает 16-битное число из массива байтов X
//
// Параметр offset автоматически сдвигается на 2 позиции
uint16_t Packet::readUint16(const uint8_t* data, size_t& offset) {
    uint16_t value = data[offset] | (data[offset + 1] << 8); // Склеивание байтов*
    offset += 2;
    return value;
}

// offest на 4 позиции
uint32_t Packet::readUint32(const uint8_t* data, size_t& offset) {
    uint32_t value = data[offset] | (data[offset + 1] << 8) |
                     (data[offset + 2] << 16) | (data[offset + 3] << 24);
    offset += 4;
    return value;
}

// offset на 8 позиций
int64_t Packet::readInt64(const uint8_t* data, size_t& offset) {
    int64_t value = 0;
    for (int i = 0; i < 8; ++i) {
        value |= (static_cast<int64_t>(data[offset + i]) << (i * 8));
    }
    offset += 8;
    return value;
}

// Читает строку фиксированной длины из буфера
// length должна быть прочитана заранее через readUint16
std::string Packet::readString(const uint8_t* data, size_t& offset, uint16_t length) {
    std::string str(reinterpret_cast<const char*>(data + offset), length);
    offset += length;
    return str;
}

// =============== PacketBuilder ===============


// Создаёт билдер для указанного типа пакета
// Байты заполнятся в методе build()
PacketBuilder::PacketBuilder(PacketType packetType) : type(packetType) {
    // Резервируем место под length (4 байта) и packetId (2 байта)
    buffer.resize(6);
}


// Добавляет данные в пакет. Возвращаем *this для цепочки вызовов
// Например: builder.addUint8(1).addString("test").build();
PacketBuilder& PacketBuilder::addUint8(uint8_t value) {
    buffer.push_back(value);
    return *this; // Возвращает сам себя
}

PacketBuilder& PacketBuilder::addUint16(uint16_t value) {
    Packet::writeUint16(buffer, value);
    return *this;
}

PacketBuilder& PacketBuilder::addUint32(uint32_t value) {
    Packet::writeUint32(buffer, value);
    return *this;
}

PacketBuilder& PacketBuilder::addInt64(int64_t value) {
    Packet::writeInt64(buffer, value);
    return *this;
}

PacketBuilder& PacketBuilder::addString(const std::string& str) {
    Packet::writeString(buffer, str);
    return *this;
}


// Финализирует пакет: [length: 4 байта][packetId: 2 байта][данные: N байт]
std::vector<uint8_t> PacketBuilder::build() {
    uint32_t length = static_cast<uint32_t>(buffer.size());
    uint16_t packetId = static_cast<uint16_t>(type);
    size_t offset = 0;

    // Записывает length (4 байта) в начало буфера
    buffer[offset++] = length & 0xFF;
    buffer[offset++] = (length >> 8) & 0xFF;
    buffer[offset++] = (length >> 16) & 0xFF;
    buffer[offset++] = (length >> 24) & 0xFF;

    // Записывает packetId (2 байта)
    buffer[offset++] = packetId & 0xFF;
    buffer[offset++] = (packetId >> 8) & 0xFF;

    return buffer;
}


// Превращение пакетов в байты для отправки по сети
// LoginRequestPacket
// 4ex: [заголовок 6 байт][длина username: 2][username: N][длина password: 2][password: M]

// =============== ErrorPacket ===============

ErrorPacket::ErrorPacket(ErrorCode code, const std::string& message)
    : Packet(PacketType::PACKET_ERROR), errorCode(code), errorMessage(message) {}

std::vector<uint8_t> ErrorPacket::serialize() const {
    PacketBuilder builder(PacketType::PACKET_ERROR);
    builder.addUint16(static_cast<uint16_t>(errorCode));
    builder.addString(errorMessage);
    return builder.build();
}


// =============== RegisterRequestPacket ===============

RegisterRequestPacket::RegisterRequestPacket(const std::string& user, const std::string& pass)
    : Packet(PacketType::REGISTER_REQUEST), username(user), password(pass) {}

std::vector<uint8_t> RegisterRequestPacket::serialize() const {
    PacketBuilder builder(PacketType::REGISTER_REQUEST);
    builder.addString(username);
    builder.addString(password);
    return builder.build();
}

// =============== RegisterResponsePacket ===============

RegisterResponsePacket::RegisterResponsePacket(bool succ, int64_t uid, const std::string& tok)
    : Packet(PacketType::REGISTER_RESPONSE), success(succ), userId(uid), token(tok) {}

std::vector<uint8_t> RegisterResponsePacket::serialize() const {
    PacketBuilder builder(PacketType::REGISTER_RESPONSE);
    builder.addUint8(success ? 1 : 0);
    builder.addInt64(userId);
    builder.addString(token);
    return builder.build();
}

// =============== LoginRequestPacket ===============

LoginRequestPacket::LoginRequestPacket(const std::string& user, const std::string& pass)
    : Packet(PacketType::LOGIN_REQUEST), username(user), password(pass) {}

std::vector<uint8_t> LoginRequestPacket::serialize() const {
    PacketBuilder builder(PacketType::LOGIN_REQUEST);
    builder.addString(username);
    builder.addString(password);
    return builder.build();
}

// =============== LoginResponsePacket ===============

LoginResponsePacket::LoginResponsePacket(bool succ, int64_t uid, const std::string& tok)
    : Packet(PacketType::LOGIN_RESPONSE), success(succ), userId(uid), token(tok) {}

std::vector<uint8_t> LoginResponsePacket::serialize() const {
    PacketBuilder builder(PacketType::LOGIN_RESPONSE);
    builder.addUint8(success ? 1 : 0);
    builder.addInt64(userId);
    builder.addString(token);
    return builder.build();
}

// =============== AuthTokenRequestPacket ===============

AuthTokenRequestPacket::AuthTokenRequestPacket(const std::string& tok)
    : Packet(PacketType::AUTH_TOKEN_REQUEST), token(tok) {}

std::vector<uint8_t> AuthTokenRequestPacket::serialize() const {
    PacketBuilder builder(PacketType::AUTH_TOKEN_REQUEST);
    builder.addString(token);
    return builder.build();
}

// =============== AuthResponsePacket ===============

AuthResponsePacket::AuthResponsePacket(bool succ, int64_t uid)
    : Packet(PacketType::AUTH_RESPONSE), success(succ), userId(uid) {}

std::vector<uint8_t> AuthResponsePacket::serialize() const {
    PacketBuilder builder(PacketType::AUTH_RESPONSE);
    builder.addUint8(success ? 1 : 0);
    builder.addInt64(userId);
    return builder.build();
}

// =============== SendMessagePacket ===============

SendMessagePacket::SendMessagePacket(int64_t recipient, const std::string& msg)
    : Packet(PacketType::SEND_MESSAGE), recipientId(recipient), body(msg) {}

std::vector<uint8_t> SendMessagePacket::serialize() const {
    PacketBuilder builder(PacketType::SEND_MESSAGE);
    builder.addInt64(recipientId);
    builder.addString(body);
    return builder.build();
}

// =============== ReceiveMessagePacket ===============

ReceiveMessagePacket::ReceiveMessagePacket(int64_t msgId, int64_t ts, int64_t sender, int64_t recipient, const std::string& msg)
    : Packet(PacketType::RECEIVE_MESSAGE), messageId(msgId), timestamp(ts), senderId(sender), recipientId(recipient), body(msg) {}

std::vector<uint8_t> ReceiveMessagePacket::serialize() const {
    PacketBuilder builder(PacketType::RECEIVE_MESSAGE);
    builder.addInt64(messageId);
    builder.addInt64(timestamp);
    builder.addInt64(senderId);
    builder.addInt64(recipientId);
    builder.addString(body);
    return builder.build();
}

// =============== HistoryRequestPacket ===============

HistoryRequestPacket::HistoryRequestPacket(int64_t peer, uint32_t lim)
    : Packet(PacketType::HISTORY_REQUEST), peerId(peer), limit(lim) {}

std::vector<uint8_t> HistoryRequestPacket::serialize() const {
    PacketBuilder builder(PacketType::HISTORY_REQUEST);
    builder.addInt64(peerId);
    builder.addUint32(limit);
    return builder.build();
}

// =============== PingPacket ===============

PingPacket::PingPacket() : Packet(PacketType::PING) {}

std::vector<uint8_t> PingPacket::serialize() const {
    PacketBuilder builder(PacketType::PING);
    return builder.build();
}

// =============== PongPacket ===============

PongPacket::PongPacket() : Packet(PacketType::PONG) {}

std::vector<uint8_t> PongPacket::serialize() const {
    PacketBuilder builder(PacketType::PONG);
    return builder.build();
}

// =============== HistoryResponsePacket ===============
HistoryResponsePacket::HistoryResponsePacket(const std::vector<ReceiveMessagePacket>& msgs)
    : Packet(PacketType::HISTORY_RESPONSE), messages(msgs) {}

std::vector<uint8_t> HistoryResponsePacket::serialize() const {
    PacketBuilder builder(PacketType::HISTORY_RESPONSE);
    builder.addUint32(static_cast<uint32_t>(messages.size()));
    for (const auto& msg : messages) {
        // Сериализуем каждое сообщение внутри
        builder.addInt64(msg.getMessageId());
        builder.addInt64(msg.getTimestamp());
        builder.addInt64(msg.getSenderId());
        builder.addInt64(msg.getRecipientId());
        builder.addString(msg.getBody());
    }
    return builder.build();
}

// =============== UserListRequestPacket ===============
UserListRequestPacket::UserListRequestPacket() : Packet(PacketType::USER_LIST_REQUEST) {}

std::vector<uint8_t> UserListRequestPacket::serialize() const {
    PacketBuilder builder(PacketType::USER_LIST_REQUEST);
    return builder.build();
}

// =============== UserListResponsePacket ===============
UserListResponsePacket::UserListResponsePacket(const std::vector<std::tuple<int64_t, std::string, bool>>& userList)
    : Packet(PacketType::USER_LIST_RESPONSE) {
    for (const auto& [uid, username, online] : userList) {
        users.push_back({uid, username, online});
    }
}

std::vector<uint8_t> UserListResponsePacket::serialize() const {
    PacketBuilder builder(PacketType::USER_LIST_RESPONSE);
    builder.addUint32(static_cast<uint32_t>(users.size()));
    for (const auto& user : users) {
        builder.addInt64(user.userId);
        builder.addString(user.username);
        builder.addUint8(user.isOnline ? 1 : 0);
    }
    return builder.build();
}

// =============== SearchUsersRequestPacket ===============
SearchUsersRequestPacket::SearchUsersRequestPacket(const std::string& q)
    : Packet(PacketType::SEARCH_USERS_REQUEST), query(q) {}

std::vector<uint8_t> SearchUsersRequestPacket::serialize() const {
    PacketBuilder builder(PacketType::SEARCH_USERS_REQUEST);
    builder.addString(query);
    return builder.build();
}

// =============== SearchUsersResponsePacket ===============
SearchUsersResponsePacket::SearchUsersResponsePacket(const std::vector<std::tuple<int64_t, std::string, bool>>& results)
    : Packet(PacketType::SEARCH_USERS_RESPONSE) {
    for (const auto& [uid, username, online] : results) {
        users.push_back({uid, username, online});
    }
}

std::vector<uint8_t> SearchUsersResponsePacket::serialize() const {
    PacketBuilder builder(PacketType::SEARCH_USERS_RESPONSE);
    builder.addUint32(static_cast<uint32_t>(users.size()));
    for (const auto& user : users) {
        builder.addInt64(user.userId);
        builder.addString(user.username);
        builder.addUint8(user.isOnline ? 1 : 0);
    }
    return builder.build();
}

// =============== LogoutRequestPacket ===============
LogoutRequestPacket::LogoutRequestPacket() : Packet(PacketType::LOGOUT_REQUEST) {}

std::vector<uint8_t> LogoutRequestPacket::serialize() const {
    PacketBuilder builder(PacketType::LOGOUT_REQUEST);
    return builder.build();
}

// =============== UserStatusUpdatePacket ===============
UserStatusUpdatePacket::UserStatusUpdatePacket(int64_t uid, bool online)
    : Packet(PacketType::USER_STATUS_UPDATE), userId(uid), isOnline(online) {}

std::vector<uint8_t> UserStatusUpdatePacket::serialize() const {
    PacketBuilder builder(PacketType::USER_STATUS_UPDATE);
    builder.addInt64(userId);
    builder.addUint8(isOnline ? 1 : 0);
    return builder.build();
}

//v1.5
// =============== SendMessageResponsePacket ===============

SendMessageResponsePacket::SendMessageResponsePacket(int64_t msgId)
    : Packet(PacketType::SEND_MESSAGE_RESPONSE), messageId(msgId) {}

std::vector<uint8_t> SendMessageResponsePacket::serialize() const {
    PacketBuilder builder(PacketType::SEND_MESSAGE_RESPONSE);
    builder.addInt64(messageId);
    return builder.build();
}