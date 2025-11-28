#pragma once

#include <string>
#include <cstdint>
#include <vector>

class Message {
private:
    int64_t messageId;
    int64_t timestamp;
    int64_t senderId;
    int64_t recipientId;
    std::string body;

public:
    Message();
    Message(int64_t msgId, int64_t ts, int64_t sender, int64_t recipient, const std::string& text);

    // Геттеры
    int64_t getMessageId() const { return messageId; }
    int64_t getTimestamp() const { return timestamp; }
    int64_t getSenderId() const { return senderId; }
    int64_t getRecipientId() const { return recipientId; }
    std::string getBody() const { return body; }

    // Сеттеры
    void setMessageId(int64_t id) { messageId = id; }
    void setTimestamp(int64_t ts) { timestamp = ts; }
    void setSenderId(int64_t sender) { senderId = sender; }
    void setRecipientId(int64_t recipient) { recipientId = recipient; }
    void setBody(const std::string& text) { body = text; }

    // Сериализация в байты для пакета
    std::vector<uint8_t> toBytes() const;

    // Проверка валидности
    bool isValid() const;
};
