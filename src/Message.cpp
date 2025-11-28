#include "Message.h"
#include "Packet.h"

Message::Message() : messageId(-1), timestamp(0), senderId(-1), recipientId(-1), body("") {}

Message::Message(int64_t msgId, int64_t ts, int64_t sender, int64_t recipient, const std::string& text)
    : messageId(msgId), timestamp(ts), senderId(sender), recipientId(recipient), body(text) {}

std::vector<uint8_t> Message::toBytes() const {
    PacketBuilder builder(PacketType::RECEIVE_MESSAGE);
    builder.addInt64(messageId);
    builder.addInt64(timestamp);
    builder.addInt64(senderId);
    builder.addInt64(recipientId);
    builder.addString(body);
    return builder.build();
}

bool Message::isValid() const {
    return messageId > 0 && timestamp > 0 && senderId > 0 && recipientId > 0;
}
