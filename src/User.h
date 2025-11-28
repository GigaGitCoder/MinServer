#pragma once

#include <string>
#include <cstdint>

class User {
private:
    int64_t userId;
    std::string username;
    std::string passwordHash;
    std::string salt;

public:
    User();
    User(int64_t id, const std::string& name, const std::string& passHash, const std::string& saltValue);

    // Геттеры
    int64_t getUserId() const { return userId; }
    std::string getUsername() const { return username; }
    std::string getPasswordHash() const { return passwordHash; }
    std::string getSalt() const { return salt; }

    // Сеттеры
    void setUserId(int64_t id) { userId = id; }
    void setUsername(const std::string& name) { username = name; }
    void setPasswordHash(const std::string& hash) { passwordHash = hash; }
    void setSalt(const std::string& saltValue) { salt = saltValue; }

    // Проверка валидности
    bool isValid() const;
};
