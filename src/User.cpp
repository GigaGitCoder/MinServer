#include "User.h"

User::User() : userId(-1), username(""), passwordHash(""), salt("") {}

User::User(int64_t id, const std::string& name, const std::string& passHash, const std::string& saltValue)
    : userId(id), username(name), passwordHash(passHash), salt(saltValue) {}

bool User::isValid() const {
    return userId > 0 && !username.empty() && !passwordHash.empty() && !salt.empty();
}
