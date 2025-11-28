#include "Database.h"
#include <chrono>
#include <sstream>
#include <iomanip>
#include <random>
#include <cstring>
#include <openssl/sha.h> // Используем OpenSSL для криптографии


using namespace std;

Database::Database() : db(nullptr) {}

Database::~Database() {
    close();
}

bool Database::open(const std::string& dbPath) {
    lock_guard<mutex> lk(dbMutex);
    if (sqlite3_open(dbPath.c_str(), &db) != SQLITE_OK) {
        return false;
    }
    return true;
}

void Database::close() {
    lock_guard<mutex> lk(dbMutex);
    if (db) {
        sqlite3_close(db);
        db = nullptr;
    }
}

bool Database::initSchema() {
    // 1. users: хранит логины и хэши паролей
    // 2. sessions: хранит активные токены входа
    // 3. messages: хранит историю переписки
    const char* sql = R"(
        CREATE TABLE IF NOT EXISTS users(
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            pass_hash TEXT NOT NULL,
            salt TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions(
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            ts INTEGER NOT NULL,
            expires INTEGER NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(user_id)
        );
        CREATE TABLE IF NOT EXISTS messages(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts INTEGER NOT NULL,
            sender_id INTEGER NOT NULL,
            recipient_id INTEGER NOT NULL,
            body TEXT NOT NULL,
            FOREIGN KEY(sender_id) REFERENCES users(user_id),
            FOREIGN KEY(recipient_id) REFERENCES users(user_id)
        );
    )";

    char* err = nullptr;
    lock_guard<mutex> lk(dbMutex);
    if (sqlite3_exec(db, sql, nullptr, nullptr, &err) != SQLITE_OK) {
        if (err) sqlite3_free(err);
        return false;
    }
    return true;
}

int64_t Database::nowEpoch() {
    using namespace chrono;
    return duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
}

// v1.4
string Database::genSalt() {
    // Генерируем 16 байт случайных данных для соли
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(0, 255);
    stringstream ss;
    for (int i = 0; i < 16; i++) {
        ss << hex << setw(2) << setfill('0') << dis(gen);
    }
    return ss.str();
}


string Database::genToken(int64_t userId) {
    // Формируем уникальный токен: префикс + ID юзера + время + случайные байты
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(0, 255);
    stringstream ss;
    ss << "token_" << userId << "_" << nowEpoch() << "_";
    for (int i = 0; i < 16; i++) {
        ss << hex << setw(2) << setfill('0') << dis(gen);
    }
    return ss.str();
}

//v 1.4
string Database::sha1(const string& input) {
    // Используем SHA256 для хэширования
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)input.c_str(), input.size(), hash);
    
    stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }
    return ss.str();
}

int64_t Database::getUserId(const string& username) {
    const char* sql = "SELECT user_id FROM users WHERE username=?1 LIMIT 1;";
    sqlite3_stmt* st = nullptr;
    lock_guard<mutex> lk(dbMutex);
    if (sqlite3_prepare_v2(db, sql, -1, &st, nullptr) != SQLITE_OK) return -1;
    sqlite3_bind_text(st, 1, username.c_str(), -1, SQLITE_TRANSIENT);
    int64_t user_id = -1;
    if (sqlite3_step(st) == SQLITE_ROW) {
        user_id = sqlite3_column_int64(st, 0);
    }
    sqlite3_finalize(st);
    return user_id;
}

string Database::getUsername(int64_t userId) {
    const char* sql = "SELECT username FROM users WHERE user_id=?1 LIMIT 1;";
    sqlite3_stmt* st = nullptr;
    lock_guard<mutex> lk(dbMutex);
    if (sqlite3_prepare_v2(db, sql, -1, &st, nullptr) != SQLITE_OK) return "";
    sqlite3_bind_int64(st, 1, userId);
    string username;
    if (sqlite3_step(st) == SQLITE_ROW) {
        const unsigned char* u = sqlite3_column_text(st, 0);
        if (u) username = reinterpret_cast<const char*>(u);
    }
    sqlite3_finalize(st);
    return username;
}

bool Database::userExists(const string& username) {
    return getUserId(username) != -1;
}

bool Database::createUser(const string& username, const string& password) {
    if (username.empty() || password.empty()) return false;
    string salt = genSalt();
    string pass_hash = sha1(salt + password);
    const char* sql = "INSERT INTO users(username, pass_hash, salt) VALUES(?1,?2,?3);";
    sqlite3_stmt* st = nullptr;
    lock_guard<mutex> lk(dbMutex);
    if (sqlite3_prepare_v2(db, sql, -1, &st, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_text(st, 1, username.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, pass_hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, salt.c_str(), -1, SQLITE_TRANSIENT);
    bool ok = (sqlite3_step(st) == SQLITE_DONE);
    sqlite3_finalize(st);
    return ok;
}

bool Database::validatePassword(const string& username, const string& password) {
    const char* sql = "SELECT pass_hash, salt FROM users WHERE username=?1;";
    sqlite3_stmt* st = nullptr;
    string ph, salt;

    lock_guard<mutex> lk(dbMutex);
    if (sqlite3_prepare_v2(db, sql, -1, &st, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_text(st, 1, username.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        const unsigned char* cph = sqlite3_column_text(st, 0);
        const unsigned char* cs = sqlite3_column_text(st, 1);
        ph = cph ? reinterpret_cast<const char*>(cph) : "";
        salt = cs ? reinterpret_cast<const char*>(cs) : "";
    }
    sqlite3_finalize(st);

    if (ph.empty() || salt.empty()) return false;
    string calc = sha1(salt + password);
    return calc == ph;
}

vector<pair<int64_t, string>> Database::searchUsers(const string& query) {
    vector<pair<int64_t, string>> results;
    // Используем LIKE для нечеткого поиска
    const char* sql = "SELECT user_id, username FROM users WHERE username LIKE ?1 LIMIT 20;";
    sqlite3_stmt* st = nullptr;
    string searchPattern = "%" + query + "%"; // Добавляем % для поиска подстроки
    lock_guard<mutex> lk(dbMutex);
    if (sqlite3_prepare_v2(db, sql, -1, &st, nullptr) != SQLITE_OK) return results;
    sqlite3_bind_text(st, 1, searchPattern.c_str(), -1, SQLITE_TRANSIENT);
    while (sqlite3_step(st) == SQLITE_ROW) {
        int64_t uid = sqlite3_column_int64(st, 0);
        const unsigned char* u = sqlite3_column_text(st, 1);
        if (u) results.push_back({ uid, reinterpret_cast<const char*>(u) });
    }
    sqlite3_finalize(st);
    return results;
}

vector<pair<int64_t, string>> Database::getAllUsers() {
    vector<pair<int64_t, string>> results;
    const char* sql = "SELECT user_id, username FROM users ORDER BY username;";
    sqlite3_stmt* st = nullptr;
    lock_guard<mutex> lk(dbMutex);
    if (sqlite3_prepare_v2(db, sql, -1, &st, nullptr) != SQLITE_OK) return results;
    while (sqlite3_step(st) == SQLITE_ROW) {
        int64_t uid = sqlite3_column_int64(st, 0);
        const unsigned char* u = sqlite3_column_text(st, 1);
        if (u) results.push_back({ uid, reinterpret_cast<const char*>(u) });
    }
    sqlite3_finalize(st);
    return results;
}

string Database::issueToken(int64_t userId, int64_t ttlSec) {
    string token = genToken(userId);
    int64_t ts = nowEpoch();
    int64_t exp = ts + ttlSec;
    // Используем INSERT OR REPLACE, чтобы обновить старую запись, если вдруг она есть
    const char* sql = "INSERT OR REPLACE INTO sessions(token, user_id, ts, expires) VALUES(?1,?2,?3,?4);";
    sqlite3_stmt* st = nullptr;
    lock_guard<mutex> lk(dbMutex);
    if (sqlite3_prepare_v2(db, sql, -1, &st, nullptr) != SQLITE_OK) return "";
    sqlite3_bind_text(st, 1, token.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, userId);
    sqlite3_bind_int64(st, 3, ts);
    sqlite3_bind_int64(st, 4, exp);
    if (sqlite3_step(st) != SQLITE_DONE) {
        sqlite3_finalize(st);
        return "";
    }
    sqlite3_finalize(st);
    return token;
}

bool Database::validateToken(const string& token, int64_t& userIdOut) {
    const char* sql = "SELECT user_id, expires FROM sessions WHERE token=?1;";
    sqlite3_stmt* st = nullptr;
    int64_t now = nowEpoch();


    lock_guard<mutex> lk(dbMutex);
    if (sqlite3_prepare_v2(db, sql, -1, &st, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_text(st, 1, token.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        userIdOut = sqlite3_column_int64(st, 0);
        int64_t exp = sqlite3_column_int64(st, 1);
        sqlite3_finalize(st);
        if (exp < now) {
            return false;
        }
    } else {
        sqlite3_finalize(st);
        return false;
    }

    // Продлеваем токен
    const char* upd = "UPDATE sessions SET expires=?1 WHERE token=?2;";
    sqlite3_stmt* su = nullptr;
    {
        lock_guard<mutex> lk(dbMutex);
        if (sqlite3_prepare_v2(db, upd, -1, &su, nullptr) == SQLITE_OK) {
            sqlite3_bind_int64(su, 1, now + 24 * 3600);
            sqlite3_bind_text(su, 2, token.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(su);
            sqlite3_finalize(su);
        }
    }
    return true;
}

string Database::refreshToken(const string& oldToken) {
    int64_t user_id;
    if (!validateToken(oldToken, user_id)) {
        return "";
    }

    {
        lock_guard<mutex> lk(dbMutex);
        const char* del = "DELETE FROM sessions WHERE token=?1;";
        sqlite3_stmt* st = nullptr;
        if (sqlite3_prepare_v2(db, del, -1, &st, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(st, 1, oldToken.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(st);
            sqlite3_finalize(st);
        }
    }

    return issueToken(user_id);
}

bool Database::revokeToken(const string& token) {
    lock_guard<mutex> lk(dbMutex);
    const char* sql = "DELETE FROM sessions WHERE token=?1;";
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &st, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_text(st, 1, token.c_str(), -1, SQLITE_TRANSIENT);
    bool ok = (sqlite3_step(st) == SQLITE_DONE);
    sqlite3_finalize(st);
    return ok;
}

void Database::cleanExpiredTokens() {
    lock_guard<mutex> lk(dbMutex);
    int64_t now = nowEpoch();
    string sql = "DELETE FROM sessions WHERE expires < " + to_string(now) + ";";
    char* err = nullptr;
    sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &err);
    if (err) sqlite3_free(err);
}

// v 1.3
int64_t Database::saveMessage(int64_t senderId, int64_t recipientId, const std::string& body) {
    const char* sql = "INSERT INTO messages(ts, sender_id, recipient_id, body) VALUES(?,?,?,?);";
    sqlite3_stmt* stmt = nullptr;
    lock_guard<mutex> lk(dbMutex);
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return -1;
    }
    
    sqlite3_bind_int64(stmt, 1, nowEpoch());
    sqlite3_bind_int64(stmt, 2, senderId);
    sqlite3_bind_int64(stmt, 3, recipientId);
    sqlite3_bind_text(stmt, 4, body.c_str(), -1, SQLITE_TRANSIENT);
    
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return -1;
    }
    
    // Получаем ID только что вставленной строки (сообщения)
    int64_t messageId = sqlite3_last_insert_rowid(db);
    sqlite3_finalize(stmt);
    return messageId;
}



vector<Message> Database::getHistory(int64_t userId) {
    vector<Message> messages;
    const char* sql = "SELECT id, ts, sender_id, recipient_id, body FROM messages "
                      "WHERE sender_id = ?1 OR recipient_id = ?1 ORDER BY ts ASC;";
    sqlite3_stmt* stmt = nullptr;
    lock_guard<mutex> lk(dbMutex);
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return messages;
    }
    sqlite3_bind_int64(stmt, 1, userId);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        int64_t id = sqlite3_column_int64(stmt, 0);
        int64_t ts = sqlite3_column_int64(stmt, 1);
        int64_t sender_id = sqlite3_column_int64(stmt, 2);
        int64_t recipient_id = sqlite3_column_int64(stmt, 3);
        const unsigned char* body = sqlite3_column_text(stmt, 4);
        string bodyStr = body ? reinterpret_cast<const char*>(body) : "";
        messages.emplace_back(id, ts, sender_id, recipient_id, bodyStr);
    }
    sqlite3_finalize(stmt);
    return messages;
}

vector<Message> Database::getHistoryWithUser(int64_t userId, int64_t peerId, uint32_t limit) {
    vector<Message> messages;
    string sql = "SELECT id, ts, sender_id, recipient_id, body FROM messages "
                 "WHERE (sender_id = ?1 AND recipient_id = ?2) OR (sender_id = ?2 AND recipient_id = ?1) "
                 "ORDER BY ts ASC";
    if (limit > 0) {
        sql += " LIMIT " + to_string(limit);
    }
    sql += ";";

    sqlite3_stmt* stmt = nullptr;
    lock_guard<mutex> lk(dbMutex);
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        return messages;
    }
    sqlite3_bind_int64(stmt, 1, userId);
    sqlite3_bind_int64(stmt, 2, peerId);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        int64_t id = sqlite3_column_int64(stmt, 0);
        int64_t ts = sqlite3_column_int64(stmt, 1);
        int64_t sender_id = sqlite3_column_int64(stmt, 2);
        int64_t recipient_id = sqlite3_column_int64(stmt, 3);
        const unsigned char* body = sqlite3_column_text(stmt, 4);
        string bodyStr = body ? reinterpret_cast<const char*>(body) : "";
        messages.emplace_back(id, ts, sender_id, recipient_id, bodyStr);
    }
    sqlite3_finalize(stmt);
    return messages;
}

vector<int64_t> Database::getPeers(int64_t userId) {
    vector<int64_t> peers;
    // 1. Берем всех, кому МЫ писали.
    // 2. Объединяем (UNION) со всеми, кто писал НАМ.
    // 3. Исключаем самого себя (на всякий случай) и убираем дубликаты (DISTINCT).
    const char* sql = "SELECT DISTINCT peer_id FROM ("
                      "SELECT sender_id AS peer_id FROM messages WHERE recipient_id = ?1 "
                      "UNION "
                      "SELECT recipient_id AS peer_id FROM messages WHERE sender_id = ?1"
                      ") WHERE peer_id <> ?1 ORDER BY peer_id;";
    sqlite3_stmt* stmt = nullptr;
    lock_guard<mutex> lk(dbMutex);
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return peers;
    }
    sqlite3_bind_int64(stmt, 1, userId);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        int64_t peer_id = sqlite3_column_int64(stmt, 0);
        peers.push_back(peer_id);
    }
    sqlite3_finalize(stmt);
    return peers;
}

// v1.3
int64_t Database::getLastMessageId() {
    lock_guard<mutex> lk(dbMutex);
    int64_t lastId = sqlite3_last_insert_rowid(db);
    return lastId;
}
