#pragma once

#include "User.h"
#include "Message.h"
#include <string>
#include <vector>
#include <mutex>

// Используем "C" для корректного подключения библиотеки SQLite, так как она написана на C
extern "C" {
#include "sqlite3.h"
}

class Database {
private:
    sqlite3* db;         // Указатель на подключение к базе данных SQLite
    std::mutex dbMutex;  // Мьютекс для защиты базы данных от одновременного доступа из разных потоков

public:
    Database();
    ~Database();

    // --- Управление подключением ---

    // Открывает файл базы данных по указанному пути.
    // Если файла нет, SQLite создаст его.
    bool open(const std::string& dbPath);

    // Закрывает соединение с базой данных и освобождает память.
    void close();

    // Создает необходимые таблицы (users, sessions, messages), если они еще не существуют.
    // Эту функцию нужно вызывать один раз при запуске сервера.
    bool initSchema();

    // --- Работа с пользователями ---

    // Ищет ID пользователя по его логину (username). Возвращает -1, если не найден.
    int64_t getUserId(const std::string& username);

    // Получает текстовое имя пользователя по его числовому ID.
    std::string getUsername(int64_t userId);

    // Проверяет, зарегистрирован ли уже пользователь с таким именем.
    bool userExists(const std::string& username);

    // Создает нового пользователя: генерирует соль, хэширует пароль и сохраняет в БД.
    bool createUser(const std::string& username, const std::string& password);

    // Проверяет правильность введенного пароля при входе.
    // Сравнивает хэш введенного пароля с хэшем, сохраненным в базе.
    bool validatePassword(const std::string& username, const std::string& password);

    // Поиск пользователей по части имени (например, "al" найдет "alex" и "alice").
    std::vector<std::pair<int64_t, std::string>> searchUsers(const std::string& query);

    // Возвращает список вообще всех зарегистрированных пользователей.
    std::vector<std::pair<int64_t, std::string>> getAllUsers();

    // --- Работа с сессиями (авторизация) ---

    // Создает новый токен доступа для пользователя.
    // Токен позволяет клиенту делать запросы без постоянной отправки пароля.
    // ttlSec - время жизни токена в секундах (по умолчанию 24 часа).
    std::string issueToken(int64_t userId, int64_t ttlSec = 24 * 3600);

    // Проверяет, действителен ли токен.
    // Если токен валиден, функция автоматически продлевает его срок действия.
    // userIdOut заполняется ID пользователя, которому принадлежит токен.
    bool validateToken(const std::string& token, int64_t& userIdOut);

    // Заменяет старый токен на новый (например, если старый скоро истечет).
    std::string refreshToken(const std::string& oldToken);

    // Удаляет токен из базы (используется при выходе из аккаунта - Logout).
    bool revokeToken(const std::string& token);

    // Удаляет из базы все просроченные токены, чтобы не занимать место.
    void cleanExpiredTokens();

    // --- Работа с сообщениями ---

    // Сохраняет новое сообщение в базу данных.
    // Возвращает уникальный ID созданного сообщения.
    int64_t saveMessage(int64_t senderId, int64_t recipientId, const std::string& body);

    // Возвращает ID последнего добавленного сообщения (системная функция).
    int64_t getLastMessageId(); // v1.3

    // Получает полную историю сообщений пользователя (все чаты вперемешку).
    std::vector<Message> getHistory(int64_t userId);

    // Получает историю переписки конкретно между двумя пользователями (диалог).
    // limit позволяет загрузить только последние N сообщений.
    std::vector<Message> getHistoryWithUser(int64_t userId, int64_t peerId, uint32_t limit = 0);

    // Возвращает список ID пользователей, с которыми у текущего юзера есть диалоги ("Список контактов").
    std::vector<int64_t> getPeers(int64_t userId);

private:
    // Вспомогательная функция: возвращает текущее время в секундах (Unix timestamp).
    static int64_t nowEpoch();

    // Генерирует случайную строку ("соль") для усиления безопасности паролей.
    static std::string genSalt();

    // Генерирует уникальную строку токена.
    static std::string genToken(int64_t userId);

    // Вычисляет SHA-256 хэш от строки (название sha1 оставлено для совместимости, но внутри SHA256).
    static std::string sha1(const std::string& input);
};
