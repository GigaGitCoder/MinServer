#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Python Messenger Client для тестирования C++ сервера
Поддерживает все типы пакетов с debug-отображением
"""

import socket
import struct
import sys
import time
import threading
from datetime import datetime
from enum import IntEnum
from typing import Optional, List, Tuple
from dataclasses import dataclass


# ============== ЦВЕТНОЙ ВЫВОД ==============
class Colors:
    RESET = '\033[0m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    GRAY = '\033[90m'


def log(message: str, color: str = Colors.WHITE):
    """Вывод лога с цветом и временем"""
    timestamp = datetime.now().strftime("%d.%m.%Y | %H:%M:%S.%f")[:-3]
    print(f"{Colors.GRAY}[{timestamp}]{Colors.RESET} {color}{message}{Colors.RESET}")


def log_debug(message: str):
    log(f"[DEBUG] {message}", Colors.CYAN)


def log_info(message: str):
    log(f"[INFO] {message}", Colors.BLUE)


def log_success(message: str):
    log(f"[SUCCESS] {message}", Colors.GREEN)


def log_warning(message: str):
    log(f"[WARNING] {message}", Colors.YELLOW)


def log_error(message: str):
    log(f"[ERROR] {message}", Colors.RED)


def log_packet(direction: str, packet_type: str, data: str):
    """Вывод информации о пакете"""
    arrow = "→" if direction == "SEND" else "←"
    color = Colors.MAGENTA if direction == "SEND" else Colors.GREEN
    log(f"{arrow} {direction} [{packet_type}] {data}", color)


# ============== ТИПЫ ПАКЕТОВ ==============
class PacketType(IntEnum):
    PACKET_ERROR = 0x0001
    REGISTER_REQUEST = 0x0002
    REGISTER_RESPONSE = 0x0003
    LOGIN_REQUEST = 0x0004
    LOGIN_RESPONSE = 0x0005
    AUTH_TOKEN_REQUEST = 0x0006
    AUTH_RESPONSE = 0x0007
    SEND_MESSAGE = 0x0008
    RECEIVE_MESSAGE = 0x0009
    SEARCH_USERS_REQUEST = 0x0010
    SEARCH_USERS_RESPONSE = 0x0011
    LOGOUT_REQUEST = 0x0012
    USER_STATUS_UPDATE = 0x0013
    HISTORY_REQUEST = 0x000A
    HISTORY_RESPONSE = 0x000B
    USER_LIST_REQUEST = 0x000C
    USER_LIST_RESPONSE = 0x000D
    PING = 0x000E
    PONG = 0x000F


class ErrorCode(IntEnum):
    AUTH_FAILED = 1000
    USER_EXISTS = 1001
    INVALID_TOKEN = 1002
    UNAUTHORIZED = 1003
    USER_NOT_FOUND = 1004
    DATABASE_ERROR = 2000
    INVALID_PACKET = 3000


# ============== PACKET BUILDER ==============
class PacketBuilder:
    """Построитель пакетов для сервера"""
    
    def __init__(self, packet_type: PacketType):
        self.packet_type = packet_type
        self.buffer = bytearray()
    
    def add_uint8(self, value: int) -> 'PacketBuilder':
        self.buffer += struct.pack('<B', value)
        return self
    
    def add_uint16(self, value: int) -> 'PacketBuilder':
        self.buffer += struct.pack('<H', value)
        return self
    
    def add_uint32(self, value: int) -> 'PacketBuilder':
        self.buffer += struct.pack('<I', value)
        return self
    
    def add_int64(self, value: int) -> 'PacketBuilder':
        self.buffer += struct.pack('<q', value)
        return self
    
    def add_string(self, value: str) -> 'PacketBuilder':
        encoded = value.encode('utf-8')
        self.add_uint16(len(encoded))
        self.buffer += encoded
        return self
    
    def build(self) -> bytes:
        """Собрать финальный пакет с заголовком"""
        # 4 байта length + 2 байта packet_id + данные
        total_length = 6 + len(self.buffer)
        header = struct.pack('<I', total_length) + struct.pack('<H', self.packet_type)
        return header + bytes(self.buffer)


# ============== PACKET PARSER ==============
class PacketParser:
    """Парсер пакетов от сервера"""
    
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0
    
    def read_uint8(self) -> int:
        value = struct.unpack_from('<B', self.data, self.offset)[0]
        self.offset += 1
        return value
    
    def read_uint16(self) -> int:
        value = struct.unpack_from('<H', self.data, self.offset)[0]
        self.offset += 2
        return value
    
    def read_uint32(self) -> int:
        value = struct.unpack_from('<I', self.data, self.offset)[0]
        self.offset += 4
        return value
    
    def read_int64(self) -> int:
        value = struct.unpack_from('<q', self.data, self.offset)[0]
        self.offset += 8
        return value
    
    def read_string(self) -> str:
        length = self.read_uint16()
        value = self.data[self.offset:self.offset + length].decode('utf-8')
        self.offset += length
        return value
    
    def skip_header(self):
        """Пропустить заголовок (4 байта length + 2 байта packet_id)"""
        self.offset = 6


# ============== MESSENGER CLIENT ==============
@dataclass
class UserInfo:
    user_id: int
    username: str
    is_online: bool


@dataclass
class MessageInfo:
    message_id: int
    timestamp: int
    sender_id: int
    recipient_id: int
    body: str


class MessengerClient:
    def __init__(self, host: str = "127.0.0.1", port: int = 8080):
        self.host = host
        self.port = port
        self.socket: Optional[socket.socket] = None
        self.connected = False
        self.authenticated = False
        self.user_id: Optional[int] = None
        self.username: Optional[str] = None
        self.token: Optional[str] = None
        self.receive_thread: Optional[threading.Thread] = None
        self.running = False
    
    def connect(self) -> bool:
        """Подключение к серверу"""
        try:
            log_info(f"Подключение к {self.host}:{self.port}...")
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            self.connected = True
            self.running = True
            
            # Запуск потока приема
            self.receive_thread = threading.Thread(target=self._receive_loop, daemon=True)
            self.receive_thread.start()
            
            log_success(f"Подключено к серверу {self.host}:{self.port}")
            return True
        except Exception as e:
            log_error(f"Ошибка подключения: {e}")
            return False
    
    def disconnect(self):
        """Отключение от сервера"""
        self.running = False
        self.connected = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        log_info("Отключено от сервера")
    
    def _send_packet(self, data: bytes):
        """Отправка пакета на сервер"""
        if not self.connected or not self.socket:
            log_error("Не подключено к серверу")
            return
        
        try:
            self.socket.sendall(data)
        except Exception as e:
            log_error(f"Ошибка отправки: {e}")
            self.disconnect()
    
    def _receive_loop(self):
        """Поток приема пакетов"""
        buffer = bytearray()
        
        while self.running and self.connected:
            try:
                chunk = self.socket.recv(4096)
                if not chunk:
                    log_warning("Сервер закрыл соединение")
                    self.disconnect()
                    break
                
                buffer.extend(chunk)
                
                # Обработка пакетов в буфере
                while len(buffer) >= 6:
                    # Читаем длину пакета
                    length = struct.unpack_from('<I', buffer, 0)[0]
                    
                    if len(buffer) < length:
                        break  # Ждем остальные данные
                    
                    # Извлекаем пакет
                    packet_data = bytes(buffer[:length])
                    buffer = buffer[length:]
                    
                    # Обрабатываем пакет
                    self._handle_packet(packet_data)
            
            except Exception as e:
                if self.running:
                    log_error(f"Ошибка приема: {e}")
                break
    
    def _handle_packet(self, data: bytes):
        """Обработка полученного пакета"""
        parser = PacketParser(data)
        length = parser.read_uint32()
        packet_type = PacketType(parser.read_uint16())
        
        # Обработка по типу
        if packet_type == PacketType.PACKET_ERROR:
            self._handle_error(parser)
        elif packet_type == PacketType.REGISTER_RESPONSE:
            self._handle_register_response(parser)
        elif packet_type == PacketType.LOGIN_RESPONSE:
            self._handle_login_response(parser)
        elif packet_type == PacketType.AUTH_RESPONSE:
            self._handle_auth_response(parser)
        elif packet_type == PacketType.RECEIVE_MESSAGE:
            self._handle_receive_message(parser)
        elif packet_type == PacketType.HISTORY_RESPONSE:
            self._handle_history_response(parser)
        elif packet_type == PacketType.USER_LIST_RESPONSE:
            self._handle_user_list_response(parser)
        elif packet_type == PacketType.SEARCH_USERS_RESPONSE:
            self._handle_search_users_response(parser)
        elif packet_type == PacketType.USER_STATUS_UPDATE:
            self._handle_user_status_update(parser)
        elif packet_type == PacketType.PONG:
            self._handle_pong()
        else:
            log_warning(f"Неизвестный тип пакета: {packet_type}")
    
    def _handle_error(self, parser: PacketParser):
        error_code = ErrorCode(parser.read_uint16())
        error_message = parser.read_string()
        log_packet("RECV", "ERROR", f"Code={error_code.name}, Message='{error_message}'")
    
    def _handle_register_response(self, parser: PacketParser):
        success = parser.read_uint8() == 1
        user_id = parser.read_int64()
        token = parser.read_string()
        
        log_packet("RECV", "REGISTER_RESPONSE", 
                   f"Success={success}, UserId={user_id}, Token='{token[:20]}...'")
        
        if success:
            self.authenticated = True
            self.user_id = user_id
            self.token = token
            log_success(f"Регистрация успешна! User ID: {user_id}")
    
    def _handle_login_response(self, parser: PacketParser):
        success = parser.read_uint8() == 1
        user_id = parser.read_int64()
        token = parser.read_string()
        
        log_packet("RECV", "LOGIN_RESPONSE", 
                   f"Success={success}, UserId={user_id}, Token='{token[:20]}...'")
        
        if success:
            self.authenticated = True
            self.user_id = user_id
            self.token = token
            log_success(f"Вход выполнен! User ID: {user_id}")
    
    def _handle_auth_response(self, parser: PacketParser):
        success = parser.read_uint8() == 1
        user_id = parser.read_int64()
        
        log_packet("RECV", "AUTH_RESPONSE", f"Success={success}, UserId={user_id}")
        
        if success:
            self.authenticated = True
            self.user_id = user_id
            log_success(f"Аутентификация успешна! User ID: {user_id}")
    
    def _handle_receive_message(self, parser: PacketParser):
        msg_id = parser.read_int64()
        timestamp = parser.read_int64()
        sender_id = parser.read_int64()
        recipient_id = parser.read_int64()
        body = parser.read_string()
        
        dt = datetime.fromtimestamp(timestamp / 1000.0).strftime("%Y-%m-%d %H:%M:%S")
        log_packet("RECV", "RECEIVE_MESSAGE", 
                   f"MsgId={msg_id}, From={sender_id}, To={recipient_id}, Time={dt}")
        log_info(f"💬 Сообщение от [{sender_id}]: {body}")
    
    def _handle_history_response(self, parser: PacketParser):
        count = parser.read_uint32()
        log_packet("RECV", "HISTORY_RESPONSE", f"Count={count}")
        
        messages = []
        for _ in range(count):
            msg_id = parser.read_int64()
            timestamp = parser.read_int64()
            sender_id = parser.read_int64()
            recipient_id = parser.read_int64()
            body = parser.read_string()
            messages.append(MessageInfo(msg_id, timestamp, sender_id, recipient_id, body))
        
        log_info(f"📜 История сообщений ({count}):")
        for msg in messages:
            dt = datetime.fromtimestamp(msg.timestamp / 1000.0).strftime("%Y-%m-%d %H:%M:%S")
            direction = "→" if msg.sender_id == self.user_id else "←"
            print(f"  {direction} [{dt}] {msg.sender_id} -> {msg.recipient_id}: {msg.body}")
    
    def _handle_user_list_response(self, parser: PacketParser):
        count = parser.read_uint32()
        log_packet("RECV", "USER_LIST_RESPONSE", f"Count={count}")
        
        users = []
        for _ in range(count):
            user_id = parser.read_int64()
            username = parser.read_string()
            is_online = parser.read_uint8() == 1
            users.append(UserInfo(user_id, username, is_online))
        
        log_info(f"👥 Список пользователей ({count}):")
        for user in users:
            status = "🟢" if user.is_online else "🔴"
            print(f"  {status} [{user.user_id}] {user.username}")
    
    def _handle_search_users_response(self, parser: PacketParser):
        count = parser.read_uint32()
        log_packet("RECV", "SEARCH_USERS_RESPONSE", f"Count={count}")
        
        users = []
        for _ in range(count):
            user_id = parser.read_int64()
            username = parser.read_string()
            is_online = parser.read_uint8() == 1
            users.append(UserInfo(user_id, username, is_online))
        
        log_info(f"🔍 Результаты поиска ({count}):")
        for user in users:
            status = "🟢" if user.is_online else "🔴"
            print(f"  {status} [{user.user_id}] {user.username}")
    
    def _handle_user_status_update(self, parser: PacketParser):
        user_id = parser.read_int64()
        is_online = parser.read_uint8() == 1
        status_text = "В сети" if is_online else "Не в сети"
        log_packet("RECV", "USER_STATUS_UPDATE", f"UserId={user_id}, Status={status_text}")
    
    def _handle_pong(self):
        log_packet("RECV", "PONG", "Pong received")
    
    # ============== API МЕТОДЫ ==============
    
    def register(self, username: str, password: str):
        """Регистрация нового пользователя"""
        packet = PacketBuilder(PacketType.REGISTER_REQUEST) \
            .add_string(username) \
            .add_string(password) \
            .build()
        
        log_packet("SEND", "REGISTER_REQUEST", f"Username='{username}'")
        self._send_packet(packet)
    
    def login(self, username: str, password: str):
        """Вход существующего пользователя"""
        packet = PacketBuilder(PacketType.LOGIN_REQUEST) \
            .add_string(username) \
            .add_string(password) \
            .build()
        
        log_packet("SEND", "LOGIN_REQUEST", f"Username='{username}'")
        self._send_packet(packet)
    
    def auth_with_token(self, token: str):
        """Аутентификация по токену"""
        packet = PacketBuilder(PacketType.AUTH_TOKEN_REQUEST) \
            .add_string(token) \
            .build()
        
        log_packet("SEND", "AUTH_TOKEN_REQUEST", f"Token='{token[:20]}...'")
        self._send_packet(packet)
    
    def send_message(self, recipient_id: int, message: str):
        """Отправка сообщения"""
        if not self.authenticated:
            log_error("Необходима аутентификация")
            return
        
        packet = PacketBuilder(PacketType.SEND_MESSAGE) \
            .add_int64(recipient_id) \
            .add_string(message) \
            .build()
        
        log_packet("SEND", "SEND_MESSAGE", f"To={recipient_id}, Message='{message}'")
        self._send_packet(packet)
    
    def request_history(self, peer_id: int, limit: int = 50):
        """Запрос истории с пользователем"""
        if not self.authenticated:
            log_error("Необходима аутентификация")
            return
        
        packet = PacketBuilder(PacketType.HISTORY_REQUEST) \
            .add_int64(peer_id) \
            .add_uint32(limit) \
            .build()
        
        log_packet("SEND", "HISTORY_REQUEST", f"PeerId={peer_id}, Limit={limit}")
        self._send_packet(packet)
    
    def request_user_list(self):
        """Запрос списка пользователей"""
        if not self.authenticated:
            log_error("Необходима аутентификация")
            return
        
        packet = PacketBuilder(PacketType.USER_LIST_REQUEST).build()
        log_packet("SEND", "USER_LIST_REQUEST", "")
        self._send_packet(packet)
    
    def search_users(self, query: str):
        """Поиск пользователей"""
        if not self.authenticated:
            log_error("Необходима аутентификация")
            return
        
        packet = PacketBuilder(PacketType.SEARCH_USERS_REQUEST) \
            .add_string(query) \
            .build()
        
        log_packet("SEND", "SEARCH_USERS_REQUEST", f"Query='{query}'")
        self._send_packet(packet)
    
    def ping(self):
        """Отправка PING"""
        packet = PacketBuilder(PacketType.PING).build()
        log_packet("SEND", "PING", "")
        self._send_packet(packet)
    
    def logout(self):
        """Выход из системы"""
        if not self.authenticated:
            log_error("Не аутентифицирован")
            return
        
        packet = PacketBuilder(PacketType.LOGOUT_REQUEST).build()
        log_packet("SEND", "LOGOUT_REQUEST", "")
        self._send_packet(packet)
        
        self.authenticated = False
        self.user_id = None
        self.token = None


# ============== ИНТЕРАКТИВНОЕ МЕНЮ ==============
def print_menu():
    print(f"\n{Colors.CYAN}{'='*60}")
    print("             MESSENGER CLIENT MENU")
    print(f"{'='*60}{Colors.RESET}")
    print(f"{Colors.YELLOW}Аутентификация:{Colors.RESET}")
    print("  1. Регистрация")
    print("  2. Вход")
    print("  3. Аутентификация по токену")
    print(f"\n{Colors.YELLOW}Операции с сообщениями:{Colors.RESET}")
    print("  4. Отправить сообщение")
    print("  5. Запросить историю")
    print(f"\n{Colors.YELLOW}Пользователи:{Colors.RESET}")
    print("  6. Список пользователей")
    print("  7. Поиск пользователей")
    print(f"\n{Colors.YELLOW}Прочее:{Colors.RESET}")
    print("  8. PING")
    print("  9. Выход (Logout)")
    print("  0. Закрыть клиент")
    print(f"{Colors.CYAN}{'='*60}{Colors.RESET}\n")


def interactive_mode(client: MessengerClient):
    """Интерактивный режим работы"""
    while client.connected:
        print_menu()
        
        choice = input(f"{Colors.GREEN}Выберите действие: {Colors.RESET}").strip()
        
        if choice == "1":
            username = input("Имя пользователя: ").strip()
            password = input("Пароль: ").strip()
            client.register(username, password)
            time.sleep(0.5)
        
        elif choice == "2":
            username = input("Имя пользователя: ").strip()
            password = input("Пароль: ").strip()
            client.login(username, password)
            time.sleep(0.5)
        
        elif choice == "3":
            token = input("Токен: ").strip()
            client.auth_with_token(token)
            time.sleep(0.5)
        
        elif choice == "4":
            recipient_id = int(input("ID получателя: ").strip())
            message = input("Сообщение: ").strip()
            client.send_message(recipient_id, message)
        
        elif choice == "5":
            peer_id = int(input("ID пользователя: ").strip())
            limit = int(input("Лимит сообщений (по умолчанию 50): ").strip() or "50")
            client.request_history(peer_id, limit)
            time.sleep(0.5)
        
        elif choice == "6":
            client.request_user_list()
            time.sleep(0.5)
        
        elif choice == "7":
            query = input("Поисковый запрос: ").strip()
            client.search_users(query)
            time.sleep(0.5)
        
        elif choice == "8":
            client.ping()
            time.sleep(0.3)
        
        elif choice == "9":
            client.logout()
            time.sleep(0.3)
        
        elif choice == "0":
            log_info("Закрытие клиента...")
            client.disconnect()
            break
        
        else:
            log_warning("Неверный выбор")


# ============== MAIN ==============
def main():
    print(f"{Colors.MAGENTA}")
    print("╔════════════════════════════════════════════════════════════╗")
    print("║           Python Messenger Client - Debug Edition          ║")
    print("║                 Тестирование C++ сервера                   ║")
    print("╚════════════════════════════════════════════════════════════╝")
    print(f"{Colors.RESET}\n")
    
    host = "127.0.0.1" # or input(f"IP сервера (по умолчанию 127.0.0.1): ").strip()
    port_str = "5555" # or input(f"Порт сервера (по умолчанию 5555): ").strip()
    port = int(port_str)
    
    client = MessengerClient(host, port)
    
    if not client.connect():
        log_error("Не удалось подключиться к серверу")
        return
    
    try:
        interactive_mode(client)
    except KeyboardInterrupt:
        log_info("\nПрервано пользователем")
    except Exception as e:
        log_error(f"Ошибка: {e}")
        import traceback
        traceback.print_exc()
    finally:
        client.disconnect()
    
    log_info("Клиент завершен")


if __name__ == "__main__":
    main()
