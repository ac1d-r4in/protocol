#pragma once

#include "includes.h"
#include <sstream>

#define BUFFER_SIZE 2048

// генерация сидов для инициализации XMSS
std::vector<unsigned char> generate256BitNumber() {
    std::vector<unsigned char> number(32); // 256 бит = 32 байта
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<unsigned int> dis(0, 255);

    for (auto& byte : number) {
        byte = static_cast<unsigned char>(dis(gen));
    }
    return number;
}

XMSS createNewXMSSObject() {
    std::vector<unsigned char> sign1 = generate256BitNumber();
    std::vector<unsigned char> sign2 = generate256BitNumber();

    return XMSS(sign1, sign2);
}

std::string u8ArrayToString(const u8* array, size_t size) {
    std::ostringstream oss;
    for (size_t i = 0; i < size; ++i) {
        // Форматируем каждый байт в виде двух шестнадцатеричных символов
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(array[i]);
    }
    return oss.str();
}

#include <string>
#include <cstring> // Для memcpy

typedef unsigned char u8;

// Преобразование std::string в u8*
u8* stringToU8Array(const std::string& str) {
    size_t size = str.size();
    u8* u8Array = new u8[size + 1]; // Выделяем память (включая нуль-терминатор)
    std::memcpy(u8Array, str.c_str(), size); // Копируем данные
    u8Array[size] = '\0'; // Завершаем нуль-терминатором
    return u8Array;
}

#include <iostream>
#include <iomanip>

void print_hex(const char* label, const unsigned char* data, size_t size) {
    std::cout << label << ": ";
    for (size_t i = 0; i < size; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    }
    std::cout << std::dec << std::endl; // Возвращаем формат вывода обратно в десятичный
}

// подпись и отправка сообщения
void sendSigned(int socket, const u8* message, XMSS &xmss) {

    std::size_t messageLen = CURVE25519_KEY_LEN;

    // Получаем публичный ключ и подпись
    std::vector<unsigned char> publicKey = xmss.getPublicKey();
    std::vector<unsigned char> signature = xmss.getSignature(std::vector<unsigned char>(message, message + messageLen));

    // Конвертируем размеры в сетевой порядок
    uint32_t msgLen = htonl(static_cast<uint32_t>(messageLen));
    uint32_t sigLen = htonl(static_cast<uint32_t>(signature.size()));
    uint32_t pkLen = htonl(static_cast<uint32_t>(publicKey.size()));

    // Создаем буфер для отправки
    std::vector<unsigned char> buffer;
    buffer.insert(buffer.end(), reinterpret_cast<unsigned char*>(&msgLen), reinterpret_cast<unsigned char*>(&msgLen) + sizeof(msgLen));
    buffer.insert(buffer.end(), message, message + messageLen);
    buffer.insert(buffer.end(), reinterpret_cast<unsigned char*>(&sigLen), reinterpret_cast<unsigned char*>(&sigLen) + sizeof(sigLen));
    buffer.insert(buffer.end(), signature.begin(), signature.end());
    buffer.insert(buffer.end(), reinterpret_cast<unsigned char*>(&pkLen), reinterpret_cast<unsigned char*>(&pkLen) + sizeof(pkLen));
    buffer.insert(buffer.end(), publicKey.begin(), publicKey.end());

    // Отправляем буфер по сокету
    send(socket, buffer.data(), buffer.size(), 0);
}

// получение и валидация сообщения
bool receiveSigned(int socket, u8* message, int* returnCode) {
    int size = BUFFER_SIZE;
    char* buffer = new char[size];

    // Получаем данные из сокета
    ssize_t bytesRead = recv(socket, buffer, size, 0);
    if (bytesRead < 0) {
        delete[] buffer;
        *returnCode = 1; // Ошибка при чтении
        return false;
    }
    if (bytesRead == 0) {
        delete[] buffer;
        *returnCode = 2; // Подключение закрыто
        return false;
    }

    // Извлекаем длину сообщения
    uint32_t msgLen = ntohl(*reinterpret_cast<uint32_t*>(buffer));
    if (msgLen != 32) {
        delete[] buffer;
        *returnCode = 4; // Неверная длина сообщения
        return false;
    }

    // Копируем сообщение в u8[32]
    std::memcpy(message, buffer + 4, 32);

    // Извлекаем длину подписи и саму подпись
    uint32_t sigLen = ntohl(*reinterpret_cast<uint32_t*>(buffer + 4 + msgLen));
    std::vector<unsigned char> signature(buffer + 4 + msgLen + 4, buffer + 4 + msgLen + 4 + sigLen);

    // Извлекаем длину публичного ключа и сам публичный ключ
    uint32_t pkLen = ntohl(*reinterpret_cast<uint32_t*>(buffer + 4 + msgLen + 4 + sigLen));
    std::vector<unsigned char> publicKey(buffer + 4 + msgLen + 4 + sigLen + 4, buffer + 4 + msgLen + 4 + sigLen + 4 + pkLen);

    // Проверяем подпись
    std::vector<unsigned char> messageVec(message, message + 32);
    bool isValid = XMSS::Verify(messageVec, signature, publicKey);
    if (!isValid) {
        delete[] buffer;
        *returnCode = 3; // Неверная подпись
        return false;
    }

    delete[] buffer;
    return true;
}