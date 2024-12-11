#pragma once

#include "includes.h"

#define BUFFER_SIZE 2048

// генерация сидов для инициализации XMSS
std::vector<uint8_t> generate256BitNumber() {
    std::vector<uint8_t> number(32); // 256 бит = 32 байта
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<unsigned int> dis(0, 255);

    for (auto& byte : number) {
        byte = static_cast<uint8_t>(dis(gen));
    }
    return number;
}

XMSS createNewXMSSObject() {
    std::vector<uint8_t> sign1 = generate256BitNumber();
    std::vector<uint8_t> sign2 = generate256BitNumber();

    return XMSS(sign1, sign2);
}

void print_hex(const char* label, const uint8_t* data, size_t size) {
    std::cout << label << ": ";
    for (size_t i = 0; i < size; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    }
    std::cout << std::dec << std::endl; // Возвращаем формат вывода обратно в десятичный
}

// подпись и отправка сообщения
void sendSignedKey(int socket, const uint8_t* message, XMSS &xmss) {

    std::size_t messageLen = CURVE25519_KEY_LEN;

    std::vector<uint8_t> publicKey = xmss.getPublicKey();
    std::vector<uint8_t> signature = xmss.getSignature(std::vector<uint8_t>(message, message + messageLen));

    // Конвертируем размеры в сетевой порядок
    uint32_t msgLen = htonl(static_cast<uint32_t>(messageLen));
    uint32_t sigLen = htonl(static_cast<uint32_t>(signature.size()));
    uint32_t pkLen = htonl(static_cast<uint32_t>(publicKey.size()));

    std::vector<uint8_t> buffer;
    buffer.insert(buffer.end(), reinterpret_cast<uint8_t*>(&msgLen), reinterpret_cast<uint8_t*>(&msgLen) + sizeof(msgLen));
    buffer.insert(buffer.end(), message, message + messageLen);
    buffer.insert(buffer.end(), reinterpret_cast<uint8_t*>(&sigLen), reinterpret_cast<uint8_t*>(&sigLen) + sizeof(sigLen));
    buffer.insert(buffer.end(), signature.begin(), signature.end());
    buffer.insert(buffer.end(), reinterpret_cast<uint8_t*>(&pkLen), reinterpret_cast<uint8_t*>(&pkLen) + sizeof(pkLen));
    buffer.insert(buffer.end(), publicKey.begin(), publicKey.end());

    size_t bytesSent = send(socket, buffer.data(), buffer.size(), 0);
}

// получение и валидация сообщения
bool receiveSignedKey(int socket, uint8_t* message, int* returnCode) {
    int size = BUFFER_SIZE;
    char* buffer = new char[size];

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

    uint32_t msgLen = ntohl(*reinterpret_cast<uint32_t*>(buffer));
    if (msgLen != 32) {
        delete[] buffer;
        *returnCode = 4; // Неверная длина сообщения
        return false;
    }

    std::memcpy(message, buffer + 4, 32);
    std::vector<uint8_t> messageVec(message, message + 32);

    uint32_t sigLen = ntohl(*reinterpret_cast<uint32_t*>(buffer + 4 + msgLen));
    std::vector<uint8_t> signature(buffer + 4 + msgLen + 4, buffer + 4 + msgLen + 4 + sigLen);

    uint32_t pkLen = ntohl(*reinterpret_cast<uint32_t*>(buffer + 4 + msgLen + 4 + sigLen));
    std::vector<uint8_t> publicKey(buffer + 4 + msgLen + 4 + sigLen + 4, buffer + 4 + msgLen + 4 + sigLen + 4 + pkLen);

    bool isValid = XMSS::Verify(messageVec, signature, publicKey);
    if (!isValid) {
        delete[] buffer;
        *returnCode = 3; // Неверная подпись
        return false;
    }

    delete[] buffer;
    return true;
}

void getTimestampNonce(uint8_t* nonce) {

    size_t size = CHACHA20_NONCE_LEN;

    uint64_t timestamp = static_cast<uint64_t>(std::time(nullptr)); // 8 байт
    std::memcpy(nonce, &timestamp, std::min(size, sizeof(timestamp)));
    if (size > sizeof(timestamp)) {
        std::memset(nonce + sizeof(timestamp), 0, size - sizeof(timestamp));
    }
}

void getSharedSecretHash(uint8_t* out, const uint8_t* msg) {

    size_t msgLen = CHACHA20_KEY_LEN;

    std::vector<unsigned char> msgVector(msg, msg + msgLen);
    std::vector<unsigned char> resultVector = keccak(msgVector, msgLen);

    std::copy(resultVector.begin(), resultVector.end(), out);
}

void chacha20Wrapper(char* out, const char* in, size_t msgLength, const uint8_t* key, bool decrypt = false) {
    uint8_t nonce[CHACHA20_NONCE_LEN];
    const uint8_t* inputData;

    if (decrypt) {
        memcpy(nonce, in, CHACHA20_NONCE_LEN);
        inputData = reinterpret_cast<const uint8_t*>(in + CHACHA20_NONCE_LEN);
        msgLength -= CHACHA20_NONCE_LEN;
    } else {
        getTimestampNonce(nonce);
        inputData = reinterpret_cast<const uint8_t*>(in);
    }

    uint8_t* outputLocation = decrypt ? reinterpret_cast<uint8_t*>(out) : reinterpret_cast<uint8_t*>(out + CHACHA20_NONCE_LEN);
    ChaCha20::encrypt(outputLocation, key, nonce, inputData, msgLength);

    if (!decrypt) {
        memcpy(out, nonce, CHACHA20_NONCE_LEN);
    }
}