#pragma once

#include "includes.h"

#define BUFFER_SIZE 2048

// генерация сидов для инициализации XMSS
std::vector<uint8_t> generate256BitNumber() {
    std::vector<uint8_t> number(XMSS_KEY_LEN); // 256 бит = 32 байта
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<unsigned int> dis(0, 255);

    for (auto& byte : number) {
        byte = static_cast<uint8_t>(dis(gen));
    }
    return number;
}

// создание #XMSS объекта для подписи сообщений
XMSS createNewXMSSObject() {
    std::vector<uint8_t> sign1 = generate256BitNumber();
    std::vector<uint8_t> sign2 = generate256BitNumber();

    return XMSS(sign1, sign2);
}

// вывод сообщения в hex-формате
void print_hex(const char* label, const uint8_t* data, size_t size) {
    std::cout << label << ": ";
    for (size_t i = 0; i < size; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    }
    std::cout << std::dec << std::endl; // Возвращаем формат вывода обратно в десятичный
}

// отправка ключа для проверки подписи
void sendVerificationKey(int socket, XMSS &xmss) {
    std::vector<uint8_t> verificationKey = xmss.getPublicKey();

    if (verificationKey.size() != XMSS_KEY_LEN) {
        throw std::runtime_error("Public key size mismatch. Expected 32 bytes.");
    }

    size_t bytesSent = send(socket, verificationKey.data(), verificationKey.size(), 0);
    if (bytesSent != verificationKey.size()) {
        throw std::runtime_error("Error sending public key.");
    }

    // print_hex("Sending", publicKey.data(), publicKey.size());
}

// получение ключа для проверки подписи
void receiveVerificationKey(int socket, uint8_t* verificationKey) {
    ssize_t bytesRead = recv(socket, verificationKey, XMSS_KEY_LEN, 0);
    if (bytesRead <= 0 || bytesRead != XMSS_KEY_LEN) {
        throw std::runtime_error("Error receiving public key or invalid key size.");
    }

    // print_hex("Received", publicKey, XMSS_KEY_LEN);
}

// подпись и отправка сообщения
void sendSignedKey(int socket, const uint8_t* key, XMSS &xmss) {

    std::vector<uint8_t> signature = xmss.getSignature(std::vector<uint8_t>(key, key + CURVE25519_KEY_LEN));
    uint32_t sigLen = htonl(static_cast<uint32_t>(signature.size()));

    std::vector<uint8_t> buffer;
    buffer.insert(buffer.end(), key, key + CURVE25519_KEY_LEN);
    buffer.insert(buffer.end(), reinterpret_cast<uint8_t*>(&sigLen), reinterpret_cast<uint8_t*>(&sigLen) + sizeof(sigLen)); // Добавляем длину подписи
    buffer.insert(buffer.end(), signature.begin(), signature.end());

    size_t bytesSent = send(socket, buffer.data(), buffer.size(), 0);
    if (bytesSent != buffer.size()) {
        throw std::runtime_error("Error sending signed key.");
    }
}

// получение и валидация сообщения
bool receiveSignedKey(int socket, uint8_t* senderPublicKey, uint8_t* senderVerifyKey, int* returnCode) {
    const size_t bufferSize = BUFFER_SIZE;

    char* buffer = new char[bufferSize];

    // Принимаем данные
    ssize_t bytesRead = recv(socket, buffer, bufferSize, 0);
    if (bytesRead <= 0) {
        delete[] buffer;
        *returnCode = (bytesRead == 0) ? 2 : 1; // 2 - закрыто, 1 - ошибка чтения
        return false;
    }

    // Проверяем, что сообщение содержит ключ фиксированной длины
    if (bytesRead <= CURVE25519_KEY_LEN + sizeof(uint32_t)) {
        delete[] buffer;
        *returnCode = 4; // Неверный формат данных
        return false;
    }

    // Извлекаем публичный ключ отправителя
    std::memcpy(senderPublicKey, buffer, CURVE25519_KEY_LEN);

    // Извлекаем длину подписи
    uint32_t sigLen = ntohl(*reinterpret_cast<uint32_t*>(buffer + CURVE25519_KEY_LEN));

    // Проверяем, что оставшихся данных достаточно для подписи
    if (bytesRead < CURVE25519_KEY_LEN + sizeof(uint32_t) + sigLen) {
        delete[] buffer;
        *returnCode = 4; // Неверный формат данных
        return false;
    }

    std::vector<uint8_t> signature(buffer + CURVE25519_KEY_LEN + sizeof(uint32_t), buffer + CURVE25519_KEY_LEN + sizeof(uint32_t) + sigLen);

    std::vector<uint8_t> messageVec(senderPublicKey, senderPublicKey + CURVE25519_KEY_LEN);
    std::vector<uint8_t> senderVerifyKeyVec(senderVerifyKey, senderVerifyKey + XMSS_KEY_LEN);

    bool isValid = XMSS::Verify(messageVec, signature, senderVerifyKeyVec);
    if (!isValid) {
        delete[] buffer;
        *returnCode = 3; // Неверная подпись
        return false;
    }

    delete[] buffer;
    return true;
}

// генерация nonce для #ChaCha20 используя таймстемп
void getTimestampNonce(uint8_t* nonce) {

    size_t size = CHACHA20_NONCE_LEN;

    uint64_t timestamp = static_cast<uint64_t>(std::time(nullptr)); // 8 байт
    std::memcpy(nonce, &timestamp, std::min(size, sizeof(timestamp)));
    if (size > sizeof(timestamp)) {
        std::memset(nonce + sizeof(timestamp), 0, size - sizeof(timestamp));
    }
}

// генерация ключа для #ChaCha20 из хеша #Keccak
void getSharedSecretHash(uint8_t* out, const uint8_t* msg) {

    size_t msgLen = CHACHA20_KEY_LEN;

    std::vector<unsigned char> msgVector(msg, msg + msgLen);
    std::vector<unsigned char> resultVector = keccak(msgVector, msgLen);

    std::copy(resultVector.begin(), resultVector.end(), out);
}

// обертка для шифрования и дешифрования сообщений с #ChaCha20
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