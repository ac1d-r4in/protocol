#pragma once

#include "includes.h"

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

// подпись и отправка сообщения
void sendSigned(int socket, const std::string &message, XMSS &xmss) {

    std::vector<unsigned char> messageVec(message.begin(), message.end());

    std::vector<unsigned char> publicKey = xmss.getPublicKey();
    std::vector<unsigned char> signature = xmss.getSignature(messageVec);

    // std::cout << "Signature (client): ";
    // for (const auto& byte : signature) {
    //     std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << " ";
    // }
    // std::cout << "\n";

    uint32_t msgLen = htonl(message.size());
    uint32_t sigLen = htonl(signature.size());
    uint32_t pkLen = htonl(publicKey.size());

    std::vector<unsigned char> buffer;
    buffer.insert(buffer.end(), reinterpret_cast<unsigned char *>(&msgLen), reinterpret_cast<unsigned char *>(&msgLen) + sizeof(msgLen));
    buffer.insert(buffer.end(), message.begin(), message.end());
    buffer.insert(buffer.end(), reinterpret_cast<unsigned char *>(&sigLen), reinterpret_cast<unsigned char *>(&sigLen) + sizeof(sigLen));
    buffer.insert(buffer.end(), signature.begin(), signature.end());
    buffer.insert(buffer.end(), reinterpret_cast<unsigned char *>(&pkLen), reinterpret_cast<unsigned char *>(&pkLen) + sizeof(pkLen));
    buffer.insert(buffer.end(), publicKey.begin(), publicKey.end());

    send(socket, buffer.data(), buffer.size(), 0);
}

// получение и валидация сообщения
std::string recieveSigned(int socket, int* returnCode) {

    int size = BUFFER_SIZE;
    char* buffer = new char[size];

    // memset(buffer, 0, size);
    ssize_t bytesRead = recv(socket, buffer, size, 0);
    if (bytesRead < 0) {
        delete [] buffer;
        *returnCode = 1;
        return "";
    }
    if (bytesRead == 0) {
        delete [] buffer;
        *returnCode = 2;
        return "";
    }

    uint32_t msgLen = ntohl(*reinterpret_cast<uint32_t*>(buffer));
    std::vector<unsigned char> message(buffer + 4, buffer + 4 + msgLen);

    uint32_t sigLen = ntohl(*reinterpret_cast<uint32_t*>(buffer + 4 + msgLen));
    std::vector<unsigned char> signature(buffer + 4 + msgLen + 4, buffer + 4 + msgLen + 4 + sigLen);

    uint32_t pkLen = ntohl(*reinterpret_cast<uint32_t*>(buffer + 4 + msgLen + 4 + sigLen));
    std::vector<unsigned char> publicKey(buffer + 4 + msgLen + 4 + sigLen + 4, buffer + 4 + msgLen + 4 + sigLen + 4 + pkLen);


    bool isValid = XMSS::Verify(message, signature, publicKey);
    if (!isValid) {
        delete [] buffer;
        *returnCode = 3;
        return "";
    }

    std::string messageStr(message.begin(), message.end());

    delete [] buffer;

    return messageStr;
}