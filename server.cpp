#include "includes.h"

// using namespace std;

int main() {
    int port = PORT;  // Порт для прослушивания
    std::cout << "Starting server on port " << port << "...\n";

    // Создаём сокет
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == -1) {
        std::cerr << "Error: Unable to create socket.\n";
        return 1;
    }

    // Настройка адреса
    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(port);

    // Привязка сокета к адресу
    if (bind(serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        std::cerr << "Error: Unable to bind socket.\n";
        close(serverSocket);
        return 1;
    }

    // Начинаем прослушивание
    if (listen(serverSocket, 1) == -1) {
        std::cerr << "Error: Unable to listen on socket.\n";
        close(serverSocket);
        return 1;
    }

    std::cout << "Waiting for a connection...\n";

    // Принятие входящего соединения
    sockaddr_in clientAddr{};
    socklen_t clientSize = sizeof(clientAddr);
    int clientSocket = accept(serverSocket, (sockaddr*)&clientAddr, &clientSize);
    if (clientSocket == -1) {
        std::cerr << "Error: Unable to accept connection.\n";
        close(serverSocket);
        return 1;
    }

    char clientIP[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &clientAddr.sin_addr, clientIP, INET_ADDRSTRLEN);
    std::cout << "Client connected from " << clientIP << "\n";

    // Обработка сообщений
    char buffer[2048];
    while (true) {
        memset(buffer, 0, sizeof(buffer));  // Очистка буфера
        ssize_t bytesRead = recv(clientSocket, buffer, sizeof(buffer), 0);
        if (bytesRead < 0) {
            std::cerr << "Error: Unable to read from client.\n";
            break;
        }
        if (bytesRead == 0) {
            std::cout << "Client disconnected.\n";
            break;
        }

        // Вывод принятых данных в hex
        std::vector<unsigned char> receivedData(buffer, buffer + bytesRead);
        std::cout << "Received data (hex): ";
        for (const auto& byte : receivedData) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << " ";
        }
        std::cout << "\n";

        // Чтение длины сообщения
        if (bytesRead < 4) {
            std::cerr << "Error: Incomplete header received.\n";
            continue;
        }
        uint32_t msgLen = ntohl(*reinterpret_cast<uint32_t*>(buffer));
        if (bytesRead < 4 + msgLen) {
            std::cerr << "Error: Incomplete message received.\n";
            continue;
        }
        std::string message(buffer + 4, buffer + 4 + msgLen);
        std::cout << "Message: " << message << "\n";

        // Чтение подписи
        if (bytesRead < 4 + msgLen + 4) {
            std::cerr << "Error: Incomplete signature length.\n";
            continue;
        }
        uint32_t sigLen = ntohl(*reinterpret_cast<uint32_t*>(buffer + 4 + msgLen));
        if (bytesRead < 4 + msgLen + 4 + sigLen) {
            std::cerr << "Error: Incomplete signature received.\n";
            continue;
        }
        std::vector<unsigned char> signature(buffer + 4 + msgLen + 4, buffer + 4 + msgLen + 4 + sigLen);
        std::cout << "Signature (server): ";
        for (const auto& byte : signature) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << " ";
        }
        std::cout << "\n";

        // Чтение публичного ключа
        if (bytesRead < 4 + msgLen + 4 + sigLen + 4) {
            std::cerr << "Error: Incomplete public key length.\n";
            continue;
        }
        uint32_t pkLen = ntohl(*reinterpret_cast<uint32_t*>(buffer + 4 + msgLen + 4 + sigLen));
        if (bytesRead < 4 + msgLen + 4 + sigLen + 4 + pkLen) {
            std::cerr << "Error: Incomplete public key received.\n";
            continue;
        }
        std::vector<unsigned char> publicKey(buffer + 4 + msgLen + 4 + sigLen + 4, buffer + 4 + msgLen + 4 + sigLen + 4 + pkLen);

        // Проверка подписи
        bool isValid = XMSS::Verify(stringToVector(message), signature, publicKey);
        if (!isValid) {
            std::cout << "Message did not pass validation.\n";
            continue;
        }

        std::cout << "Message successfully validated.\n";
    }
    // Закрытие сокетов
    close(clientSocket);
    close(serverSocket);
    std::cout << "Server shut down.\n";

    return 0;
}