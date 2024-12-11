#include "includes.h"

// using namespace std;

int main() {
    int port = PORT;
    std::cout << "Starting server on port " << port << "...\n";

    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == -1) {
        std::cerr << "Error: Unable to create socket.\n";
        return 1;
    }

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(port);

    if (bind(serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        std::cerr << "Error: Unable to bind socket.\n";
        close(serverSocket);
        return 1;
    }

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

    std::cout << "Client trying to connect from " << clientIP << "\n";
    std::cout << "Initializing XMSS-Curve25519 handshake..." << std::endl;
    XMSS xmss = createNewXMSSObject();

    uint8_t bobPrivate[32], bobPublic[32];
    uint8_t shared[32];
    Curve25519::generate_keypair(bobPublic, bobPrivate);

    int result = 0;
    uint8_t alicePublic[32];
    bool recieved = receiveSigned(clientSocket, alicePublic, &result);

    if(!recieved) {
        std::cout << "Not recieved!\n" << std::endl;
        return 1;
    }

    sendSigned(clientSocket, bobPublic, xmss);

    Curve25519::x25519(shared, alicePublic, bobPrivate);

    uint8_t chachaKey[32], chachaNonce[12];
    getSharedSecretHash(chachaKey, shared);
    // getTimestampNonce(chachaNonce);
    // print_hex("ChaCha key", chachaKey, 32);

    std::cout << "Client successfully connected!" << std::endl;
    
    char buffer[BUFFER_SIZE];
    while (true) {
        memset(buffer, 0, sizeof(buffer));  // Очистка буфера
        ssize_t bytesRead = recv(clientSocket, buffer, sizeof(buffer), 0);
        if (bytesRead < 0) {
            std::cerr << "Error: Unable to read from client.\n";
            break;
        }
        if (bytesRead == 0) {
            std::cout << "Client disconnected. Shutting down server.\n";
            break;
        }

        if (bytesRead <= CHACHA20_NONCE_LEN) {
            std::cerr << "Error: Message too short to contain valid data.\n";
            continue;
        }

        // print_hex("Received", reinterpret_cast<const uint8_t*>(buffer), bytesRead);

        // Расшифровка сообщения с использованием chacha20Wrapper
        size_t decryptedLength = bytesRead - CHACHA20_NONCE_LEN;
        char* decryptedMessage = new char[decryptedLength];
        chacha20Wrapper(decryptedMessage, buffer, bytesRead, chachaKey, true);

        // Вывод расшифрованного сообщения
        std::cout << "Decrypted message: " << std::string(decryptedMessage, decryptedLength) << '\n';

        // Освобождаем память
        delete[] decryptedMessage;
    }

    close(clientSocket);
    close(serverSocket);
    std::cout << "Server shut down.\n";

    return 0;
}