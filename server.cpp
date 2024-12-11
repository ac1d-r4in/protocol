#include "includes.h"

// using namespace std;

int main() {

    // ИНИЦИАЛИЗИРУЕМ СЕРВЕР

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

    // ЖДЕМ КЛИЕНТА

    std::cout << "Waiting for a connection...\n";

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

    // КЛИЕНТ ПОДСОЕДИНИЛСЯ, НАЧИНАЕМ КРИПТОГРАФИЮ

    std::cout << "Client trying to connect from " << clientIP << "\n";
    std::cout << "Initializing XMSS-Curve25519 handshake..." << std::endl;
    XMSS xmss = createNewXMSSObject(); // создаем объект #XMSS который содержит наш ключ и подпись

    uint8_t bobPrivate[32], bobPublic[32]; // сервер это Боб
    uint8_t shared[32];

    Curve25519::generate_keypair(bobPublic, bobPrivate); // генерируем нашу пару ключей #CURVE

    int result = 0;
    uint8_t alicePublic[32];
    bool recieved = receiveSignedKey(clientSocket, alicePublic, &result);  // получаем (и проверяем) подписанный #XMSS ключ клиента

    if(!recieved) {
        std::cout << "Could not verify signature! Error code: " << result << std::endl;
        return 1;
    }

    sendSignedKey(clientSocket, bobPublic, xmss); // отправляем подписанный #XMSS открытый ключ

    Curve25519::x25519(shared, alicePublic, bobPrivate);  // вычисляем общий секрет #CURVE

    uint8_t chachaKey[32], chachaNonce[12];
    getSharedSecretHash(chachaKey, shared); // вычисляем симметричный ключ #CHACHA20 из хэша #KECCAK

    std::cout << "Client successfully connected!" << std::endl;
    
    char buffer[BUFFER_SIZE];
    while (true) {

        // ПРИЕМ СООБЩЕНИЯ ОТ КЛИЕНТА

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

        size_t msgLength = bytesRead - CHACHA20_NONCE_LEN;
        char* message = new char[msgLength];
        chacha20Wrapper(message, buffer, bytesRead, chachaKey, true); // дешифруем сообщение #CHACHA20
        std::string messageString(message, msgLength);

        delete[] message;

        // ОТВЕТ КЛИЕНТУ

        std::string responseString = "Recieved message: \"" + messageString + "\"\n";
        // std::cout << responseString << std::endl;
        size_t responseLength = responseString.size();
        size_t encryptedLength = responseLength + CHACHA20_NONCE_LEN;
        char* response = new char[encryptedLength];

        chacha20Wrapper(response, responseString.c_str(), responseLength, chachaKey, false); // шифруем сообщение #CHACHA20

        send(clientSocket, response, encryptedLength, 0);

        delete[] response;
    }

    close(clientSocket);
    close(serverSocket);
    std::cout << "Server shut down.\n";

    return 0;
}