#include "includes.h"

int main() {

    // ПОДКЛЮЧАЕМСЯ К СЕРВЕРУ

    std::cout << "Connecting to server..." << std::endl;
    std::string serverIP = IP;
    int port = PORT;
    
    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket == -1) {
        std::cerr << "Error creating client socket.\n";
        return 1;
    }

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    inet_pton(AF_INET, serverIP.c_str(), &serverAddr.sin_addr);
    serverAddr.sin_port = htons(port);

    if (connect(clientSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == -1) {
        std::cerr << "Error connecting to server.\n";
        close(clientSocket);
        return 2;
    }

    std::cout << "Connected to server " << serverIP << " on port " << port << ".\n<<<<<<<<<<<<<<<<<<<<<<\n";

    // ПОДКЛЮЧИЛИСЬ, НАЧИНАЕМ КРИПТОГРАФИЮ

    std::cout << "Initializing XMSS-Curve25519 handshake..." << std::endl;
    XMSS xmss = createNewXMSSObject();  // создаем объект #XMSS который содержит наш ключ и подпись

    uint8_t alicePrivate[32], alicePublic[32]; // клиент это Алиса
    uint8_t shared[32];
    Curve25519::generate_keypair(alicePublic, alicePrivate); // генерируем нашу пару ключей #CURVE
    
    sendSignedKey(clientSocket, alicePublic, xmss); // отправляем подписанный #XMSS открытый ключ

    int result = 0;
    uint8_t bobPublic[32];
    bool recieved = receiveSignedKey(clientSocket, bobPublic, &result); // получаем (и проверяем) подписанный #XMSS ключ клиента

    if(!recieved) {
        std::cout << "Could not verify signature! Error code: " << result << std::endl;
        return 1;
    }

    Curve25519::x25519(shared, bobPublic, alicePrivate);  // вычисляем общий секрет #CURVE

    uint8_t chachaKey[32];
    getSharedSecretHash(chachaKey, shared); // вычисляем симметричный ключ #CHACHA20 из хэша #KECCAK

    std::cout << "Success! You can start sending messages:" << std::endl;
    
    std::string message;
    while (true) {

        // ОТПРАВЛЯЕМ СООБЩЕНИЕ СЕРВЕРУ

        std::cout << "\nEnter message (type 'exit' to quit): ";
        std::getline(std::cin, message);
        if (message == "exit") {
            break;
        }
        if (message.length() == 0) {
            std::cout << "Message should be not empty!\n";
            continue;
        }
        if (message.length() > 1024) {
            std::cout << "Message is too big!\n";
            continue;
        }

        size_t msgLength = message.size();
        size_t encryptedLength = msgLength + CHACHA20_NONCE_LEN;
        char* encryptedMessage = new char[encryptedLength];

        chacha20Wrapper(encryptedMessage, message.c_str(), msgLength, chachaKey, false);

        // print_hex("Sending", reinterpret_cast<const uint8_t*>(encryptedMessage), msgLength+CHACHA20_NONCE_LEN);
        send(clientSocket, encryptedMessage, encryptedLength, 0);

        delete [] encryptedMessage;

        // ПОЛУЧАЕМ ОТВЕТ ОТ СЕРВЕРА

        char buffer[BUFFER_SIZE];
        memset(buffer, 0, sizeof(buffer));
        ssize_t bytesRead = recv(clientSocket, buffer, sizeof(buffer), 0);

        if (bytesRead < 0) {
            std::cerr << "Error: Unable to read from server.\n";
            break;
        }
        if (bytesRead == 0) {
            std::cout << "Server disconnected.\n";
            break;
        }

        if (bytesRead <= CHACHA20_NONCE_LEN) {
            std::cerr << "Error: Received message too short to contain valid data.\n";
            continue;
        }

        size_t decryptedLength = bytesRead - CHACHA20_NONCE_LEN;
        char* decryptedMessage = new char[decryptedLength];
        chacha20Wrapper(decryptedMessage, buffer, bytesRead, chachaKey, true);

        std::string response(decryptedMessage, decryptedLength);
        std::cout << "[SERVER]: " << response << std::endl;

        delete[] decryptedMessage;
    }

    close(clientSocket);

    return 0;
}