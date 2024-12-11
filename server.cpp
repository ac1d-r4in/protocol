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
    uint8_t bobShared[32];
    Curve25519::generate_keypair(bobPublic, bobPrivate);

    int result = 0;
    uint8_t alicePublic[32];
    bool recieved = receiveSigned(clientSocket, alicePublic, &result);

    if(!recieved) {
        std::cout << "Not recieved!\n" << std::endl;
        return 1;
    }

    sendSigned(clientSocket, bobPublic, xmss);

    Curve25519::x25519(bobShared, alicePublic, bobPrivate);

    // print_hex("Shared key", bobShared, 32);

    std::cout << "Client successfully connected!" << std::endl;
    getchar();
    
    // Обработка сообщений
    // bool exitloop = false;
    // while (!exitloop) {
        
    //     int result = 0;
    //     std::string message = recieveSigned(clientSocket, &result);

    //     if(message.length() > 0) {
    //         // Отправляем ответное сообщение клиенту
    //         std::cout << "Recieved: " << message << std::endl;
    //         std::string responseString = "u8ArrayToString(curvePublic, 32)";
    //         sendSigned(clientSocket, responseString, xmss);
    //     }
    //     else {
    //         switch (result) {
    //             case 1:
    //                 std::cout << "Error: Unable to read from client." << std::endl;
    //                 exitloop = true;
    //                 break;
    //             case 2:
    //                 std::cout << "Client disconnected. Shutting down server." << std::endl;
    //                 exitloop = true;
    //                 break;
    //             case 3:
    //                 sendSigned(clientSocket, "Could not validate signature from client, please try again or contact your administrator!", xmss);
    //                 break;
    //             default:
    //                 break;
    //         }
    //     }
    // }

    close(clientSocket);
    close(serverSocket);
    std::cout << "Server shut down.\n";

    return 0;
}