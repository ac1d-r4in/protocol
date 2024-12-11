#include "includes.h"

using namespace std;

int main() {

    std::cout << "Connecting to server..." << std::endl;
    string serverIP = IP;
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

    cout << "Connected to server " << serverIP << " on port " << port << ".\n<<<<<<<<<<<<<<<<<<<<<<\n";

    std::cout << "Initializing XMSS-Curve25519 handshake..." << std::endl;
    XMSS xmss = createNewXMSSObject();

    u8 alicePrivate[32], alicePublic[32], aliceShared[32];
    Curve25519::generate_keypair(alicePublic, alicePrivate);
    sendSigned(clientSocket, alicePublic, xmss);

    int result = 0;
    u8 bobPublic[32];
    bool recieved = receiveSigned(clientSocket, bobPublic, &result);

    if(!recieved) {
        std::cout << "Not recieved!\n" << std::endl;
        return 1;
    }

    Curve25519::x25519(aliceShared, bobPublic, alicePrivate);

    // print_hex("Shared key", aliceShared, 32);

    std::cout << "Success! You can start sending messages:\n" << std::endl;
    getchar();
    // std::string message;
    // while (true) {
    //     std::cout << "Enter message:" << std::endl;
    //     getline(std::cin, message);
    //     if (message == "exit") {
    //         break;
    //     }
    //     if (message.length() < 1) {
    //         cout << "Message should not be empty!";
    //         continue;
    //     }
        
    //     sendSigned(clientSocket, message, xmss);

    //     int result = 0;
    //     std::string serverResponse = recieveSigned(clientSocket, &result);

    //     if(serverResponse.length() > 0) {
    //         // Отправляем ответное сообщение клиенту
    //         std::string responseString;
    //         cout << "[SERVER]: " << serverResponse << std::endl;
    //     }
    //     else {
    //         switch (result) {
    //             case 1:
    //             case 2:
    //                 std::cout << "Error reading responce from server. Shutting down connection." << std::endl;
    //                 break;
    //             default:
    //                 continue;
    //         }
    //     }
    // }

    close(clientSocket);

    return 0;
}