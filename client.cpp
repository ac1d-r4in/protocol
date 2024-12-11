#include "includes.h"

int main() {

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

    std::cout << "Initializing XMSS-Curve25519 handshake..." << std::endl;
    XMSS xmss = createNewXMSSObject();

    uint8_t alicePrivate[32], alicePublic[32], shared[32];
    Curve25519::generate_keypair(alicePublic, alicePrivate);
    sendSigned(clientSocket, alicePublic, xmss);

    int result = 0;
    uint8_t bobPublic[32];
    bool recieved = receiveSigned(clientSocket, bobPublic, &result);

    if(!recieved) {
        std::cout << "Not recieved!\n" << std::endl;
        return 1;
    }

    Curve25519::x25519(shared, bobPublic, alicePrivate);

    uint8_t chachaKey[32];
    getSharedSecretHash(chachaKey, shared);
    // print_hex("ChaCha key", chachaKey, 32);

    std::cout << "Success! You can start sending messages:\n" << std::endl;
    
    std::string message;
    while (true) {
        std::cout << "Enter message (type 'exit' to quit): ";
        std::getline(std::cin, message);
        if (message == "exit") {
            break;
        }

        size_t msgLength = message.size();
        size_t encryptedLength = msgLength + CHACHA20_NONCE_LEN;
        char* encryptedMessage = new char[encryptedLength]; // Выходной буфер

        chacha20Wrapper(encryptedMessage, message.c_str(), msgLength, chachaKey, false);

        // print_hex("Sending", reinterpret_cast<const uint8_t*>(encryptedMessage), msgLength+CHACHA20_NONCE_LEN);
        send(clientSocket, encryptedMessage, encryptedLength, 0);

        delete [] encryptedMessage;
    }

    close(clientSocket);

    return 0;
}