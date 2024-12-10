#include "includes.h"

using namespace std;

vector<unsigned char> generate256BitNumber() {
    vector<unsigned char> number(32); // 256 бит = 32 байта
    random_device rd; // Источник энтропии
    mt19937 gen(rd()); // Генератор случайных чисел
    uniform_int_distribution<unsigned int> dis(0, 255); // Диапазон байтов

    for (auto& byte : number) {
        byte = static_cast<unsigned char>(dis(gen));
    }
    return number;
}

XMSS createNewXMSSObject() {
    vector<unsigned char> sign1 = generate256BitNumber();
    vector<unsigned char> sign2 = generate256BitNumber();

    return XMSS(sign1, sign2);
}

void sendSigned(int socket, const string &message, XMSS &xmss) {
    vector<unsigned char> publicKey = xmss.getPublicKey();
    vector<unsigned char> signature = xmss.getSignature(stringToVector(message));

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

    // std::cout << "Sending message: [";
    // for (const auto& byte : buffer) {
    //     std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << " ";
    // }
    // std::cout << "]\n";

    send(socket, buffer.data(), buffer.size(), 0);
}

int main() {

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
    XMSS xmss = createNewXMSSObject();

    if (connect(clientSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == -1) {
        std::cerr << "Error connecting to server.\n";
        close(clientSocket);
        return 2;
    }

    cout << "Connected to server " << serverIP << " on port " << port << ".\n";

    string message;
    while (true) {
        cout << "Enter message (type 'exit' to quit): ";
        getline(std::cin, message);
        if (message == "exit") {
            break;
        }
        
        sendSigned(clientSocket, message, xmss);
    }

    close(clientSocket);

    return 0;
}