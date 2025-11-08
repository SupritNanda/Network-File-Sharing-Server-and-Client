/*
 * client.cpp
 * Capstone Project: Network File Sharing Client
 *
 * This is a console-based client that connects to the server,
 * authenticates, and provides a menu for file operations.
 */

#include <iostream>
#include <string>
#include <vector>
#include <fstream>x
#include <sstream>
#include <stdexcept>
#include <cstring>      // For memset
#include <unistd.h>     // For close, read, write
#include <sys/socket.h> // For socket
#include <netinet/in.h> // For sockaddr_in
#include <arpa/inet.h>  // For inet_addr
#include <sys/stat.h>   // For mkdir

// --- Configuration ---
#define SERVER_IP "127.0.0.1"
#define PORT 8080
#define BUFFER_SIZE 4096
const std::string CLIENT_FILES_DIR = "client_files/";
const std::string ENCRYPTION_KEY = "MY_SECRET_KEY";

/**
 * @brief A simple XOR encryption/decryption function.
 * @note This is NOT for real-world security. It's for academic demonstration.
 * @param data The data to encrypt/decrypt.
 * @param len The length of the data.
 */
void encryptDecrypt(char* data, int len) {
    for (int i = 0; i < len; ++i) {
        data[i] = data[i] ^ ENCRYPTION_KEY[i % ENCRYPTION_KEY.length()];
    }
}

/**
 * @brief Sends a command to the server.
 * @param sock The server socket descriptor.
 * @param command The string command to send.
 */
bool sendCommand(int sock, const std::string& command) {
    std::string encryptedCommand = command;
    // Encrypt the command before sending
    encryptDecrypt(const_cast<char*>(encryptedCommand.c_str()), encryptedCommand.length());
    
    if (send(sock, encryptedCommand.c_str(), encryptedCommand.length(), 0) < 0) {
        std::cerr << "[Error] Failed to send command." << std::endl;
        return false;
    }
    return true;
}

/**
 * @brief Receives a response from the server.
 * @param sock The server socket descriptor.
 * @param response The string to store the received response in.
 * @return true on success, false on failure or disconnect.
 */
bool receiveResponse(int sock, std::string& response) {
    char buffer[BUFFER_SIZE];
    memset(buffer, 0, BUFFER_SIZE);

    int bytesReceived = recv(sock, buffer, BUFFER_SIZE - 1, 0);
    if (bytesReceived <= 0) {
        std::cerr << "[Error] Server disconnected." << std::endl;
        return false;
    }

    // Decrypt the received data
    encryptDecrypt(buffer, bytesReceived);
    response.assign(buffer, bytesReceived);
    return true;
}

/**
 * @brief Receives a file from the server and saves it.
 * @param sock The server socket descriptor.
 * @param fullPath The full path to save the file.
 * @param fileSize The size of the file to receive.
 */
void receiveFile(int sock, const std::string& fullPath, long long fileSize) {
    std::ofstream outFile(fullPath, std::ios::binary);
    if (!outFile) {
        std::cerr << "[Error] Could not create file " << fullPath << std::endl;
        // Tell server we're not ready (though this is a client-side error)
        sendCommand(sock, "500 ERROR\n");
        return;
    }

    // Tell server we're ready
    sendCommand(sock, "200 OK_READY\n");

    char buffer[BUFFER_SIZE];
    long long bytesReceived = 0;

    while (bytesReceived < fileSize) {
        int bytesToRead = std::min((long long)BUFFER_SIZE, fileSize - bytesReceived);
        int bytes = recv(sock, buffer, bytesToRead, 0);

        if (bytes <= 0) {
            std::cerr << "[Error] Server disconnected during file transfer." << std::endl;
            outFile.close();
            remove(fullPath.c_str()); // Delete partial file
            return;
        }

        // Decrypt the file chunk
        encryptDecrypt(buffer, bytes);

        outFile.write(buffer, bytes);
        if (!outFile) {
            std::cerr << "[Error] Failed to write to file " << fullPath << std::endl;
            outFile.close();
            remove(fullPath.c_str());
            return;
        }
        bytesReceived += bytes;
    }

    outFile.close();
    std::cout << "[Client] File received successfully: " << fullPath << std::endl;
}

/**
 * @brief Sends a file to the server.
 * @param sock The server socket descriptor.
 * @param fullPath The full path of the file to send.
 * @param fileSize The size of the file.
 */
void sendFile(int sock, const std::string& fullPath, long long fileSize) {
    std::ifstream inFile(fullPath, std::ios::binary);
    if (!inFile) {
        std::cerr << "[Error] Could not open file " << fullPath << std::endl;
        return;
    }

    // Wait for server to be ready
    std::string serverReady;
    if (!receiveResponse(sock, serverReady) || serverReady.rfind("200 OK_READY", 0) != 0) {
        std::cerr << "[Error] Server not ready for file transfer. Server said: " << serverReady << std::endl;
        return;
    }

    std::cout << "[Client] Server ready. Starting upload..." << std::endl;
    
    char buffer[BUFFER_SIZE];
    while (inFile.read(buffer, BUFFER_SIZE) || inFile.gcount() > 0) {
        int bytesRead = inFile.gcount();
        
        // Encrypt the file chunk before sending
        encryptDecrypt(buffer, bytesRead);
        
        if (send(sock, buffer, bytesRead, 0) < 0) {
            std::cerr << "[Error] Failed to send file chunk." << std::endl;
            return; // Server probably disconnected
        }
    }

    inFile.close();
    std::cout << "[Client] File sent successfully: " << fullPath << std::endl;

    // Wait for final confirmation from server
    std::string finalResponse;
    if (receiveResponse(sock, finalResponse)) {
        std::cout << "[Server] " << finalResponse;
    }
}

/**
 * @brief Handles the 'LIST' command.
 * @param sock The server socket descriptor.
 */
void doList(int sock) {
    sendCommand(sock, "LIST\n");
    std::string response;
    if (receiveResponse(sock, response)) {
        std::stringstream ss(response);
        std::string line;
        std::getline(ss, line); // Read the "200 OK" line
        
        std::cout << "--- Files on Server ---" << std::endl;
        while (std::getline(ss, line)) {
            if (!line.empty()) {
                std::cout << line << std::endl;
            }
        }
        std::cout << "-----------------------" << std::endl;
    }
}

/**
 * @brief Handles the 'GET' (download) command.
 * @param sock The server socket descriptor.
 */
void doGet(int sock) {
    std::string filename;
    std::cout << "Enter filename to download: ";
    std::getline(std::cin, filename);
    if (filename.empty()) return;

    sendCommand(sock, "GET " + filename + "\n");
    
    std::string response;
    if (!receiveResponse(sock, response)) return;

    std::stringstream ss(response);
    std::string status, ok, fileSizeStr;
    ss >> status >> ok >> fileSizeStr;

    if (status == "200" && ok == "OK") {
        try {
            long long fileSize = std::stoll(fileSizeStr);
            std::string fullPath = CLIENT_FILES_DIR + filename;
            std::cout << "[Client] Downloading " << filename << " (" << fileSize << " bytes)..." << std::endl;
            receiveFile(sock, fullPath, fileSize);
        } catch (...) {
            std::cerr << "[Error] Invalid file size received from server." << std::endl;
        }
    } else {
        std::cerr << "[Server] " << response;
    }
}

/**
 * @brief Handles the 'PUT' (upload) command.
 * @param sock The server socket descriptor.
 */
void doPut(int sock) {
    std::string filename;
    std::cout << "Enter filename to upload (must be in " << CLIENT_FILES_DIR << "): ";
    std::getline(std::cin, filename);
    if (filename.empty()) return;

    std::string fullPath = CLIENT_FILES_DIR + filename;
    std::ifstream inFile(fullPath, std::ios::binary | std::ios::ate);
    if (!inFile) {
        std::cerr << "[Error] File not found or cannot be opened: " << fullPath << std::endl;
        return;
    }

    long long fileSize = inFile.tellg();
    inFile.close();

    std::cout << "[Client] Uploading " << filename << " (" << fileSize << " bytes)..." << std::endl;
    sendCommand(sock, "PUT " + filename + " " + std::to_string(fileSize) + "\n");
    
    // sendFile will wait for the server's "OK_READY" response
    sendFile(sock, fullPath, fileSize);
}

/**
 * @brief Handles user authentication.
 * @param sock The server socket descriptor.
 * @return true if authenticated, false otherwise.
 */
bool authenticate(int sock) {
    std::string user, pass;
    std::cout << "Enter username: ";
    std::getline(std::cin, user);
    std::cout << "Enter password: ";
    std::getline(std::cin, pass);

    sendCommand(sock, "AUTH " + user + " " + pass + "\n");
    
    std::string response;
    if (!receiveResponse(sock, response)) {
        return false;
    }

    if (response.rfind("200 OK", 0) == 0) { // Check if response starts with "200 OK"
        std::cout << "[Server] " << response;
        return true;
    } else {
        std::cerr << "[Server] " << response;
        return false;
    }
}

int main() {
    // Create client file directory if it doesn't exist
    mkdir(CLIENT_FILES_DIR.c_str(), 0777);

    int sock = 0;
    sockaddr_in serv_addr;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        std::cerr << "[Error] Socket creation error." << std::endl;
        return 1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // Convert IPv4 and IPv6 addresses from text to binary form
    if (inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0) {
        std::cerr << "[Error] Invalid address/ Address not supported." << std::endl;
        return 1;
    }

    if (connect(sock, (sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        std::cerr << "[Error] Connection Failed. Is the server running?" << std::endl;
        return 1;
    }

    std::cout << "[Client] Connected to server." << std::endl;
    
    // --- 1. Authentication ---
    if (!authenticate(sock)) {
        std::cerr << "[Client] Authentication failed. Exiting." << std::endl;
        close(sock);
        return 1;
    }

    // --- 2. Main Menu Loop ---
    std::string choice;
    while (true) {
        std::cout << "\n--- Client Menu ---\n"
                  << "1. List files on server\n"
                  << "2. Download file\n"
                  << "3. Upload file\n"
                  << "4. Exit\n"
                  << "Enter choice: ";
        
        std::getline(std::cin, choice);

        if (choice == "1") {
            doList(sock);
        } else if (choice == "2") {
            doGet(sock);
        } else if (choice == "3") {
            doPut(sock);
        } else if (choice == "4") {
            sendCommand(sock, "EXIT\n");
            break;
        } else {
            std::cout << "Invalid choice. Please try again." << std::endl;
        }
    }

    std::cout << "[Client] Disconnecting." << std::endl;
    close(sock);
    return 0;
}