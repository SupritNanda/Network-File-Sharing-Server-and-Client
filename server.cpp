/*
 * server.cpp
 * Capstone Project: Network File Sharing Server
 *
 * This is a multi-threaded TCP server that allows clients to authenticate,
 * list files, download files, and upload files.
 */

#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <thread>
#include <mutex>
#include <stdexcept>
#include <cstring>      // For memset, c_str
#include <unistd.h>     // For close, read, write
#include <sys/socket.h> // For socket, bind, listen, accept
#include <netinet/in.h> // For sockaddr_in
#include <arpa/inet.h>  // For inet_ntoa
#include <dirent.h>     // For directory listing
#include <sys/stat.h>   // For mkdir
#include <signal.h>     // For signal handling (SIGPIPE)

// --- Configuration ---
#define PORT 8080
#define BUFFER_SIZE 4096
const std::string SERVER_FILES_DIR = "server_files/";
const std::string AUTH_USER = "admin";
const std::string AUTH_PASS = "password123";
const std::string ENCRYPTION_KEY = "MY_SECRET_KEY";

// --- Globals ---
std::mutex g_coutMutex; // To make console output thread-safe

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
 * @brief Logs messages to the console in a thread-safe manner.
 * @param message The message to log.
 */
void log(const std::string& message) {
    std::lock_guard<std::mutex> lock(g_coutMutex);
    std::cout << message << std::endl;
}

/**
 * @brief Checks if a file path is safe (i.e., doesn't contain "..").
 * @param filename The filename to check.
 * @return true if the path is safe, false otherwise.
 */
bool isPathSafe(const std::string& filename) {
    if (filename.find("..") != std::string::npos) {
        return false;
    }
    return true;
}

/**
 * @brief Sends a response (command or error) to the client.
 * @param clientSocket The client's socket descriptor.
 * @param response The string response to send.
 */
bool sendResponse(int clientSocket, const std::string& response) {
    std::string encryptedResponse = response;
    // We encrypt the response before sending
    encryptDecrypt(const_cast<char*>(encryptedResponse.c_str()), encryptedResponse.length());
    
    int bytesSent = send(clientSocket, encryptedResponse.c_str(), encryptedResponse.length(), 0);
    if (bytesSent < 0) {
        log("[Error] Failed to send response.");
        return false;
    }
    return true;
}

/**
 * @brief Receives a command from the client.
 * @param clientSocket The client's socket descriptor.
 * @param command The string to store the received command in.
 * @return true on success, false on failure or disconnect.
 */
bool receiveCommand(int clientSocket, std::string& command) {
    char buffer[BUFFER_SIZE];
    memset(buffer, 0, BUFFER_SIZE);

    int bytesReceived = recv(clientSocket, buffer, BUFFER_SIZE - 1, 0);
    if (bytesReceived <= 0) {
        log("[Client] Disconnected.");
        return false;
    }

    // Decrypt the received data
    encryptDecrypt(buffer, bytesReceived);
    command.assign(buffer, bytesReceived);
    return true;
}

/**
 * @brief Handles the 'LIST' command. Lists files in SERVER_FILES_DIR.
 * @param clientSocket The client's socket descriptor.
 */
void handleList(int clientSocket) {
    DIR* dir;
    struct dirent* ent;
    std::stringstream fileList;

    if ((dir = opendir(SERVER_FILES_DIR.c_str())) != NULL) {
        while ((ent = readdir(dir)) != NULL) {
            // Don't list . and ..
            if (strcmp(ent->d_name, ".") != 0 && strcmp(ent->d_name, "..") != 0) {
                fileList << ent->d_name << "\n";
            }
        }
        closedir(dir);
        
        // Send OK followed by the list
        std::string response = "200 OK\n" + fileList.str();
        sendResponse(clientSocket, response);
    } else {
        log("[Error] Could not open directory " + SERVER_FILES_DIR);
        sendResponse(clientSocket, "500 ERROR Could not list files\n");
    }
}

/**
 * @brief Receives a file from the client and saves it.
 * @param clientSocket The client's socket descriptor.
 * @param fullPath The full path to save the file.
 * @param fileSize The size of the file to receive.
 */
void receiveFile(int clientSocket, const std::string& fullPath, long long fileSize) {
    std::ofstream outFile(fullPath, std::ios::binary);
    if (!outFile) {
        log("[Error] Could not create file " + fullPath);
        sendResponse(clientSocket, "500 ERROR Could not create file on server\n");
        return;
    }

    // Send OK, ready to receive
    sendResponse(clientSocket, "200 OK_READY\n");

    char buffer[BUFFER_SIZE];
    long long bytesReceived = 0;

    while (bytesReceived < fileSize) {
        int bytesToRead = std::min((long long)BUFFER_SIZE, fileSize - bytesReceived);
        int bytes = recv(clientSocket, buffer, bytesToRead, 0);

        if (bytes <= 0) {
            log("[Error] Client disconnected during file transfer.");
            outFile.close();
            remove(fullPath.c_str()); // Delete partial file
            return;
        }

        // Decrypt the file chunk
        encryptDecrypt(buffer, bytes);
        
        outFile.write(buffer, bytes);
        if (!outFile) {
            log("[Error] Failed to write to file " + fullPath);
            outFile.close();
            remove(fullPath.c_str());
            // Don't send response, connection might be broken
            return;
        }
        bytesReceived += bytes;
    }

    outFile.close();
    log("[Server] File received successfully: " + fullPath);
    sendResponse(clientSocket, "200 OK File uploaded\n");
}

/**
 * @brief Handles the 'PUT' command. Receives a file from the client.
 * @param clientSocket The client's socket descriptor.
 * @param filename The name of the file to receive.
 * @param fileSizeStr The size of the file as a string.
 */
void handlePut(int clientSocket, const std::string& filename, const std::string& fileSizeStr) {
    if (!isPathSafe(filename)) {
        sendResponse(clientSocket, "403 FORBIDDEN Invalid path\n");
        return;
    }

    long long fileSize;
    try {
        fileSize = std::stoll(fileSizeStr);
    } catch (...) {
        sendResponse(clientSocket, "400 BAD_REQUEST Invalid file size\n");
        return;
    }

    std::string fullPath = SERVER_FILES_DIR + filename;
    receiveFile(clientSocket, fullPath, fileSize);
}

/**
 * @brief Sends a file to the client.
 * @param clientSocket The client's socket descriptor.
 * @param fullPath The full path of the file to send.
 */
void sendFile(int clientSocket, const std::string& fullPath) {
    std::ifstream inFile(fullPath, std::ios::binary | std::ios::ate);
    if (!inFile) {
        sendResponse(clientSocket, "404 NOT_FOUND File not found\n");
        return;
    }

    long long fileSize = inFile.tellg();
    inFile.seekg(0, std::ios::beg);

    // Send OK, file size
    sendResponse(clientSocket, "200 OK " + std::to_string(fileSize) + "\n");

    // Wait for client to be ready
    std::string clientReady;
    if (!receiveCommand(clientSocket, clientReady) || clientReady != "200 OK_READY\n") {
        log("[Error] Client not ready for file transfer.");
        return;
    }
    
    char buffer[BUFFER_SIZE];
    while (inFile.read(buffer, BUFFER_SIZE) || inFile.gcount() > 0) {
        int bytesRead = inFile.gcount();
        
        // Encrypt the file chunk before sending
        encryptDecrypt(buffer, bytesRead);

        if (send(clientSocket, buffer, bytesRead, 0) < 0) {
            log("[Error] Failed to send file chunk.");
            return; // Client probably disconnected
        }
    }

    log("[Server] File sent successfully: " + fullPath);
    // No final response needed, client knows when file is done (by size)
}

/**
 * @brief Handles the 'GET' command. Sends a file to the client.
 * @param clientSocket The client's socket descriptor.
 * @param filename The name of the file to send.
 */
void handleGet(int clientSocket, const std::string& filename) {
    if (!isPathSafe(filename)) {
        sendResponse(clientSocket, "403 FORBIDDEN Invalid path\n");
        return;
    }

    std::string fullPath = SERVER_FILES_DIR + filename;
    sendFile(clientSocket, fullPath);
}

/**
 * @brief Handles a single client connection.
 * @param clientSocket The socket descriptor for the connected client.
 */
void handleClient(int clientSocket) {
    std::string clientAddr;
    {
        // Get client IP address for logging
        sockaddr_in addr;
        socklen_t addr_size = sizeof(sockaddr_in);
        getpeername(clientSocket, (sockaddr*)&addr, &addr_size);
        clientAddr = inet_ntoa(addr.sin_addr);
        log("[Client] Connected: " + clientAddr);
    }

    try {
        // --- 1. Authentication ---
        bool authenticated = false;
        while (!authenticated) {
            std::string authCmd;
            if (!receiveCommand(clientSocket, authCmd)) {
                throw std::runtime_error("Client disconnected before auth.");
            }

            std::stringstream ss(authCmd);
            std::string cmd, user, pass;
            ss >> cmd >> user >> pass;

            if (cmd == "AUTH" && user == AUTH_USER && pass == AUTH_PASS) {
                authenticated = true;
                sendResponse(clientSocket, "200 OK Authentication successful\n");
                log("[Client] " + clientAddr + " authenticated successfully.");
            } else {
                sendResponse(clientSocket, "401 UNAUTHORIZED Invalid credentials\n");
            }
        }

        // --- 2. Main Command Loop ---
        while (true) {
            std::string commandStr;
            if (!receiveCommand(clientSocket, commandStr)) {
                break; // Client disconnected
            }

            log("[Client] " + clientAddr + " command: " + commandStr);
            std::stringstream ss(commandStr);
            std::string cmd;
            ss >> cmd;

            if (cmd == "LIST") {
                handleList(clientSocket);
            } else if (cmd == "GET") {
                std::string filename;
                ss >> filename;
                if (filename.empty()) {
                    sendResponse(clientSocket, "400 BAD_REQUEST Filename missing\n");
                } else {
                    handleGet(clientSocket, filename);
                }
            } else if (cmd == "PUT") {
                std::string filename, fileSizeStr;
                ss >> filename >> fileSizeStr;
                if (filename.empty() || fileSizeStr.empty()) {
                    sendResponse(clientSocket, "400 BAD_REQUEST Filename or size missing\n");
                } else {
                    handlePut(clientSocket, filename, fileSizeStr);
                }
            } else if (cmd == "EXIT") {
                break; // Client requested exit
            } else {
                sendResponse(clientSocket, "400 BAD_REQUEST Unknown command\n");
            }
        }

    } catch (const std::exception& e) {
        log("[Error] " + std::string(e.what()));
    } catch (...) {
        log("[Error] Unknown exception in client handler.");
    }

    log("[Client] Disconnecting: " + clientAddr);
    close(clientSocket);
}

int main() {
    // Ignore SIGPIPE (which happens when writing to a disconnected socket)
    signal(SIGPIPE, SIG_IGN);

    // Create server file directory if it doesn't exist
    mkdir(SERVER_FILES_DIR.c_str(), 0777);

    int serverSocket, clientSocket;
    sockaddr_in serverAddr, clientAddr;
    socklen_t clientAddrSize = sizeof(clientAddr);

    // Create socket
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket < 0) {
        log("[Error] Could not create socket.");
        return 1;
    }

    // Set SO_REUSEADDR to allow kernel to reuse port
    int opt = 1;
    setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // Prepare the sockaddr_in structure
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(PORT);

    // Bind
    if (bind(serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        log("[Error] Bind failed.");
        return 1;
    }

    // Listen
    listen(serverSocket, 5);
    log("[Server] Waiting for connections on port " + std::to_string(PORT) + "...");

    // Accept and handle connections
    while (true) {
        clientSocket = accept(serverSocket, (sockaddr*)&clientAddr, &clientAddrSize);
        if (clientSocket < 0) {
            log("[Error] Accept failed.");
            continue;
        }

        // Create a new thread to handle the client
        std::thread clientThread(handleClient, clientSocket);
        clientThread.detach(); // Detach the thread, server doesn't need to join it
    }

    close(serverSocket);
    return 0;
}