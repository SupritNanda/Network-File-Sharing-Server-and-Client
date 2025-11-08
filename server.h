#ifndef SERVER_H
#define SERVER_H

// --- Includes ---
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
extern const std::string SERVER_FILES_DIR;
extern const std::string AUTH_USER;
extern const std::string AUTH_PASS;
extern const std::string ENCRYPTION_KEY;

// --- Globals ---
extern std::mutex g_coutMutex; // To make console output thread-safe

// --- Function Prototypes ---

/**
 * @brief A simple XOR encryption/decryption function.
 */
void encryptDecrypt(char* data, int len);

/**
 * @brief Logs messages to the console in a thread-safe manner.
 */
void log(const std::string& message);

/**
 * @brief Checks if a file path is safe (i.e., doesn't contain "..").
 */
bool isPathSafe(const std::string& filename);

/**
 * @brief Sends a response (command or error) to the client.
 */
bool sendResponse(int clientSocket, const std::string& response);

/**
 * @brief Receives a command from the client.
 */
bool receiveCommand(int clientSocket, std::string& command);

/**
 * @brief Handles the 'LIST' command. Lists files in SERVER_FILES_DIR.
 */
void handleList(int clientSocket);

/**
 * @brief Receives a file from the client and saves it.
 */
void receiveFile(int clientSocket, const std::string& fullPath, long long fileSize);

/**
 * @brief Handles the 'PUT' command. Receives a file from the client.
 */
void handlePut(int clientSocket, const std::string& filename, const std::string& fileSizeStr);

/**
 * @brief Sends a file to the client.
 */
void sendFile(int clientSocket, const std::string& fullPath);

/**
 * @brief Handles the 'GET' command. Sends a file to the client.
 */
void handleGet(int clientSocket, const std::string& filename);

/**
 * @brief Handles a single client connection.
 */
void handleClient(int clientSocket);

#endif // SERVER_H