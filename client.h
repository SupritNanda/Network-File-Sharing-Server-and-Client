#ifndef CLIENT_H
#define CLIENT_H

// --- Includes ---
#include <iostream>
#include <string>
#include <vector>
#include <fstream>
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
extern const std::string CLIENT_FILES_DIR;
extern const std::string ENCRYPTION_KEY;

// --- Function Prototypes ---

/**
 * @brief A simple XOR encryption/decryption function.
 */
void encryptDecrypt(char* data, int len);

/**
 * @brief Sends a command to the server.
 */
bool sendCommand(int sock, const std::string& command);

/**
 * @brief Receives a response from the server.
 */
bool receiveResponse(int sock, std::string& response);

/**
 * @brief Receives a file from the server and saves it.
 */
void receiveFile(int sock, const std::string& fullPath, long long fileSize);

/**
 * @brief Sends a file to the server.
 */
void sendFile(int sock, const std::string& fullPath, long long fileSize);

/**
 * @brief Handles the 'LIST' command.
 */
void doList(int sock);

/**
 * @brief Handles the 'GET' (download) command.
 */
void doGet(int sock);

/**
 * @brief Handles the 'PUT' (upload) command.
 */
void doPut(int sock);

/**
 * @brief Handles user authentication.
 */
bool authenticate(int sock);

#endif // CLIENT_H