#include <stdio.h>
#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#define maxLength 3000

//CLIENT
unsigned char iv[16] = {
    0x2b, 0x7e, 0x15, 0x16,
    0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88,
    0x09, 0xcf, 0x4f, 0x3c
};
unsigned char key[32] = {
    0x2b, 0x7e, 0x15, 0x16,
    0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88,
    0x09, 0xcf, 0x4f, 0x3c,
    0x2b, 0x7e, 0x15, 0x16,
    0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88,
    0x09, 0xcf, 0x4f, 0x3c
};

int stream_encrypt(unsigned char *plaintext, int plaintext_len, unsigned
char *key, unsigned char *iv, unsigned char *ciphertext)
{
    //creating our context, cipher type, and declaring our lengths
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher_type;
    int length = 0;
    int ciphertext_len = 0;
    cipher_type = EVP_aes_256_cbc();
    ctx = EVP_CIPHER_CTX_new();
    //initializing our encryption envelope with the key, iv, and cipher type
    EVP_EncryptInit_ex(ctx, cipher_type, nullptr, key, iv);
    //creates ciphertext in the ciphertext buffer from the plaintext
    //&length corresponds to the length of the ciphertext buffer in bytes
    EVP_EncryptUpdate(ctx, ciphertext, &length, plaintext, plaintext_len);
    ciphertext_len = length;
    //finalizes our encryption by processing unencrypted data and appending it to the index represented by ciphertext+length
    //stores the new length of the updated ciphertext in length. We update our total ciphertext length to contain this new length.
    EVP_EncryptFinal_ex(ctx, ciphertext + length, &length);
    ciphertext_len += length;
    //clearing cipher 
    EVP_CIPHER_CTX_free(ctx);
return ciphertext_len;
}

int main(void)
{
    //VARIABLE DEFINITION
    int PORT = 8080;
    const char *IP = "127.0.0.1";
    char serverMessage[maxLength]; 

    //CREATING SOCKET
    sockaddr_in clientSocketAddress;
    memset(&clientSocketAddress, 0, sizeof(clientSocketAddress));
    clientSocketAddress.sin_family = AF_INET;
    clientSocketAddress.sin_addr.s_addr = inet_addr(IP);
    clientSocketAddress.sin_port = htons(PORT);
    int client = socket(AF_INET, SOCK_STREAM, 0);

    //CONNECTING TO SERVER
    if (connect(client,(sockaddr*) &clientSocketAddress, sizeof(clientSocketAddress))>=0){
        printf("Successfully connected to server\n");
    }

    while(true)
    {
        //SENDING MESSAGE TO SERVER - first retrieving the input from command line
        printf("Client: ");
        std::string input;
        std::getline(std::cin, input);
        //defining our buffers for our encrypted and decrypted methods
        unsigned char plaintextBuffer[maxLength];
        unsigned char encryptedBuffer[maxLength];
        //copying the input string to the plaintext buffer, making sure to include the null character 
        memcpy(plaintextBuffer, input.c_str(), input.length()+1);
        //calling the encrypt method whatever is in the plaintext buffer and putting it in the encrypted buffer
        int ciphertextLength = stream_encrypt(plaintextBuffer, input.length(), key, iv, encryptedBuffer);
        //sending the encrypted message to the serverå
        

        send(client, (char*)encryptedBuffer, ciphertextLength, 0);
        printf("Waiting for server response\n");
        //clearing the message buffer for the received server response and then clearing our encrypted buffer for the next message
        memset(&serverMessage, 0, sizeof(serverMessage));
        memset(&plaintextBuffer, 0, sizeof(plaintextBuffer));
        memset(&encryptedBuffer, 0, sizeof(encryptedBuffer)); 
        recv(client, (char*)&serverMessage, sizeof(serverMessage), 0);
        printf("Server: %s\n", serverMessage);
        
    }
    close(client);
    printf("Socket closed\n");
    return 0;    
}