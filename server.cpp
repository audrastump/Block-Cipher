#include <stdio.h>
#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>


//SERVER
int PORT = 8080;
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


int stream_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext)
{
    //initializing our cipher context and lengths
    EVP_CIPHER_CTX *ctx;
    int length = 0;
    int plaintext_len = 0;
    ctx = EVP_CIPHER_CTX_new();
    const EVP_CIPHER *ciphertype = EVP_aes_256_cbc();
    //using our key, and index vector to decrypt
    EVP_DecryptInit_ex(ctx, ciphertype, nullptr, key, iv);
    //taking the cipher text and its length, decrypting it, and storing it in the plaintext buffer
    //stores length of plaintext in length 
    EVP_DecryptUpdate(ctx, plaintext, &length, ciphertext, ciphertext_len);
    
    EVP_DecryptFinal_ex(ctx, plaintext, &length);
    
    EVP_CIPHER_CTX_free(ctx);

    return 0;
}

int main(void)
{
    //CREATING SOCKET
    int server = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in servAddr;
    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servAddr.sin_port = htons(PORT);
    
    //BINDING SOCKET
    if ((bind(server, (struct sockaddr*) &servAddr, sizeof(servAddr))) < 0){
        printf("Uh oh, socket not binding\n");
        return 1;
    }

    //LISTENING FOR CLIENTS
    listen(server,9);
    sockaddr_in clientSockAddr;
    socklen_t clientSockAddrSize = sizeof(clientSockAddr);
    
    //ACCEPTING CLIENTS
    int client = accept(server, (sockaddr *)&clientSockAddr, &clientSockAddrSize);
    printf("Client connected at port %i\n", PORT);

    char clientMessage[3000];
    unsigned char inputBuffer[3000];
    unsigned char outputBuffer[3000];
    while(true)
    {
        //clearing our input and output buffers for the next message
        memset(&outputBuffer, 0, sizeof(outputBuffer));
        memset(&inputBuffer, 0, sizeof(inputBuffer));  
        //receiving the encrypted message and printing
        recv(client, clientMessage, sizeof(clientMessage),0);
        printf("Client Encrypted Message: %s\n", clientMessage);
        
        //copying the encrypted message to the input buffer to be decrypted into the output buffer
        memcpy(inputBuffer, clientMessage, strlen(clientMessage));
        

        int finalLength = stream_decrypt(inputBuffer, strlen(clientMessage), key, iv, outputBuffer);

        
        printf("Client Decrypted Message: %s\n",outputBuffer);
        printf("Server: ");
        
        //SERVER RESPONSE
        std::string input;
        getline(std::cin, input);
        memset(&clientMessage, 0, sizeof(clientMessage));
        strcpy(clientMessage, input.c_str());
        send(client, clientMessage, strlen(clientMessage), 0);
    }
    close(client);
    close(server);
    printf("Socket closed\n");
    return 0;   
}