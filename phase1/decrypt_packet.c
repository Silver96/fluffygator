#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <assert.h>
#include "crypto.h"

#define MAX_SIZE 100000

int main(int argc, char **argv){
    if(argc < 4){
        printf("Usage: %s key iv packet_file\n", argv[0]);
        exit(1);
    }

    unsigned char *key = (unsigned char *)argv[1];
    unsigned char *iv = (unsigned char *)argv[2];

    int fd_encrypted = open(argv[3], O_RDONLY);

    assert(fd_encrypted >= 0);

    unsigned char ciphertext[MAX_SIZE];
    unsigned char decryptedtext[MAX_SIZE];

    int cipher_size = read(fd_encrypted, ciphertext, MAX_SIZE);

    assert(cipher_size >= 0);

    close(fd_encrypted);

    int decrypt_size = decrypt(ciphertext, cipher_size, key, iv, decryptedtext);

    int fd_decrypted = open("tmp/plaintext", O_WRONLY|O_CREAT, 0777);

    assert(fd_decrypted >= 0);

    int written = write(fd_decrypted, decryptedtext, decrypt_size);

    assert(written == decrypt_size);

    close(fd_decrypted);

}