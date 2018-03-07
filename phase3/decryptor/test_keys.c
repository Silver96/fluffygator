#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <assert.h>
#include <string.h>
#include <errno.h>

#include "crypto.h"

#define OBF_KEY_SIZE 992
#define MAX_SIZE 100000

int main(int argc, char **argv){

    if(argc < 5){
        printf("Usage: %s obfkey iv packet_file output_file\n", argv[0]);
        exit(1);
    }

    unsigned char *iv = (unsigned char *)argv[2];

    int fd_encrypted = open(argv[3], O_RDONLY);

    assert(fd_encrypted >= 0);

    unsigned char ciphertext[MAX_SIZE];
    unsigned char decryptedtext[MAX_SIZE];

    memset(ciphertext, 0, MAX_SIZE);
    memset(decryptedtext, 0, MAX_SIZE);

    int cipher_size = read(fd_encrypted, ciphertext, MAX_SIZE);

    assert(cipher_size >= 0);

    close(fd_encrypted);

    int i = 0;

    while(i < OBF_KEY_SIZE-32){

        char key[33];

        strncpy(key, argv[1]+i, 32);
        key[32] = 0;

        int decrypt_size = decrypt(ciphertext, cipher_size, (unsigned char *)key, iv, decryptedtext);
        
        if(decrypt_size <= 0){
            i++;
            continue;
        }

        int fd_decrypted = open(argv[4], O_WRONLY | O_TRUNC | O_CREAT, 0777);

        if(fd_decrypted == -1){
            printf("%s\n", argv[4]);
            printf("%s\n", strerror(errno));
        }

        assert(fd_decrypted >= 0);

        int written = write(fd_decrypted, decryptedtext, decrypt_size);

        assert(written == decrypt_size);

        close(fd_decrypted);

        // TODO: put meaningful sizes

        char cmd[200];
        char result[200];

        snprintf(cmd, 200, "file %s", argv[4]);

        FILE *f_result = popen(cmd, "r");

        fread(result, sizeof(result), 200, f_result);

        pclose(f_result);

        if(!strstr(result, "ASCII")){
            i++;
            continue;
        }

        printf("%s\n", result);

        break;  
    }
    

    return 0;
}