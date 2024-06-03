#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include "util.h"

void xor_operation(const unsigned char *in, unsigned char *out, size_t length, const unsigned char *key, size_t key_length) {
    for(int i = 0; i < length; i++){
        out[i] = in[i] ^ key[i];
    }
}

int main() {
    unsigned char key[] = {
        0x30, 0x90, 0x55, 0xba, 0xc0, 0x80, 0x12, 0xbb, 
        0x12, 0x00, 0xc4, 0xfc, 0x14, 0xd3, 0x08, 0x40, 
    };
    unsigned char plaintext1[16], plaintext2[16];
    unsigned char ciphertext1[16], ciphertext2[16], ciphertext3[16], ciphertext4[16];

    memset(plaintext1, 0x31, sizeof(plaintext1));
    memset(plaintext2, 0x32, sizeof(plaintext2));

    // 执行异或操作
    xor_operation(plaintext1, ciphertext1, sizeof(plaintext1), key, sizeof(key));
    hex_dump(ciphertext1, 16, "CIPHERTEXT1");

    xor_operation(plaintext2, ciphertext2, sizeof(plaintext2), key, sizeof(key));
    hex_dump(ciphertext2, 16, "CIPHERTEXT2");

    xor_operation(ciphertext1, ciphertext3, sizeof(ciphertext3), ciphertext2, sizeof(ciphertext2));
    hex_dump(ciphertext3, 16, "CIPHERTEXT3");

    xor_operation(plaintext1, ciphertext4, sizeof(ciphertext4), plaintext2, sizeof(plaintext2));
    hex_dump(ciphertext4, 16, "CIPHERTEXT4");

    return 0;
}