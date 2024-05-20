#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdint.h>
#include <time.h>
#include <string.h>

int aead_hmac_cbc(const uint8_t *key, const uint8_t *iv, const uint8_t *hmac_key, int calc_count){
    EVP_CIPHER_CTX *ctx;
    uint8_t plaintext[1024];
    uint8_t ciphertext[1024 + 16] = {0};
    uint8_t hmac[EVP_MAX_MD_SIZE];
    int plaintext_len = sizeof(plaintext);
    int hmac_output_len;

    memset(plaintext, 0x11, sizeof(plaintext));
    ctx = EVP_CIPHER_CTX_new();

    while(calc_count--){
        EVP_EncryptInit_ex(ctx, EVP_sm4_cbc(), NULL, key, iv);
        EVP_EncryptUpdate(ctx, ciphertext, &plaintext_len, plaintext, plaintext_len);
        EVP_EncryptFinal_ex(ctx, ciphertext + plaintext_len, &plaintext_len);

        HMAC(EVP_sm3(), hmac_key, strlen((char*)hmac_key), ciphertext, plaintext_len, hmac, &hmac_output_len);
    }

    EVP_CIPHER_CTX_free(ctx);

    return 0;
}

int gcm_sm4(const uint8_t *key, const uint8_t *iv, const uint8_t *hmac_key, int calc_count){
    EVP_CIPHER_CTX *ctx;
    int ciphertext_len;
    uint8_t plaintext[1024];
    uint8_t ciphertext[1024] = {0};
    uint8_t hmac[EVP_MAX_MD_SIZE];
    int plaintext_len = sizeof(plaintext);
    int hmac_output_len;

    ctx = EVP_CIPHER_CTX_new();
 
    while(calc_count--){
        EVP_EncryptInit_ex(ctx, EVP_sm4_gcm(), NULL, key, iv);
        EVP_EncryptUpdate(ctx, ciphertext, &plaintext_len, plaintext, plaintext_len);
        EVP_EncryptFinal_ex(ctx, ciphertext + plaintext_len, &plaintext_len);
    }

    EVP_CIPHER_CTX_free(ctx);

    return 0;
}

float calc_speed(int num, clock_t interval){
    uint64_t bits = (uint64_t)num * 1024 * 8;
    uint64_t mbits =  8 * 1024 * 1024;
    float time = (float)interval / CLOCKS_PER_SEC;

    float speed = (float)bits / time;
    
    return speed / mbits;
}

int main(){
    uint8_t key[] = "your-256-bit-key-here!";
    uint8_t iv[] = "your-16-byte-iv";
    uint8_t hmac_key[] = "your-hmac-key";
    clock_t start, end;
    float time;
    int encrypted_count = 30000000;

    start = clock();
    aead_hmac_cbc(key, iv, hmac_key, encrypted_count);
    end = clock();

    time = end - start;
    printf("authenc(sm3,sm4) time: %05fS\n", time / CLOCKS_PER_SEC);
    printf("authenc(sm3,sm4) speed: %06fMbps\n", calc_speed(encrypted_count, end - start));

    start = clock();
    gcm_sm4(key, iv, NULL, encrypted_count);
    end = clock();

    time = end - start;
    printf("gcm(sm4) time: %05fS\n", time / CLOCKS_PER_SEC);
    printf("gcm(sm4) speed: %06fMbps\n", calc_speed(encrypted_count, end - start));

    return 0;
}

// 每次加密1024Bytes数据，一共进行30000000次运算
// authenc(sm3,sm4) time: 147.947678S
// authenc(sm3,sm4) speed: 198.021866Mbps
// gcm(sm4) time: 39.235950S
// gcm(sm4) speed: 746.684448Mbps
