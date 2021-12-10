#include <sys/types.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/aes.h>

#include "aes.h"

#define AES_KEY_LENGTH 16

typedef enum AESKeyType {
    AESCustom = 0,
    AESUID = 1
} AESKeyType;

static const uint8_t key_uid[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
static const uint8_t GenImg2VerifyData[] =	{0xCD, 0xF3, 0x45, 0xB3, 0x12, 0xE7, 0x48, 0x85, 0x8B, 0xBE, 0x21, 0x47, 0xF0, 0xE5, 0x80, 0x88};
static const uint8_t GenImg2VerifyIV[] =	{0x11, 0x5D, 0x70, 0x41, 0x82, 0x4B, 0x98, 0x6F, 0xBB, 0x99, 0x6C, 0x9C, 0x69, 0x78, 0xF1, 0xA5};
static uint8_t KeyImg2Verify[16];

static void to_le2(uint32_t *data, int words) {
    for(int i = 0; i < words; i++) {
        data[i] = ((data[i]>>24)&0xff) | // move byte 3 to byte 0
                    ((data[i]<<8)&0xff0000) | // move byte 1 to byte 2
                    ((data[i]>>8)&0xff00) | // move byte 2 to byte 1
                    ((data[i]<<24)&0xff000000); // byte 0 to byte 3
    }
}

void aes_encrypt(uint8_t* data, int size, AESKeyType key_type, const void* key, const void* iv) {
	AES_KEY encryption_key;
	uint32_t *key_words = malloc(32);
	memset(key_words, 0, 32);
	int key_size = 0;
	if(key_type == 0) { // CUSTOM KEY
	    key_size = 32;
	    memcpy(key_words+4, (uint8_t *)key, 16);
	}
	else if(key_type == 1) { // UID key
		key_size = 16;
		memcpy(key_words, (uint8_t *)key, 16);
	}

	AES_set_decrypt_key((uint8_t *)key_words, key_size * 8, &encryption_key);

	uint8_t *iv_enc = malloc(AES_KEY_LENGTH);
	memset(iv_enc, 0x0, AES_BLOCK_SIZE);
	if(iv) {
		memcpy(iv_enc, iv, AES_BLOCK_SIZE);
	}

	AES_cbc_encrypt(data, data, size, &encryption_key, (uint8_t *)iv_enc, AES_ENCRYPT);
}

void aes_img2verify_encrypt(void* data, int size, const void* iv) {
	aes_encrypt(data, size, AESCustom, KeyImg2Verify, iv);
}

void aes_setup() {
	memcpy(KeyImg2Verify, GenImg2VerifyData, 16);
	aes_encrypt(KeyImg2Verify, 16, AESUID, key_uid, GenImg2VerifyIV);
	to_le2((uint32_t *)KeyImg2Verify, 4);
}