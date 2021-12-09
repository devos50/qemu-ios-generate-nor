#ifndef AES_H
#define AES_H

void aes_setup();
void aes_img2verify_encrypt(void* data, int size, const void* iv);

#endif