#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <stdint.h>
#include <math.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include "aes.h"

#define NOR_SIZE 1024 * 1024
#define NOR_BLOCK_SIZE 64  // 64 bytes
#define NOR_SYSCFG_HEADER_OFFSET 0x4000
#define NOR_IMG_HEADER_OFFSET 0x200
#define NOR_IMG_SECTION_OFFSET 0x0  // in blocks

#define NUM_SYSCFG_ENTRIES 4

#define NVRAM_START 0xFC000
#define NVRAM_SIZE 0x2000
#define NVRAM_COMMON_PARTITION_NAME "common"
#define NVRAM_PANIC_INFO_PARTITION_NAME "APL,OSXPanic"
#define NVRAM_FREE_PARTITION_NAME "wwwwwwwwwwww"

static const uint8_t Img2HashPadding[] = {  0xAD, 0x2E, 0xE3, 0x8D, 0x2D, 0x9B, 0xE4, 0x35, 0x99, 4,
                        0x44, 0x33, 0x65, 0x3D, 0xF0, 0x74, 0x98, 0xD8, 0x56, 0x3B,
                        0x4F, 0xF9, 0x6A, 0x55, 0x45, 0xCE, 0x82, 0xF2, 0x9A, 0x5A,
                        0xC2, 0xBC, 0x47, 0x61, 0x6D, 0x65, 0x4F, 0x76, 0x65, 0x72,
                        0xA6, 0xA0, 0x99, 0x13};

static uint32_t crc32_table[256];
static int crc32_table_computed = 0;

#define key_uid ((uint8_t[]){0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF})

typedef struct nor_header {
    uint32_t fourcc;
    uint32_t block_size;
    uint32_t img_section_offset;
    uint32_t img_section_blk_location;
    uint32_t img_section_len;
    uint32_t unknown1[7];
    uint32_t checksum;
} nor_header;

typedef struct Img2Header {
    uint32_t magic;        /* 0x0 */
    uint32_t imageType;        /* 0x4 */
    uint16_t revision;         /* 0x8 */
    uint16_t security_epoch;   /* 0xa */
    uint32_t flags1;           /* 0xc */
    uint32_t dataLenPadded;    /* 0x10 */
    uint32_t dataLen;          /* 0x14 */
    uint32_t length_in_blocks;         /* 0x18 */
    uint32_t flags2;           /* 0x1c */ /* 0x01000000 has to be unset */
    uint8_t  data_hash[0x40];   /* 0x20 */
    uint32_t next_size;         /* 0x60 */
    uint32_t header_checksum;  /* 0x64 */ /* standard crc32 on first 0x64 bytes */
    uint32_t extension_checksum;        /* 0x68 */
    uint32_t extension_next_size;
    uint32_t extension_type;
    uint32_t extension_options;
    uint8_t  unknown5[0x368]; /* 0x68 */
    uint8_t hash[0x20];
} Img2Header;

typedef struct Img3Header {
    uint32_t magic;
    uint32_t size;
    uint32_t dataSize;
} Img3Header;

typedef struct SyscfgHeader {
    uint32_t shMagic;
    uint32_t shSize;
    uint32_t maxSize;
    uint32_t version;
    uint32_t bigEndian;
    uint32_t keyCount;
} SyscfgHeader;

typedef struct SyscfgEntry {
        u_int32_t       seTag;
        char        seData[16];
} SyscfgEntry;

SyscfgEntry syscfg_entries[NUM_SYSCFG_ENTRIES] = { {'Mod#', "MA623" },
                                                   {'Regn', "B/LL" },
                                                   {'SrNm', "ABCDEFG" },
                                                   {'Batt', "690476146348"}};

typedef struct chrp_nvram_header {
        uint8_t sig;
        uint8_t cksum;
        uint16_t len;
        char    name[12];
        uint8_t data[0];
} chrp_nvram_header;

typedef struct apple_nvram_header {
        struct chrp_nvram_header chrp;
        uint32_t adler;
        uint32_t generation;
        uint8_t padding[8];
} apple_nvram_header;

#define BASE 65521L /* largest prime smaller than 65536 */
#define NMAX 5000
// NMAX (was 5521) the largest n such that 255n(n+1)/2 + (n+1)(BASE-1) <= 2^32-1

#define ADLER_DO1(buf,i)  {s1 += buf[i]; s2 += s1;}
#define ADLER_DO2(buf,i)  ADLER_DO1(buf,i); ADLER_DO1(buf,i+1);
#define ADLER_DO4(buf,i)  ADLER_DO2(buf,i); ADLER_DO2(buf,i+2);
#define ADLER_DO8(buf,i)  ADLER_DO4(buf,i); ADLER_DO4(buf,i+4);
#define ADLER_DO16(buf)   ADLER_DO8(buf,0); ADLER_DO8(buf,8);

uint32_t adler32(uint8_t *buf, int32_t len)
{
    unsigned long s1 = 1; // adler & 0xffff;
    unsigned long s2 = 0; // (adler >> 16) & 0xffff;
    int k;

    while (len > 0) {
        k = len < NMAX ? len : NMAX;
        len -= k;
        while (k >= 16) {
            ADLER_DO16(buf);
            buf += 16;
            k -= 16;
        }
        if (k != 0) do {
            s1 += *buf++;
            s2 += s1;
        } while (--k);
        s1 %= BASE;
        s2 %= BASE;
    }
    return (s2 << 16) | s1;
}

static uint8_t compute_nvram_header_checkbit(apple_nvram_header* header) {
	uint32_t c = header->chrp.sig;
	uint8_t* data = (uint8_t*) header;

	int i;
	for(i = 0x2; i < 0x10; i++) {
		c = (c + data[i]) & 0xffff;
	}

	while(c > 0xff) {
		c = (c >> 8) + (c & 0xff);
	}

	return c;
}

static void make_crc32_table(void)
{
        uint32_t c;
        int n, k;

        for (n = 0; n < 256; n++) {
                c = (uint32_t) n;
                for (k = 0; k < 8; k++) {
                        if (c & 1)
                                c = 0xedb88320L ^ (c >> 1);
                        else
                                c = c >> 1;
                }
                crc32_table[n] = c;
        }
        crc32_table_computed = 1;
}

uint32_t update_crc32(uint32_t crc, const uint8_t *buf,
                         int len)
{
        uint32_t c = crc;
        int n;

        if (!crc32_table_computed)
                make_crc32_table();
        for (n = 0; n < len; n++) {
                c = crc32_table[(c ^ buf[n]) & 0xff] ^ (c >> 8);
        }
        return c;
}

uint32_t crc32(const uint8_t *buf, int len)
{
        return update_crc32(0xffffffffL, buf, len) ^ 0xffffffffL;
}

/*
IMG2 crypto
*/
static void to_le(uint32_t *data, int words) {
    for(int i = 0; i < words; i++) {
        data[i] = ((data[i]>>24)&0xff) | // move byte 3 to byte 0
                    ((data[i]<<8)&0xff0000) | // move byte 1 to byte 2
                    ((data[i]>>8)&0xff00) | // move byte 2 to byte 1
                    ((data[i]<<24)&0xff000000); // byte 0 to byte 3
    }
}

static void calculate_img2_data_hash(void* buffer, int len, uint8_t* hash) {
    /*
    Compute the hash over the IMG2 data.
    */
	SHA_CTX context;
	SHA1_Init(&context);
	SHA1_Update(&context, buffer, len);
	SHA1_Final(hash, &context);

	memcpy(hash + 20, Img2HashPadding, 64 - 20);
	aes_img2verify_encrypt(hash, 64, NULL);
}

static void calculate_img2_hash(Img2Header *header, uint8_t* hash) {
    printf("Computing hash of IMG2 header\n");

    SHA_CTX context;
    SHA1_Init(&context);
    SHA1_Update(&context, (uint8_t *)header, 0x3E0);
    SHA1_Final(hash, &context);

    memcpy(hash + 20, Img2HashPadding, 32 - 20);
    aes_img2verify_encrypt(hash, 32, NULL);
}

void add_img3(void *nor, char *filename, int *cur_block_ind) {
    printf("Adding IMG3 %s\n", filename);
    FILE *f = fopen(filename, "rb");
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);  /* same as rewind(f); */

    char *imgdata = malloc(fsize);
    fread(imgdata, 1, fsize, f);
    fclose(f);

    // modify header
    int img_length_in_blocks = ceil((float)fsize / (float)NOR_BLOCK_SIZE);
    printf("Raw IMG3 length (in bytes): %ld, in blocks: %ld\n", fsize, img_length_in_blocks);
    Img3Header *img_header = (Img3Header *)imgdata;
    printf("--- IMG3 info ---\n");
    printf("Data length: %d (padded: %d)\n", img_header->size, img_header->dataSize);
    printf("\n");
    img_header->size = img_length_in_blocks * NOR_BLOCK_SIZE; // the images should be aligned to a block

    // If we're adding the iBoot image, we have to encrypt the signed hash
    if(strcmp(filename, "data/iboot.img3") == 0) {
        printf("Encrypting hash...\n");
        unsigned char   derivedSeed[16] = {0xdb, 0x1f, 0x5b, 0x33, 0x60, 0x6c, 0x5f, 0x1c, 0x19, 0x34, 0xaa, 0x66, 0x58, 0x9c, 0x06, 0x61};
        unsigned char   derivedKey[16];

        /* derive the key */
        AES_KEY encryptKey, decryptKey;
        AES_set_decrypt_key(key_uid, sizeof(key_uid) * 8, &encryptKey);
        uint8_t ivec[16] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
        AES_cbc_encrypt(derivedSeed, derivedKey, 16, &encryptKey, &ivec, AES_DECRYPT);

        printf("Derived key: 0x");
        for(int i = 0; i < 16; i++) { printf("%02x", derivedKey[i]); }
        printf("\n");

        printf("Plaintext hash: 0x");
        for(int i = 0; i < 128; i++) { printf("%02x", ((uint8_t *)imgdata)[168108 + i]); }
        printf("\n");

        // encrypt the signature using the derived key
        AES_set_encrypt_key(derivedKey, sizeof(key_uid) * 8, &encryptKey);
        uint8_t ivec2[16] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
        uint8_t res[128];
        AES_cbc_encrypt(&imgdata[168108], &imgdata[168108], 0x80, &encryptKey, &ivec2, AES_ENCRYPT);

        printf("Encrypted hash: 0x");
        for(int i = 0; i < 128; i++) { printf("%02x", ((uint8_t *)imgdata)[168108 + i]); }
        printf("\n");

        // // decrypt again
        // AES_set_decrypt_key(derivedKey, sizeof(key_uid) * 8, &decryptKey);
        // uint8_t res2[128];
        // uint8_t ivec3[16] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
        // AES_cbc_encrypt(&imgdata[168108], &imgdata[168108], 0x80, &decryptKey, &ivec3, AES_DECRYPT);

        // printf("Decrypted hash: 0x");
        // for(int i = 0; i < 128; i++) { printf("%02x", ((uint8_t *)imgdata)[168108 + i]); }
        // printf("\n");
    }

    // copy image
    uint32_t img_section_offset = NOR_IMG_SECTION_OFFSET * NOR_BLOCK_SIZE;
    uint32_t addr_offset = img_section_offset + *cur_block_ind * NOR_BLOCK_SIZE;
    printf("Copying image to address 0x%08x\n", addr_offset);
    memcpy(nor + addr_offset, imgdata, fsize);
    (*cur_block_ind) += img_length_in_blocks;
    printf("\n");
}

void setup_nor_partition(void *nor) {
    // prepare the header
    nor_header *header = malloc(sizeof(nor_header));
    header->fourcc = 0x494d4732; // 2GMI
    header->block_size = NOR_BLOCK_SIZE;
    header->img_section_offset = NOR_IMG_SECTION_OFFSET;
    header->img_section_blk_location = NOR_IMG_HEADER_OFFSET;
    
    // add IMG3 images
    int cur_block_ind = NOR_IMG_HEADER_OFFSET; // the current block index, counted from the img2 partition start
    add_img3(nor, "data/llb.img3", &cur_block_ind);
    add_img3(nor, "data/iboot.img3", &cur_block_ind);
    add_img3(nor, "data/dtree.img3", &cur_block_ind);
    add_img3(nor, "data/applelogo.img3", &cur_block_ind);
    add_img3(nor, "data/needservice.img3", &cur_block_ind);
    add_img3(nor, "data/batterylow0.img3", &cur_block_ind);
    add_img3(nor, "data/batterylow1.img3", &cur_block_ind);
    add_img3(nor, "data/recoverymode.img3", &cur_block_ind);
    add_img3(nor, "data/glyphcharging.img3", &cur_block_ind);
    add_img3(nor, "data/glyphplugin.img3", &cur_block_ind);

    header->img_section_len = cur_block_ind; // TODO hard-coded
    header->checksum = crc32((uint8_t *)header, 0x30);
    memcpy(nor, header, sizeof(nor_header));
}

int main(int argc, char *argv[]) {
    aes_setup();
    printf("Preparing NOR...\n");
    
    // prepare 1MB of nor
    void *nor = malloc(NOR_SIZE);
    memset(nor, 0x0, NOR_SIZE);
    
    setup_nor_partition(nor);

    // // prepare syscfg
    // SyscfgHeader *syscfg_header = malloc(sizeof(SyscfgHeader));
    // syscfg_header->shMagic = 'SCfg';
    // syscfg_header->maxSize = 0x2000;
    // syscfg_header->version = 0x00010001;
    // syscfg_header->shSize = 200;
    // syscfg_header->keyCount = NUM_SYSCFG_ENTRIES;
    // memcpy(nor + NOR_SYSCFG_HEADER_OFFSET, syscfg_header, sizeof(SyscfgHeader));

    // // write syscfg entries
    // for(int index = 0; index < NUM_SYSCFG_ENTRIES; index++) {
    //     memcpy(nor + NOR_SYSCFG_HEADER_OFFSET + sizeof(SyscfgHeader) + sizeof(SyscfgEntry) * index, &syscfg_entries[index], sizeof(SyscfgEntry));
    // }

    // prepare NVRAM
    printf("Preparing NVRAM...\n");

    // create header
    uint8_t *nvram_data = (uint8_t *)malloc(NVRAM_SIZE);
    apple_nvram_header *nvram_header = (apple_nvram_header *)nvram_data;
    nvram_header->chrp.len = 0x2;
    nvram_header->chrp.sig = 0x5A;
    char nvram_name[5] = {'n', 'v', 'r', 'a', 'm'};
    memcpy(nvram_header->chrp.name, &nvram_name, 5);
    nvram_header->generation = 0x10;

    // create "common" partition with env variables
    chrp_nvram_header *partition_header = (chrp_nvram_header *)(nvram_data + sizeof(apple_nvram_header));
    char *env = "debug-uarts=1";
    memcpy(partition_header->data, env, strlen(env) + 1);
    partition_header->sig = 0x70;
    partition_header->len = 0x80;
    memcpy(partition_header->name, &NVRAM_COMMON_PARTITION_NAME, sizeof(NVRAM_COMMON_PARTITION_NAME));
    partition_header->cksum = compute_nvram_header_checkbit((apple_nvram_header *) partition_header);

    // create the "panic info" partition
    chrp_nvram_header *panic_partition_header = (chrp_nvram_header *)(nvram_data + sizeof(apple_nvram_header) + 0x800);
    panic_partition_header->sig = 0xA1;
    panic_partition_header->len = 0x81;
    memcpy(panic_partition_header->name, &NVRAM_PANIC_INFO_PARTITION_NAME, sizeof(NVRAM_PANIC_INFO_PARTITION_NAME));
    panic_partition_header->cksum = compute_nvram_header_checkbit((apple_nvram_header *) panic_partition_header);

    // create the "free" partition
    chrp_nvram_header *free_partition_header = (chrp_nvram_header *)(nvram_data + 0x1030);
    free_partition_header->sig = 0x7F;
    free_partition_header->len = 0xFD;
    memcpy(free_partition_header->name, &NVRAM_FREE_PARTITION_NAME, sizeof(NVRAM_FREE_PARTITION_NAME));
    free_partition_header->cksum = compute_nvram_header_checkbit((apple_nvram_header *) free_partition_header);

    // update header checksums
    nvram_header->adler = adler32(nvram_data + 0x14, NVRAM_SIZE - 0x14);
    nvram_header->chrp.cksum = compute_nvram_header_checkbit(nvram_header);

    // write NVRAM
    memcpy(nor + NVRAM_START, nvram_data, NVRAM_SIZE);

    // write NOR
    FILE *f = fopen("nor.bin", "wb");
    fwrite(nor, sizeof(char), NOR_SIZE, f);
    fclose(f);
    
    printf("NOR prepared!\n");
}
