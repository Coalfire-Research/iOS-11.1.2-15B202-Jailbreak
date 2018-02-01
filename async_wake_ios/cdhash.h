#ifndef cdhash_h
#define cdhash_h

#include <CommonCrypto/CommonDigest.h>

#define AMFID_HASH_SIZE CC_SHA256_DIGEST_LENGTH

void get_hash_for_amfid(char* path, uint8_t* hash_buf);
void* find_cs_blob(uint8_t* buf, size_t size);

#endif
