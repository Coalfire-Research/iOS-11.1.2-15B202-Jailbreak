#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>

#include <mach-o/loader.h>
#include <mach/machine.h>

#include <CommonCrypto/CommonDigest.h>

#include "cdhash.h"

// this code has very minimal mach-o parsing - it works for thin arm64 binaries though

// these three structure definitions are from opensource.apple.come from codesign.c in Security

/*
 * Structure of an embedded-signature SuperBlob
 */
typedef struct __BlobIndex {
  uint32_t type;                                  /* type of entry */
  uint32_t offset;                                /* offset of entry */
} CS_BlobIndex;

typedef struct __SuperBlob {
  uint32_t magic;                                 /* magic number */
  uint32_t length;                                /* total length of SuperBlob */
  uint32_t count;                                 /* number of index entries following */
  CS_BlobIndex index[];                   /* (count) entries */
  /* followed by Blobs in no particular order as indicated by offsets in index */
} CS_SuperBlob;


/*
 * C form of a CodeDirectory.
 */
typedef struct __CodeDirectory {
  uint32_t magic;                                 /* magic number (CSMAGIC_CODEDIRECTORY) */
  uint32_t length;                                /* total length of CodeDirectory blob */
  uint32_t version;                               /* compatibility version */
  uint32_t flags;                                 /* setup and mode flags */
  uint32_t hashOffset;                    /* offset of hash slot element at index zero */
  uint32_t identOffset;                   /* offset of identifier string */
  uint32_t nSpecialSlots;                 /* number of special hash slots */
  uint32_t nCodeSlots;                    /* number of ordinary (code) hash slots */
  uint32_t codeLimit;                             /* limit to main image signature range */
  uint8_t hashSize;                               /* size of each hash in bytes */
  uint8_t hashType;                               /* type of hash (cdHashType* constants) */
  uint8_t spare1;                                 /* unused (must be zero) */
  uint8_t pageSize;                               /* log2(page size in bytes); 0 => infinite */
  uint32_t spare2;                                /* unused (must be zero) */
  /* followed by dynamic content as located by offset fields above */
} CS_CodeDirectory;

size_t max_input_size = 20*1024*1024; // limit input binaries to 20MB

// run time assertion, exits on failure
void assert(int condition, char* failure_message) {
  if (!condition) {
    printf("[-] %s\n", failure_message);
    exit(EXIT_FAILURE);
  }
}

void* read_file(char* target, size_t* size_out) {
  int err = 0;
  struct stat st = {0};
  
  err = stat(target, &st);
  assert(err == 0, "can't stat input");
  
  size_t size = st.st_size;
  assert(size > 0, "input empty");
  assert(size < max_input_size, "input too large");
  
  void* buf = malloc(size);
  assert(buf != NULL, "can't allocate buffer for input file");
  
  int fd = open(target, O_RDONLY);
  assert(fd != -1, "can't open input file");
  
  ssize_t amount_read = read(fd, buf, size);
  assert(amount_read > 0, "can't read input file");
  assert((size_t)amount_read == size, "read truncated");
  
  close(fd);
  
  *size_out = size;
  return buf;
}

void* find_cs_blob(uint8_t* buf, size_t size) {
  struct mach_header_64* hdr = (struct mach_header_64*)buf;
  
  uint32_t ncmds = hdr->ncmds;
  
  assert(ncmds < 1000, "too many load commands");
  
  uint8_t* commands = (uint8_t*)(hdr+1);
  for (uint32_t command_i = 0; command_i < ncmds; command_i++) {
    //assert(commands + sizeof(struct load_command) < end, "invalid load command");
    
    struct load_command* lc = (struct load_command*)commands;
    //assert(commands + lc->cmdsize <= end, "invalid load command");
    
    if (lc->cmd == LC_CODE_SIGNATURE) {
      struct linkedit_data_command* cs_cmd = (struct linkedit_data_command*)lc;
      printf("found LC_CODE_SIGNATURE blob at offset +0x%x\n", cs_cmd->dataoff);
      return ((uint8_t*)buf) + cs_cmd->dataoff;
    }
    
    commands += lc->cmdsize;
  }
  return NULL;
}

// do a SHA1 hash of the CodeDirectory
// scratch that do SHA256
void hash_cd(CS_CodeDirectory* cd, uint8_t* hash_buf) {
//  uint8_t* buf = (uint8_t*) cd;
//  CC_LONG len = ntohl(cd->length);
  
    //extern uint64_t doSHA256(uint64_t a1, unsigned int a2, uint64_t a3); //TODO
    //doSHA256((uint64_t)buf, len, (uint64_t)&hash_buf); //TODO
    //this was a test
    /*
     replace this and you're golden
  CC_SHA1_CTX context;
  CC_SHA1_Init(&context);
  CC_SHA1_Update(&context, buf, len);
  CC_SHA1_Final(hash_buf, &context);
     */
  
//  printf("hash for amfid is:");
//  for (int i = 0; i < CC_SHA1_DIGEST_LENGTH; i++) {
//    printf("%02x", hash_buf[i]);
//  }
//  printf("\n");
}

void find_cd_hash(uint8_t* buf, size_t size, uint8_t* hash_buf) {
  CS_SuperBlob* sb = (CS_SuperBlob*)find_cs_blob(buf, size);
  
  for (uint32_t i = 0; i < ntohl(sb->count); i++) {
    CS_BlobIndex* bi = &sb->index[i];
    uint8_t* blob = ((uint8_t*)sb) + (htonl(bi->offset));
    if (htonl(*(uint32_t*)blob) == 0xfade0c02) {
      CS_CodeDirectory* cd = (CS_CodeDirectory*)blob;
      printf("found code directory\n");
      hash_cd(cd, hash_buf);
      // only want the first one
      return;
    }
  }
}

void get_hash_for_amfid(char* path, uint8_t* hash_buf) {
  size_t size = 0;
  uint8_t* file_buf = read_file(path, &size);
  find_cd_hash(file_buf, size, hash_buf);
  free(file_buf);
}

