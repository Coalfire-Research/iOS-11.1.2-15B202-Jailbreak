//
//  written_code_hiding_for_sanity.c
//  async_wake_ios
//
//
#ifndef CODE_HIDING
#define CODE_HIDING

// externs
#include <CommonCrypto/CommonDigest.h>
extern void proc_name(int pid, char * buf, int size);
extern uint64_t kernel_leak;

// accessors
#pragma pack(4)
typedef struct {
    mach_msg_header_t Head;
    mach_msg_body_t msgh_body;
    mach_msg_port_descriptor_t thread;
    mach_msg_port_descriptor_t task;
    NDR_record_t NDR;
} exception_raise_request; // the bits we need at least

typedef struct {
    mach_msg_header_t Head;
    NDR_record_t NDR;
    kern_return_t RetCode;
} exception_raise_reply;
#pragma pack()
#define AMFID_HASH_SIZE CC_SHA256_DIGEST_LENGTH

// Bryce's code
void do_execution_test(char* app_path);
void dump_pointer(mach_port_t tfp0, addr64_t addr, uint64_t max_size);
uint32_t get_pid_from_name(char* name);
void write_file(char *f_name, char *f_data, size_t f_size);
void ls(char *cwd);
void listdir(const char *name, int indent);
void cat(char *f_name);
void copy_creds_from_to(uint64_t proc_from, uint64_t proc_to);
char* dump_pointer_html(mach_port_t tfp0, addr64_t addr, uint64_t max_size);
uint64_t dump_kernel(mach_port_t tfp0, uint64_t kernel_base);
int give_me_root_privs(mach_port_t tfp0);
int copy_file_from_container(char* container_path, char *src, char *dest);
void neuter_updates(void);
void ps_html(int sfd);

// re'd from QiLin
uint32_t exec_wrapper(char* prog_name,
                      char* arg1,
                      char* arg2,
                      char* arg3,
                      char* arg4,
                      char* arg5,
                      mach_port_t tfp0);
void set_platform_attribs(uint64_t proc, mach_port_t tfp0);
void nerf_hammer_AMFID(uint32_t amfid_pid, void* amfid_exception_handler);
char* get_binary_hash(char* filename);
void modify_entitlements(char* entitlements, mach_port_t tfp0);

// mach portal
uint64_t binary_load_address(mach_port_t tp);

// xerub's code (modified)
void xerub_remount_code(uint64_t kaslr, int phone_type);

//harvested from: https://github.com/maximehip/mach_portal/blob/0d7470ae0896519ba4a97d06dfc17d0b6eee1042/patch_amfid.c
void get_hash_for_amfid(char* path, uint8_t* hash_buf);
void w8(mach_port_t tp, uint64_t addr, uint8_t val);
void w32(mach_port_t tp, uint64_t addr, uint32_t val);
void w64(mach_port_t tp, uint64_t addr, uint64_t val);

// copied / reworked from mach_portal (Ian Beer's code)
void* rkmem(uint64_t addr, uint64_t len);
void* rmem(mach_port_t tp, uint64_t addr, uint64_t len);
uint64_t get_proc_block(uint32_t target);
uint64_t find_proc(char* target_p_comm);
void* amfid_exception_handler(void* arg);
int set_exception_handler(mach_port_t amfid_task_port);
uint64_t patch_amfid(mach_port_t amfid_task_port);
int unpatch_amfid(mach_port_t amfid_task_port, uint64_t old_amfid_MISVSACI);

//benjibob's code
uint64_t impersonate(uint32_t target, mach_port_t tfp0);
void set_my_pid(uint64_t orig_cred);

// use get_proc_block instead
uint64_t proc_for_pid(uint32_t pid);

#define TFP_OFFSET_15B202 0x183a710
#define LEAK_OFFSET_15B202 0x13f8000

#define amfid_MISValidateSignatureAndCopyInfo_import_offset 0x4150

#endif




/*
For reference:
 
 
struct stat {
    uint32_t       st_dev;
    uint64_t       st_ino;
    uint16_t      st_mode;
    uint16_t     st_nlink;
    uint32_t       st_uid;
    uint32_t       st_gid;
}
    dev_t       st_rdev;
#if !defined(_POSIX_C_SOURCE) || defined(_DARWIN_C_SOURCE)
    struct  timespec st_atimespec;
    struct  timespec st_mtimespec;
    struct  timespec st_ctimespec;
#else
    time_t      st_atime;
    long        st_atimensec;
    time_t      st_mtime;
    long        st_mtimensec;
    time_t      st_ctime;
    long        st_ctimensec;
#endif
    off_t       st_size;
    blkcnt_t    st_blocks;
    blksize_t   st_blksize;
    __uint32_t  st_flags;
    __uint32_t  st_gen;
    __int32_t   st_lspare;
    __int64_t   st_qspare[2]
};

struct stat {
    __int32       st_dev;
    __int64       st_ino;
    __int16      st_mode;
    __int16     st_nlink;
    __int32       st_uid;
    __int32       st_gid;
    __int32       st_rdev;
    long      st_atime;
    long        st_atimensec;
    long      st_mtime;
    long        st_mtimensec;
    long      st_ctime;
    long        st_ctimensec;
    __int64       st_size;
    __int64    st_blocks;
    __int32   st_blksize;
    __int32  st_flags;
    __int32  st_gen;
    __int32   st_lspare;
    __int64   st_qspare[2];
};


struct fstat
{
  __int32 st_dev;
  __int64 st_ino;
  __int16 st_mode;
  __int16 st_nlink;
  __int32 st_uid;
  __int32 st_gid;
  __int32 st_rdev;
  __int64 st_atime;
  __int64 st_atimensec;
  __int64 st_mtime;
  __int64 crap1;
  __int64 crap2;
  __int64 crap3;
  __int64 crap4;
  __int64 crap5;
  __int64 crap6;
  __int64 st_size;
  __int64 st_blocks;
  __int32 st_blksize;
  __int32 st_flags;
  __int32 st_gen;
  __int32 st_lspare;
  __int64 st_qspare[2];
};

*/

