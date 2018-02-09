#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <mach/mach.h>

#include "mach_vm.h"
#include "jailbreak.h"
#include "symbols.h"
#include "kutils.h"
#include "kmem.h"
#include "code_hiding_for_sanity.h"


uint64_t leaked_proc;
uint64_t amfid_base;
mach_port_t kernel_task_port = MACH_PORT_NULL;

extern mach_port_t tfp0;
extern uint64_t rk64(uint64_t kaddr);
extern uint64_t old_amfid_MISVSACI;


/*
Place inside of the async_wake_ios folder and compile via:
`xcrun -sdk iphoneos -find clang` -Os -isysroot `xcrun -sdk iphoneos -show-sdk-path` -F`xcrun -sdk iphoneos -show-sdk-path`/System/Library/Frameworks -arch arm64 find_port.c symbols.c kmem.c kutils.c sha256.c code_hiding_for_sanity.c nerfbat.c -o nerfbat
jtool --sign --inplace --ent ../examples/ent.xml nerfbat

*/

uint64_t amfid_base;
mach_port_t amfid_exception_port = MACH_PORT_NULL;


int main(int argc, char** argv)
{
    // THIS IS BOILERPLATE TO PROPERLY GAIN TFP0 AND INITIALIZE INTERNALS
    offsets_init();
    task_t kernel_task;
    host_get_special_port(mach_host_self(), HOST_LOCAL_NODE, 4, &kernel_task);
    task_self_addr();
    kernel_task_port = kernel_task;
    tfp0 = kernel_task;
    // THIS IS BOILERPLATE TO PROPERLY GAIN TFP0 AND INITIALIZE INTERNALS

    printf("[NERFBAT]\tVersion 0.3b (tfp = 0x%x)\n", tfp0);
    printf("[NERFBAT]\tSleeping 5 seconds to get handle on amfid\n");
    sleep(5);

    set_platform_attribs(get_proc_block(getpid()), tfp0);
    

    uint32_t amfid_pid = 0;
    kern_return_t kr;
    mach_port_name_t amfid_port = 0;
    int failure = 0;
    int first_patch = 1;
    uint64_t old_amfid_MISVSACI_local = 0;

    while (1)
    {
        if (failure || get_pid_from_name("amfid") != amfid_pid)
        {
            amfid_pid = get_pid_from_name("amfid");
            printf("[NERFBAT]\t[i]\tAMFID pid == %d\n", amfid_pid);
            uint64_t amfid_proc = get_proc_block(amfid_pid);
            amfid_base = amfid_proc;
            printf("[NERFBAT]\t[i]\tAMFID proc bloc == 0x%llx\n", amfid_proc);
            //We need to enable amfid to allow us to get a port to it
            printf("[NERFBAT]\t[i]\tAMFID pid == %d\n", amfid_pid);
            uint64_t amfid_task = get_proc_block(amfid_pid);
            printf("[NERFBAT]\t[i]\tGot amfid pid at 0x%llx\n", amfid_task);
            uint64_t vnode_info = rk64(amfid_task+0x248);
            printf("[NERFBAT]\t[i]\tVNODE INFO : 0x%llx\n", vnode_info);
            uint64_t ubc_info = rk64(vnode_info+0xf*sizeof(uint64_t));
            printf("[NERFBAT]\t[i]\tMy UBC INFO is 0x%llx\n", ubc_info);
            uint64_t blob = rk64(ubc_info+0xa*sizeof(uint64_t));
            char *csb = malloc(0xa8);
            mach_vm_address_t sz = 0;
            mach_vm_read_overwrite(tfp0, (mach_vm_address_t)blob, 0xa8, (mach_vm_address_t)csb, &sz);
            printf("[NERFBAT]\t[i]\tCurrent 0xa4 = 0x%02x\n", (int)*(char *)((char *)csb + 0xA4));
            *(char *)((char *)csb + 0xA4) = (*((char *)csb + 0xA4) & 0xFE) | 1;
            printf("[NERFBAT]\t[i]\tNew 0xa4 = 0x%02x\n", (int)*(char *)((char *)csb + 0xA4));
            printf("[NERFBAT]\t[i]\tCurrent 0xc = 0x%04x\n", *(uint32_t *)((uint32_t *)csb + 0xc));
            *(uint32_t *)((uint32_t *)csb + 0xc) = *((uint32_t *)csb + 0xc) | htonl(0x22000005);
            printf("[NERFBAT]\t[i]\tCurrent 0xc = 0x%04x\n", *(uint32_t *)((uint32_t *)csb + 0xc));
            mach_vm_write(tfp0, blob, (vm_offset_t)csb, 0xa8);
            free(csb);

            printf("[NERFBAT]\t[i]\ttask for pid 0 = 0x%x\n", tfp0);
            kr = task_for_pid(mach_task_self(), amfid_pid, &amfid_port);
            if (kr != KERN_SUCCESS)
            {
                printf("[NERFBAT]\t[-]\tTHERE WAS AN ERROR GETTING TFP0 (HSP4) for AMFID\n");
                failure = 1;
            }
            printf("[NERFBAT]\t[i]\tPATCHING AMFID on port = 0x%x\n", amfid_port);
            if (first_patch)
            {
                old_amfid_MISVSACI_local = patch_amfid(amfid_port);
                old_amfid_MISVSACI = old_amfid_MISVSACI_local;
                first_patch = 0;
            } else {
                unpatch_amfid(amfid_port, old_amfid_MISVSACI_local);
                patch_amfid(amfid_port);
            }
        }
        sleep(10);
    }
}
