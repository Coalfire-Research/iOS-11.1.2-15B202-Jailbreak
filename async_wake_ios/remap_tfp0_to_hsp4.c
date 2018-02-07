//  remap_tfp0_to_hsp4.c
//  Created by Bryce Bearchell on 2/7/18.


#include "remap_tfp0_to_hsp4.h"
extern void* kernel_global;
extern uint64_t kernel_size_global;

// Reversed / Inspired by QiLin
// by recommendation for userspace hsp4 by stek29
int remap_tfp0_to_hsp4(mach_port_t tfp0, uint64_t kernel_base)
{
    uint64_t index;
    mach_port_t port;
    uint64_t my_proc = get_proc_block(getpid());
    printf("[i]\t[remap_tfp0_to_hsp4]\tI'm at 0x%llx\n", my_proc);
    host_get_special_port(mach_host_self(), 0xFFFFFFFF, 0x2, &port);
    port = mach_host_self();
    printf("[+]\t[remap_tfp0_to_hsp4]\ttfp0 = 0x%x\n", tfp0);
    printf("[+]\t[remap_tfp0_to_hsp4]\tHost_priv is 0x%x\n", port);
    uint64_t proc_data = rk64(my_proc + 0x18);
    uint64_t ipc_space = rk64(proc_data + 0x308);
    printf("[+]\t[remap_tfp0_to_hsp4]\tMy process IPC space is here: 0x%llx\n", ipc_space);
    uint64_t itks = rk64(ipc_space + 0x28);
    uint64_t itkproc = rk64(my_proc + 0x18);
    uint64_t real_host = 0, tfp0_ptr = 0, guess;
    if (itks == itkproc)
    {
        uint32_t num_count = rk32(ipc_space + 0x14);
        uint64_t ipc_structure_base = rk64(ipc_space + 0x20);
        for (index=0; index < num_count; index++)
        {
            if ( !rk32(ipc_structure_base + 0x18 * index + 0x10) && rk64(ipc_structure_base + 0x18 * index))
            {
                guess = (index << 8) + (uint64_t)((rk64(ipc_structure_base + 0x18LL * (signed int)index + 8) & 0xFF000000) >> 0x18);
                if (port == guess)
                {
                    real_host = rk64(ipc_structure_base + 0x18 * (signed int)index);
                    printf("[i]\t[remap_tfp0_to_hsp4]\tGot Real Host @0x%llx\n", real_host);
                }
                if (guess == tfp0)
                {
                    tfp0_ptr = rk64(ipc_structure_base + 0x18 * (signed int)index);
                    printf("[i]\t[remap_tfp0_to_hsp4]\tGot TFP0 @0x%llx\n", tfp0_ptr);
                }
            }
        }
        if (tfp0_ptr && real_host)
        {
            printf("[+]\t[remap_tfp0_to_hsp4]\tWoop woop, writing hsp4 to tfp0\n");
            wk64(rk64(real_host + 0x68)+0x30, (uint64_t)tfp0_ptr);
        } else {
            printf("[-]\t[remap_tfp0_to_hsp4]\tWelp, we fail at finding the refs....\n");
        }
    } else {
        printf("[-]\t[remap_tfp0_to_hsp4]\tSanity check failed, I can't move tfp0 into hsp4 :(\n");
    }
    return 0;
}
