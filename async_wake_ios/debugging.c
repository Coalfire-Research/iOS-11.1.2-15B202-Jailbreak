//  debugging.c
//  Created by Bryce Bearchell on 2/7/18.

#include "debugging.h"
void* kernel_global;
uint64_t kernel_size_global;

void cleanup_debugging()
{
    free(kernel_global);
}

int copy_kernel_to_userspace(mach_port_t tfp0, uint64_t kernel_base)
{
    uint64_t i;
    kern_return_t kr;
    kernel_size_global = 0x1d88000;
    kernel_global = malloc(kernel_size_global);
    uint64_t chunk = 0xfff;
    mach_vm_size_t sz;
    for (i=0; i < kernel_size_global; i+=chunk)
    {
        if (i + chunk > kernel_size_global)
            chunk = kernel_size_global - i;
        kr = mach_vm_read_overwrite(tfp0,
                                    kernel_base+i,
                                    chunk,
                                    (mach_vm_address_t)(kernel_global + i),
                                    &sz);
        if (kr != KERN_SUCCESS)
        {
            printf("[---]\tThere was an error reading the kernel!!!\n");
            sleep(2);
            return 1;
        }
    }
    printf("[+]\tWe've mapped kernel (0x%llx bytes) into userspace!\n", kernel_size_global);
    return 0;
}

void copy_userspace_kernel_to_file(char *fname, uint64_t kernel_base)
{
    printf("[kernel]\tCopying userland kernel to disk [%s]\n", fname);
    int fd = open(fname, O_WRONLY | O_CREAT);
    ssize_t bytes_written = 0;
    printf("[kernel]\tFD = [%d]\n", fd);
    bytes_written = write(fd, kernel_global, kernel_size_global);
    close(fd);
    printf("[kernel]\tCopyied %zd bytes to [%s]\n", bytes_written, fname);
    char *base = malloc(strlen(fname) + 6);
    strcpy(base, fname);
    strcat(base, ".base");
    fd = open(base, O_WRONLY | O_CREAT);
    char *base_s = malloc(0x20);
    sprintf(base_s, "0x%llx", kernel_base);
    write(fd, base_s, strlen(base_s));
    close(fd);
    free(base_s);
    free(base);
    return;
}
