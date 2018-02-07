//  debugging.h
//  Created by Bryce Bearchell on 2/7/18.

#ifndef debugging_h
#define debugging_h
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <mach-o/loader.h>
#include <mach/machine.h>
#include "kmem.h"

int copy_kernel_to_userspace(mach_port_t tfp0, uint64_t kernel_base);
void copy_userspace_kernel_to_file(char *fname, uint64_t kernel_base);
void cleanup_debugging(void);

#endif /* debugging_h */
