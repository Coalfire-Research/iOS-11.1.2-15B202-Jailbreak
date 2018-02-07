//  remap_tfp0_to_hsp4.h
//  Created by Bryce Bearchell on 2/7/18.

#ifndef remap_tfp0_to_hsp4_h
#define remap_tfp0_to_hsp4_h
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
#include "kutils.h"
#include "symbols.h"
#include "code_hiding_for_sanity.h"
#include "find_port.h"
#include "debugging.h"

// Reversed / Inspired by QiLin
int remap_tfp0_to_hsp4(mach_port_t tfp0, uint64_t kernel_base);


#endif /* remap_tfp0_to_hsp4_h */
