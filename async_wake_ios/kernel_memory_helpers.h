#ifndef _KERNEL_MEMORY_HELPERS_H
#define _KERNEL_MEMORY_HELPERS_H

#include <mach/mach.h>

void init_kernel_memory_helpers(mach_port_t ktp);
mach_port_t _kernel_task_port(void);

uint64_t r64(mach_port_t tp, uint64_t addr);
uint32_t r32(mach_port_t tp, uint64_t addr);
void w8(mach_port_t tp, uint64_t addr, uint32_t val);
void w32(mach_port_t tp, uint64_t addr, uint32_t val);
void w64(mach_port_t tp, uint64_t addr, uint64_t val);
void* rmem(mach_port_t tp, uint64_t addr, uint64_t len);

uint64_t rk64(uint64_t addr);
uint32_t rk32(uint64_t addr);
void wk8(uint64_t addr, uint8_t val);
void wk32(uint64_t addr, uint32_t val);
void wk64(uint64_t addr, uint64_t val);
void* rkmem(uint64_t addr, uint64_t len);


#endif

