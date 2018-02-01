//
//  jailbreak.h
//  async_wake_ios
//

#ifndef jailbreak_h
#define jailbreak_h

#include <stdio.h>

mach_port_t _kernel_task_port(void);
void* rkmem(uint64_t addr, uint64_t len);
void jailbreak(char* path, mach_port_t tfp0, int phone_type);

#endif /* jailbreak_h */
