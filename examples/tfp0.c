#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <mach/mach.h>

#include "mach_vm.h"
#include "webserver.h"
#include "symbols.h"
#include "kutils.h"
#include "code_hiding_for_sanity.h"

uint64_t leaked_proc;
uint64_t amfid_base;
mach_port_t amfid_exception_port = MACH_PORT_NULL;
mach_port_t kernel_task_port = MACH_PORT_NULL;

extern mach_port_t tfp0;
extern uint64_t rk64(uint64_t kaddr);

int main(int argc, char** argv, char** envp)
{
	// THIS IS BOILERPLATE TO PROPERLY GAIN TFP0 AND INITIALIZE INTERNALS
    offsets_init();
    task_t kernel_task;
    host_get_special_port(mach_host_self(), HOST_LOCAL_NODE, 4, &kernel_task);
    task_self_addr();
    kernel_task_port = kernel_task;
    tfp0 = kernel_task;
    // THIS IS BOILERPLATE TO PROPERLY GAIN TFP0 AND INITIALIZE INTERNALS

	printf("Task for pid 0 (Host Special Port 4) = 0x%x\n", tfp0);
}
