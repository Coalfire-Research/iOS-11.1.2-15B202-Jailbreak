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

/*

Place inside of the async_wake_ios folder and compile via:
`xcrun -sdk iphoneos -find clang` -Os -isysroot `xcrun -sdk iphoneos -show-sdk-path` -F`xcrun -sdk iphoneos -show-sdk-path`/System/Library/Frameworks -arch arm64 find_port.c symbols.c kmem.c kutils.c sha256.c code_hiding_for_sanity.c webserver.c ws.c -o ws
jtool --sign --inplace --ent ../examples/ent.xml ws

*/
extern mach_port_t tfp0;
extern uint64_t rk64(uint64_t kaddr);

int main(int argc, char** argv)
{
	if (argc != 2)
	{
		printf("Usage\n\t%s kernel_base\n", argv[0]);
		return -1;
	}
    uint64_t kernel_base = strtoull(argv[1], NULL, 0x10);

    // THIS IS BOILERPLATE TO PROPERLY GAIN TFP0 AND INITIALIZE INTERNALS
    offsets_init();
    task_t kernel_task;
    host_get_special_port(mach_host_self(), HOST_LOCAL_NODE, 4, &kernel_task);
    task_self_addr();
    kernel_task_port = kernel_task;
    tfp0 = kernel_task;
    // THIS IS BOILERPLATE TO PROPERLY GAIN TFP0 AND INITIALIZE INTERNALS
    
    printf("Using kernel base 0x%llx\n", kernel_base);
    printf("Kernel base * == 0x%llx\n", rk64(kernel_base));
    
    init_ws(kernel_task, kernel_base);
    wsmain(0);
}
