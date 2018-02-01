#include <stdio.h>
#include <stdlib.h>

#include <mach/mach.h>

kern_return_t mach_vm_read
(
 vm_map_t target_task,
  mach_vm_address_t address,
  mach_vm_size_t size,
  vm_offset_t *data,
  mach_msg_type_number_t *dataCnt
);

kern_return_t mach_vm_write
(
  vm_map_t target_task,
  mach_vm_address_t address,
  vm_offset_t data,
  mach_msg_type_number_t dataCnt
);

kern_return_t mach_vm_deallocate
(
  vm_map_t target,
  mach_vm_address_t address,
  mach_vm_size_t size
);

mach_port_t kernel_task_port = MACH_PORT_NULL;

void init_kernel_memory_helpers(mach_port_t ktp) {
  kernel_task_port = ktp;
}

mach_port_t _kernel_task_port() {
  return kernel_task_port;
}

/* read */

uint32_t r32(mach_port_t tp, uint64_t addr) {
  kern_return_t err;
  vm_offset_t buf = 0;
  mach_msg_type_number_t num = 0;
  err = mach_vm_read(tp,
                     addr,
                     4,
                     &buf,
                     &num);
  if (err != KERN_SUCCESS) {
    printf("read failed!\n");
    return 0;
  }
  uint32_t val = *(uint32_t*)buf;
  mach_vm_deallocate(mach_task_self(), buf, num);
  return val;
}

uint64_t r64(mach_port_t tp, uint64_t addr) {
  kern_return_t err;
  vm_offset_t buf = 0;
  mach_msg_type_number_t num = 0;
  err = mach_vm_read(tp,
                     addr,
                     8,
                     &buf,
                     &num);
  if (err != KERN_SUCCESS){
    printf("read failed!\n");
    return 0;
  }
  uint64_t val = *(uint64_t*)buf;
  mach_vm_deallocate(mach_task_self(), buf, num);
  return val;
}

void* rmem(mach_port_t tp, uint64_t addr, uint64_t len) {
  kern_return_t err;
  vm_offset_t buf = 0;
  mach_msg_type_number_t num = 0;
  err = mach_vm_read(tp,
                     addr,
                     len,
                     &buf,
                     &num);
  if (err != KERN_SUCCESS) {
    printf("read failed\n");
    return NULL;
  }
  uint8_t* outbuf = malloc(len);
  memcpy(outbuf, (void*)buf, len);
  mach_vm_deallocate(mach_task_self(), buf, num);
  return outbuf;
}

/* write */

void w8(mach_port_t tp, uint64_t addr, uint8_t val) {
  kern_return_t err =
  mach_vm_write(tp,
                addr,
                (vm_offset_t)&val,
                1);
  if (err != KERN_SUCCESS) {
    printf("write failed\n");
  }
}

void w32(mach_port_t tp, uint64_t addr, uint32_t val) {
  kern_return_t err =
  mach_vm_write(tp,
                addr,
                (vm_offset_t)&val,
                4);
  if (err != KERN_SUCCESS) {
    printf("write failed\n");
  }
}

void w64(mach_port_t tp, uint64_t addr, uint64_t val) {
  kern_return_t err =
  mach_vm_write(tp,
                addr,
                (vm_offset_t)&val,
                8);
  if (err != KERN_SUCCESS) {
    printf("write failed\n");
  }
}

/* wrappers with implict kernel task port argument */

uint64_t rk64(uint64_t addr) {
  return r64(kernel_task_port, addr);
}

uint32_t rk32(uint64_t addr) {
  return r32(kernel_task_port, addr);
}

void* rkmem(uint64_t addr, uint64_t len) {
  return rmem(kernel_task_port, addr, len);
}

void wk8(uint64_t addr, uint8_t val) {
  w8(kernel_task_port, addr, val);
}

void wk32(uint64_t addr, uint32_t val) {
  w32(kernel_task_port, addr, val);
}

void wk64(uint64_t addr, uint64_t val) {
  w64(kernel_task_port, addr, val);
}
