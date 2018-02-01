//
//  webserver.h
//  async_wake_ios
//

#ifndef webserver_h
#define webserver_h
void init_ws(mach_port_t tfp0, uint64_t kernel_base);
void* wsmain(void*);
void error(char *);
void startServer(char *);
int respond(int, mach_port_t);

#endif /* webserver_h */
