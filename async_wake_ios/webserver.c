/*
 base code taken from stackexchange, original author Abhijeet Rastogi
 heavily modified due to constraints of iOS
 and to actually get it working ;)
 */

#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<unistd.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<netdb.h>
#include<signal.h>
#include<fcntl.h>
#include <mach/vm_types.h>
#include "webserver.h"

//haxx to avoid including the .h which will break shit because FML C
extern char* dump_pointer_html(mach_port_t tfp0, addr64_t addr, uint64_t max_size);
extern char* ps_html(void);


#define CONNMAX 1000
#define BYTES 1024
#define DATA_SIZE 0x2000

char *ROOT = "/";
int listenfd, clients[CONNMAX];
int urlmode = 1;
mach_port_t ws_tfp0;
uint64_t ws_kernel_base;


#include <dirent.h>
char* http_ls(char *cwd, uint32_t* sz)
{
    struct stat st_buf;
    char *data = malloc(DATA_SIZE);
    uint32_t l = 0;
    if (urlmode)
    {
        sprintf(data,
                "<html><h1>\tListing [%s]</h1><br>\n"
                "<br><h5>\tOther HTTP Options: "
                "<a href=/dump_ptr=0x0011223344556677>/dump_ptr=0x0011223344556677</a> - dump kernel memory | "
                "<a href=/info>/info</a> - list processes | "
                "<a href=/urlmode>/urlmode</a> - disable/enable urls for recursive wget | "
                "<a href=/exit>exit</a> - exit HTTP server</h5> "
                "</ br><h5>kernel_base = <a href=/dump_ptr=0x%llx>0x%llx</a></h5><br></ br>\n",
                cwd, ws_kernel_base, ws_kernel_base);
    } else {
        sprintf(data,
                "<html><h1>\tListing [%s]</h1><br>\n"
                "<br><h5>\tOther HTTP Options: "
                "/dump_ptr=0x0011223344556677 - dump kernel memory | "
                "/info - list processes | "
                "/urlmode - disable/enable urls for recursive wget | "
                "/exit - exit HTTP server</h5> "
                "</ br><h5>kernel_base = /dump_ptr=0x%llx</h5><br></ br>\n",
                cwd, ws_kernel_base);
    }
    l += strlen(data);
    printf("About to search directory [%s] for files...\n", cwd);
    DIR *dir = opendir(cwd);
    struct dirent *ent;
    if (dir != NULL)
    {
        /* print all the files and directories within directory */
        while ((ent = readdir(dir)) != NULL)
        {
            char *tmp = malloc(0x1000);
            char *tmp2 = malloc(0x1000);
            char *name = malloc(0x1000);
            strcpy(name, ent->d_name);
            strcpy(tmp2, cwd);
            strcat(tmp2, ent->d_name);
            printf("Found file [%s] in directory [%s]\n", name, cwd);
            stat(tmp2, &st_buf);
            free(tmp2);
            if (S_ISDIR (st_buf.st_mode))
                strcat(name, "/");
            sprintf(tmp, "<a href=\"%s%s\">%s</a><br>\n", cwd, name, name);
            l += strlen(tmp);
            if (strlen(data) + strlen(tmp) < DATA_SIZE)
                strcat(data, tmp);
            free(name);
            free(tmp);
        }
        closedir(dir);
    } else {
        /* could not open directory */
        strcat(data, "Couldn't open directory\n");
        l = (uint32_t)strlen(data);
    }
    strcat(data, "<html>");
    *sz = l + 6;
    return data;
}

void init_ws(mach_port_t tfp0, uint64_t kernel_base)
{
    ws_tfp0 = tfp0;
    ws_kernel_base = kernel_base;
}

void* wsmain(void* not_used_damn_you_pthread)
{
    not_used_damn_you_pthread = not_used_damn_you_pthread;
    mach_port_t tfp0 = ws_tfp0;
    struct sockaddr_in clientaddr;
    socklen_t addrlen;
    
    //Default Values PATH = ~/ and PORT=10000
    char *PORT = "80";
    int slot=0;
    
    
    printf("Server started at port no. %s with root directory as %s\n",PORT,ROOT);
    // Setting all elements to -1: signifies there is no client connected
    int i;
    for (i=0; i<CONNMAX; i++)
        clients[i]=-1;
    startServer(PORT);
    
    // ACCEPT connections
    int flag = 1;
    while (flag)
    {
        addrlen = sizeof(clientaddr);
        clients[slot] = accept (listenfd, (struct sockaddr *) &clientaddr, &addrlen);
        
        if (clients[slot]<0)
            printf("accept() error");
        else
        {

            flag = respond(slot, tfp0);

        }
        
        while (clients[slot]!=-1) slot = (slot+1)%CONNMAX;
    }
    
    return not_used_damn_you_pthread;
}

//start server
void startServer(char *port)
{
    struct addrinfo hints, *res, *p;
    
    // getaddrinfo for host
    memset (&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    if (getaddrinfo( NULL, port, &hints, &res) != 0)
    {
        printf("getaddrinfo() error");
        exit(1);
    }
    // socket and bind
    for (p = res; p!=NULL; p=p->ai_next)
    {
        listenfd = socket (p->ai_family, p->ai_socktype, 0);
        if (listenfd == -1) continue;
        if (bind(listenfd, p->ai_addr, p->ai_addrlen) == 0) break;
    }
    if (p==NULL)
    {
        printf ("socket() or bind()");
        exit(1);
    }
    
    freeaddrinfo(res);
    
    if ( listen (listenfd, 1000000) != 0 )
    {
        printf("listen() error");
        exit(1);
    }
}

//client connection

int respond(int n, mach_port_t tfp0)

{
    char mesg[99999], *reqline[3], data_to_send[BYTES], path[99999];
    ssize_t rcvd, bytes_read;
    int fd;
    int reclaim = 0;
    
    memset( (void*)mesg, (int)'\0', 99999 );
    
    rcvd=recv(clients[n], mesg, 99999, 0);
    
    if (rcvd<0)    // receive error
        fprintf(stderr,("recv() error\n"));
    else if (rcvd==0)    // receive socket closed
        fprintf(stderr,"Client disconnected upexpectedly.\n");
    else    // message received
    {
        printf("%s", mesg);
        reqline[0] = strtok (mesg, " \t\n");
        if (strncmp(reqline[0], "GET\0", 4) == 0)
        {
            reqline[1] = strtok (NULL, " \t");
            if (strstr(reqline[1], "%20"))
            {
                // let's strip out %20's
                char *tmp = malloc(0x2000);
                char *f = reqline[1];
                int i, cont = 0, j=0;
                for (i=0; i < strlen(f); i++)
                {
                    //printf("cont=%d\n", cont);
                    if (!cont)
                    {
                        if (f[i] == '%')
                        {
                            tmp[j++] = ' ';
                            cont = 2;
                        } else {
                            tmp[j++] = f[i];
                        }
                    } else {
                        cont--;
                    }
                    
                }
                tmp[j] = 0;
                //printf("I've stripped all the spaces from [%s] and now it is [%s]\n", f, tmp);
                reqline[1] = tmp;
                reclaim = 1;
            }
            reqline[2] = strtok (NULL, " \t\n");
            if ((strncmp(reqline[2], "HTTP/1.0", 8) != 0) && (strncmp(reqline[2], "HTTP/1.1", 8) != 0))
            {
                write(clients[n], "HTTP/1.0 400 Bad Request\n", 25);
            }
            else
            {
                if (strncmp(reqline[1], "/urlmode\0", 7) == 0)
                {
                    char *redirect = "<html><script>window.location = document.referrer;</script></html>";
                    urlmode ^= 1;
                    send(clients[n], "HTTP/1.0 200 OK\n\n", 17, 0);
                    send(clients[n], redirect, strlen(redirect), 0);
                }
                if (strncmp(reqline[1], "/exit\0", 6) == 0)
                {
                    printf("Get exit, shutting down\n");
                    //free(reqline[1]); // it's ok to leak
                    return 0;
                }
                if (strncmp(reqline[1], "/dump_ptr=", 0xa) == 0)
                {
                    uint32_t sz;
                    uint64_t index = 0;
                    // convert the argument to ull
                    uint64_t addr = strtoull((char *)(reqline[1] + 0xa), (char **)NULL, 0x10);
                    printf("Dumping pointer 0x%llx\n", addr);
                    char *html = 0;
                    html = dump_pointer_html(tfp0, addr, 0x200);
                    sz = (uint32_t)strlen(html);
                    send(clients[n], "HTTP/1.0 200 OK\n\n", 17, 0);
                    while ( index < (sz - 1))
                    {
                        write(clients[n], &html[index], 1);
                        index++;
                    }
                    if (html)
                        free(html);
                } else if (strncmp(reqline[1], "/info", 5) == 0)
                {
                    char* pids = ps_html();
                    uint64_t sz = strlen(pids), index = 0;
                    send(clients[n], "HTTP/1.0 200 OK\n\n", 17, 0);
                    while ( index < (sz - 1))
                    {
                        write(clients[n], &pids[index], 1);
                        index++;
                    }
                    free(pids);
                } else {
                    printf("GOT THE FOLLOWING REQUEST: [%s]\n", &reqline[1][strlen(reqline[1])-1]);
                    if (strncmp(&reqline[1][strlen(reqline[1])-1], "/\0", 2) == 0) // if it ends with a slash
                    {
                        printf("get a directory listing\n");
                        uint32_t sz;
                        uint64_t index;
                        char *data;
                        data = http_ls(reqline[1], &sz);
                        send(clients[n], "HTTP/1.0 200 OK\n\n", 17, 0);
                        index = 0;
                        while ( index < (sz - 1))
                        {
                            write(clients[n], &data[index], 1);
                            index++;
                        }
                        if (data)
                            free(data);
                    } else {
                        strcpy(path, ROOT);
                        strcpy(&path[strlen(ROOT)], reqline[1]);
                        printf("file: %s\n", path);
                        if ((fd=open(path, O_RDONLY)) !=- 1)    //FILE FOUND
                        {
                            send(clients[n], "HTTP/1.0 200 OK\n\n", 17, 0);
                            while ( (bytes_read=read(fd, data_to_send, BYTES)) > 0 )
                                write (clients[n], data_to_send, bytes_read);
                            close(fd);
                        } else {
                            write(clients[n], "HTTP/1.0 404 Not Found\n", 23);
                        }
                    }
                }
            }
        }
    }
    if (reclaim)
        free(reqline[1]);
    shutdown(clients[n], SHUT_RDWR);
    close(clients[n]);
    clients[n]=-1;
    return 1;
}
