#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

#define DATA_SIZE 10*1024*1024 //10MB

char send_buf[DATA_SIZE];
char rec_buf[DATA_SIZE];

void init_buf(char* buf,int n)
{
    for(int i=0;i<n;++i)
        buf[i] = '0'+i%78;
}

void error(const char *msg) {
    fprintf(2, "%s\n", msg);
    exit(-1);
}

int
main(int argc, char *argv[]) {

    int p[2];
    pipe(p);

    init_buf(send_buf,DATA_SIZE);

    int pid = fork();

    if(pid==0){
        //In child process
        close(p[0]);
        int n = write(p[1],send_buf,DATA_SIZE);
        if(n!=DATA_SIZE)
            error("write failed.");
        printf("[child] write %d bytes to pipe\n",n);
        close(p[1]);
    } else if(pid>0){
        //In parent process
        int begin,end,elapse;
        close(p[1]);
        begin = uptime();
        printf("[parent] begin at : %d\n",begin);
        int n,total = 0;
        while((n=read(p[0],rec_buf+total,DATA_SIZE))!=0)
            total+=n;
        end = uptime();
        printf("[parent] end at : %d\n",end);
        printf("[parent] read %d bytes from pipe\n",total);
        elapse = end-begin;
        printf("[parent] elapse ticks : %d\n",elapse);
        //check the bytes
        if(memcmp(send_buf,rec_buf,DATA_SIZE)!=0) error("check failed.");
        close(p[0]);

        wait((int *) 0);
    }else{
        //Fork failed.
        error("fork failed.");
    }
    exit(0);
}