//
// Created by 王泽远 on 2023/9/26.
//
#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

int
main(int argc, char *argv[]) {
    void* buf1 = 0;
    void* buf2 = 0;
    void* buf3 = 0;

    ringbuf("ringbuf1",1,&buf1);
    printf("ringbuf1 at : %p\n",buf1);
    ringbuf("ringbuf1",1,&buf2);
    printf("ringbuf1 at : %p\n",buf2);
    ringbuf("ringbuf2",1,&buf3);
    printf("ringbuf2 at : %p\n",buf3);

    strcpy(buf1,"hello ring buffer");

    printf("%s\n",buf2);

    exit(0);
}