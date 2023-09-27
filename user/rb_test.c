//
// Created by 王泽远 on 2023/9/26.
//
#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

int
main(int argc, char *argv[]) {
    void* buf1 = 0;

    ringbuf("ringbuf1",1,&buf1);
    printf("ringbuf1 at : %p\n",buf1);
    ringbuf("ringbuf1",0,&buf1);

    exit(0);
}