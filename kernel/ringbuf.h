//
// Created by 王泽远 on 2023/9/20.
//

#define RINGBUF_SIZE 16
#define MAX_RINGBUFS 10

struct ringbuf
{
    int refcount;
    char name[16];
    void* buf[RINGBUF_SIZE];
    void* book;
};

extern struct ringbuf ringbufs[];

