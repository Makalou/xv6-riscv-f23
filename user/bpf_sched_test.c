#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"
#include "kernel/fs.h"
#include "kernel/fcntl.h"
#include "kernel/bpf.h"

int
main(int argc, char *argv[]) {
    if(strcmp(argv[1],"1")==0) {
        int fd = open("fcfs_spt.bpf.o",O_RDONLY);
        char elf[1024];
        int rb = read(fd,elf,1024);
        bpf(BPF_PROG_LOAD, elf, rb);
        bpf(BPF_PROG_ATTACH, "scheduler_preempt_tick", 23);
    }else if (strcmp(argv[1],"2")==0){
        int fd = open("fcfs_spt.bpf.o",O_RDONLY);
        char elf[1024];
        int rb = read(fd,elf,1024);
        bpf(BPF_PROG_LOAD, elf, rb);
        bpf(BPF_PROG_ATTACH, "scheduler_preempt_tick", 23);

        fd = open("fcfs_run.bpf.o",O_RDONLY);
        char elf2[2048];
        rb = read(fd,elf2,2048);
        bpf(BPF_PROG_LOAD, elf2, rb);
        bpf(BPF_PROG_ATTACH, "scheduler_preempt_run", 23);
    }else if (strcmp(argv[1],"3")==0){
        int fd = open("fcfs_spt.bpf.o",O_RDONLY);
        char elf[1024];
        int rb = read(fd,elf,1024);
        bpf(BPF_PROG_LOAD, elf, rb);
        bpf(BPF_PROG_ATTACH, "scheduler_preempt_tick", 23);

        fd = open("pq_run.bpf.o",O_RDONLY);
        char elf2[2048];
        rb = read(fd,elf2,2048);
        bpf(BPF_PROG_LOAD, elf2, rb);
        bpf(BPF_PROG_ATTACH, "scheduler_preempt_run", 23);
    }else if (strcmp(argv[1],"4")==0){
        int fd = open("pq_run.bpf.o",O_RDONLY);
        char elf2[2048];
        int rb = read(fd,elf2,2048);
        bpf(BPF_PROG_LOAD, elf2, rb);
        bpf(BPF_PROG_ATTACH, "scheduler_preempt_run", 23);
    }
    else{
        bpf(BPF_PROG_UNATTACH, "scheduler_preempt_tick", 23);
        bpf(BPF_PROG_UNATTACH,"scheduler_preempt_run",23);
    }

    int pid = fork();

    if(pid == 0) {
        printf("from parent -> ");
        for(int i = 0;i<10;i++)
        {
            printf("%d, ",i);
        }
        printf("\n");
        wait((int*)0);
    } else {
        for(int n = 10;n>0;n--)
        {
            int pid1 = fork();
            if(pid1 > 0){
                chpr(pid1,n);
                printf("from %d hello world! -> ",pid1);
                for(int i = 0;i<20*n;i++)
                {
                    printf("%d, ",i);
                }
                printf("\n");
                exit(0);
            }
        }
        for(int i =0;i<10;i++)
        {
            wait((int*)0);
        }
    }
    exit(0);
}