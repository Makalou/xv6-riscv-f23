#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"
#include "kernel/fs.h"
#include "kernel/fcntl.h"
#include "kernel/bpf.h"
#include "kernel/bpf_map.h"

int
main(int argc, char *argv[]) {
    //filter mkdir syscall
    if(strcmp(argv[1],"1")==0) {
        int fd = open("syscall_trace.bpf.o",O_RDONLY);
        char elf[2048];
        int rb = read(fd,elf,2048);
        printf("bpf program bytes : %d\n",rb);
        struct bpf_map_create_attr create_attr;
        strcpy(create_attr.name,"counter");
        create_attr.map_type = bpf_array;
        create_attr.value_size = sizeof(int);
        create_attr.max_eles = 30;

        int md = bpf(BPF_MAP_CREATE,(char*)&create_attr,sizeof(struct bpf_map_create_attr));
        bpf(BPF_PROG_LOAD, elf, rb);
        bpf(BPF_PROG_ATTACH, "syscall_pre_trace", 18);

        int pid = fork();

        if(pid == 0){
            sleep(50);
            int val;
            struct bpf_map_lookup_attr lookupAttr;
            lookupAttr.md = md;
            lookupAttr.idx = 20;
            lookupAttr.value = &val;
            lookupAttr.bpf = 0;
            bpf(BPF_MAP_LOOKUP_ELEM,(char*)&lookupAttr, sizeof(struct bpf_map_lookup_attr));
            printf("mkdir is invoked %d times\n",val);
        }else{
            int pid2 = fork();
            if(pid2 == 0){
                char dir_path[] = "dir0n";
                for(int i =0;i<20;i++)
                {
                    mkdir(dir_path);
                    dir_path[3]++;
                }
                printf("%d create many dir\n",pid);
                exit(0);
            }else{
                char dir_path[] = "dir0m";
                for(int i =0;i<20;i++)
                {
                    mkdir(dir_path);
                    dir_path[3]++;
                }
                printf("%d create many dir\n",pid2);
                exit(0);
            }

        }

    }else{
        bpf(BPF_PROG_UNATTACH,"syscall_pre_trace",18);
    }
    exit(0);
}