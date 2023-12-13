#include "kernel/bpf_map.h"

// Bit 0 stands for if the content pass the filter
// Bit 1 stands for whether to enable udp checksum
/*
typedef struct netPInfo_ {
    unsigned char enableUdpCSum;
    // 0: donot file content
    // 1: filt packet that contain filterContent
    // 2: filt packet that not contain filterContent
    unsigned char filtConfig;
    char filterContent[64];
    int filterCLen;
    char netPContent[128];
    int netPLen;
} netPInfo;
*/
int bpf_entry(void* mem, int size) {
    netPInfo *ptr = (netPInfo *)mem;
    int res = 0;
    if (ptr->enableUdpCSum) {
        res += 2;
    }
    if (ptr->filtConfig != 0) {
        unsigned char flag = 0;
        for (int i = 0; i < ptr->netPLen; i++) {
            if (ptr->netPContent[i] == ptr->filterContent[0]) {
                int j = 0;
                while (j < ptr->filterCLen && i + j < ptr->netPLen && \
                        ptr->filterContent[j] == ptr->netPContent[i+j]) {
                    j++;
                }
                if (j == ptr->filterCLen) {
                    flag = 1;
                    break;
                }
            }
        }
        if (ptr->filtConfig == 1) {
            res += flag;
        } else if (ptr->filtConfig == 2) {
            if (flag == 0) {
                res += 1;
            }
        } else if (ptr->filtConfig == 0) {
            res += 1;
        }
    }
    return res;
}