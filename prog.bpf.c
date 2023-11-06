int bpf_entry(void* mem, int size)
{
    int num = *(int*)mem;
    if(num == 20){
        return -1;
    }
    return num;
}