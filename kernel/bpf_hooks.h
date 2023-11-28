//
// Created by 王泽远 on 2023/11/8.
//

#ifndef XV6_RISCV_F23_BPF_HOOKS_H
#define XV6_RISCV_F23_BPF_HOOKS_H

void bpf_syscall_pre_trace(struct proc* p);

int bpf_syscall_pre_filter(struct proc* p);

int bpf_syscall_post_filter(struct proc* p);

void bpf_syscall_post_trace(struct proc* p);

/*
 *  invoked during regular preempt tick.
 *  input: current running process
 *  return value:
 *              <0 : don't preempt
 *              >0 : preempt
 *              =0 : leave to scheduler
 */
int bpf_sch_check_preempt_tick(struct proc* p);

/*
 *  invoked when scheduler try to wake up a process
 *  input: the process plan to be woken up
 *  return value:
 *              <0 :
 *              >0 :
 *              =0 : leave to scheduler
 */
int bpf_sch_check_preempt_wakeup(struct proc* p);

/*
 *  invoked when scheduler put a process into execution state.
 *  input: the process
 *  return value:
 *              <0 :
 *              >0 :
 *              =0 : leave to scheduler
 */
int bpf_sch_wake_preempt_entity(struct proc* p);

/*
 *  invoked when scheduler try to run a process
 *  input: the process plan to be woken up
 *  return value:
 *              <0 :
 *              >0 :
 *              =0 : leave to scheduler
 */
int bpf_sch_check_run(struct proc* p, struct proc* all_proc, int n);

/*
return value:
  1: enable udp checksum
  0: disable udp checksum
*/
int bpf_enable_udp_checksum_filter();

#endif //XV6_RISCV_F23_BPF_HOOKS_H
