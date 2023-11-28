#ifndef XV6_RISCV_F23_SPINLOCK_H
#define XV6_RISCV_F23_SPINLOCK_H

// Mutual exclusion lock.
struct spinlock {
  uint locked;       // Is the lock held?

  // For debugging:
  char *name;        // Name of lock.
  struct cpu *cpu;   // The cpu holding the lock.
};

#endif

