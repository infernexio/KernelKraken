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
    
      __sys_call_table = (unsigned long*)kallsyms_lookup_name("sys_call_table");

    return 0;
}

static void __exit exit_func(void){
    printk(KERN_INFO "rootkit: stoped\n");
}


module_init(init_func);
module_exit(exit_func);
