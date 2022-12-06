#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("TheXcellerator");
MODULE_DESCRIPTION("Basic Kernel Module");
MODULE_VERSION("0.01");

static int __init init_func(void){
    printk(KERN_INFO "rootkit: initalized");

    return 0;
}

static void __exit exit_func(void){
    printk(KERN_INFO " rootkit: stoped");
}