#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("infernexio");
MODULE_DESCRIPTION("rootkit");
MODULE_VERSION("0.0.1");

static int __init init_func(void){
    printk(KERN_INFO "rootkit: initalized\n");

    return 0;
}

static void __exit exit_func(void){
    printk(KERN_INFO "rootkit: stoped\n");
}


module_init(init_func);
module_exit(exit_func);
