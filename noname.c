#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("infernexio");
MODULE_DESCRIPTION("rootkit");
MODULE_VERSION("0.0.1");

static int __init init_func(void){
    printk(KERN_INFO "rootkit: initalized");

    return 0;
}

static void __exit exit_func(void){
    printk(KERN_INFO " rootkit: stoped");
}


module_init(mod_init);
module_exit(mod_exit);