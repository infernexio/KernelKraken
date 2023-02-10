#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("infernexio");
MODULE_DESCRIPTION("KernelKraken LKM");
MODULE_VERSION("0.01");

static void __exit kernal_kraken_exit(void);

static int __init kernal_kraken_init(void);

static int setup(void);

static int teardown(void);