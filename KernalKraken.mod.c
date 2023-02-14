#include <linux/build-salt.h>
#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(.gnu.linkonce.this_module) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

static const struct modversion_info ____versions[]
__used __section(__versions) = {
	{ 0xdd8f8694, "module_layout" },
	{ 0x3c3ff9fd, "sprintf" },
	{ 0x3b825fc1, "commit_creds" },
	{ 0x611bf0f1, "prepare_creds" },
	{ 0x9e423bbc, "unregister_ftrace_function" },
	{ 0x58f03b99, "register_ftrace_function" },
	{ 0xc8f162c9, "ftrace_set_filter_ip" },
	{ 0xe007de41, "kallsyms_lookup_name" },
	{ 0xcbd4898c, "fortify_panic" },
	{ 0xb0e602eb, "memmove" },
	{ 0x37a0cba, "kfree" },
	{ 0xb44ad4b3, "_copy_to_user" },
	{ 0x449ad0a7, "memcmp" },
	{ 0xa916b694, "strnlen" },
	{ 0x362ef408, "_copy_from_user" },
	{ 0x88db9f48, "__check_object_size" },
	{ 0xeb233a45, "__kmalloc" },
	{ 0xdecd0b29, "__stack_chk_fail" },
	{ 0x24428be5, "strncpy_from_user" },
	{ 0x2ea2c95c, "__x86_indirect_thunk_rax" },
	{ 0xc5850110, "printk" },
	{ 0xbdfb6dbb, "__fentry__" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "97DB754F4798058644B7CBA");
