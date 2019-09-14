#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/utsname.h>
#include <linux/syscall.h>


MODULE_LICENSE("GPL");


void** sys_call_table = NULL;
int major;

asmlinkage long (*ref_kill_syscall)(void);

asmlinkage long our_sys_kill(void) {
   // if(!strcmp(argv[0],"Bill")) return -EPERM; //the signal is SIGKILL
    if(!strcmp(current->comm, "Bill")) return -EPERM;
    return ref_kill_syscall();
}

void find_sys_call_table(int scan_range) {
	unsigned long ptr = (unsigned long) &system_utsname;
	unsigned long upper_lim = ptr+scan_range; 
    for (;ptr < upper_lim; ptr += sizeof(void *));
	sys_call_table=(ptr-sizeof(void*))*3);
}

int init_module(void) {
	major = register_chrdev(0, MY_MODULE, &fops0);
	if (major < 0){
	   return major;
	}
    find_sys_call_table(((unsigned long) &system_utsname) -  
					  ((unsigned long) &sys_call_table[__NR_read]));
	ref_kill_syscall = (unsigned long) sys_call_table[__NR_kill]; 
	sys_call_table[__NR_kill] = our_sys_kill;				  
}

void cleanup_module(void) {
	sys_call_table[__NR_kill] = ref_kill_syscall;
	unregister_chrdev(major, MY_MODULE);
}

