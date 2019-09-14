#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <asm-i386/current.h>
#include <linux/vmalloc.h>
#include <linux/list.h>
#include <asm-i386/uaccess.h>
#include <linux/list.h> //for list

MODULE_LICENSE("GPL");

#define MY_MODULE "systemcalls_logger"

#define MAX_SIZE 1024

#define store_idt(addr) \
	do { \
		__asm__ __volatile__ ( "sidt %0 \n" \
			: "=m" (addr) \
			: : "memory" ); \
    } while (0)

struct _descr { 
     uint16_t limit;
     uint32_t base;
} __attribute__((__packed__));

typedef struct idtGate {
   uint64_t gate;
} idtGate;


typedef struct {
	int syscall_num;
	int system_time;
	int time_slice;
} log_record;


typedef struct {
	list_t list_dummy;
	pid_t pid;
	int num;
	log_record record[MAX_SIZE];
} record_list;


idtGate* sys_call_gate;
uint16_t orig_offset_1;
uint16_t orig_offset_2;
uint32_t orig_func;
uint16_t* parts;
//int enterd = 0;
int major;
list_t logs;


void logging(int sys_call_num){
	/*
	if (enterd == 0){
		printk("sys_call_num:%d\n", sys_call_num);
		printk("in logging function\n");
		enterd = 1;
	}
	*/

	pid_t pid = current->pid;
	list_t* iter;
	list_for_each(iter, &logs){
		int found_pid = list_entry(iter, record_list, list_dummy)->pid;
		if(found_pid == pid){
			//printk("pid registering;%d   ", pid);
			//printk("pid sys_call_num;%d\n ", sys_call_num);
			int num = list_entry(iter, record_list, list_dummy)->num;
			if (num == MAX_SIZE){

				return;
			}
				
			log_record new_record;
			new_record.syscall_num = sys_call_num;
			new_record.system_time = jiffies;
			new_record.time_slice = current->time_slice;
			list_entry(iter, record_list, list_dummy)->record[num]  = new_record;
			list_entry(iter, record_list, list_dummy)->num++;

			return;
		}
	}

	return;
}



asm ( ".text \n\t"
    "patched_system_call: \n\t"
    "pushl %edx \n\t"
    "pushl %ecx \n\t"
    "pushl %eax \n\t"
    "call logging \n\t"
    "popl %eax\n\t"
    "popl %ecx\n\t"
    "popl %edx\n\t"
    "jmp *orig_func \n\t"
    
);
void patched_system_call();


int my_open(){
	record_list* new_record = kmalloc(sizeof(record_list), GFP_KERNEL);
	if (new_record == NULL){
		return -1;
	}
	new_record->pid = current->pid;
	new_record->num = 0;
	list_add_tail(&new_record->list_dummy, &logs);
	return 0;
}

int my_release(){
	list_t* iter;
	pid_t pid = current->pid;
	list_for_each(iter, &logs){
			int found_pid = list_entry(iter, record_list, list_dummy)->pid;
		if(found_pid == pid){
			kfree(iter);
			list_del(iter);
		}
	}
	return 0;
}

ssize_t my_read(struct file *filp, char *buf, size_t count, loff_t *f_pos){

	pid_t pid = current->pid;
	//printk("asking pid 1:%d\n", pid);
	list_t* iter;
	list_for_each(iter, &logs){
		int found_pid = list_entry(iter, record_list, list_dummy)->pid;
		if(found_pid == pid){
			//printk("asking pid 2:%d\n", pid);
			log_record* record = list_entry(iter, record_list, list_dummy)->record;
			int num = list_entry(iter, record_list, list_dummy)->num;
			//printk("num:%d\n", num);
			//printk("count:%d\n", count);
			//int i;
			if (count>num){
				/*
				log_record temp[num];
				for(i=0; i<num; i++){
					temp[i] = record[i];
				}
				*/
				int copy_res = copy_to_user(buf, record, num*sizeof(log_record));
				//printk("\ncopy_res 1: %d\n", copy_res);
				if (copy_res == 0){
			
					return num;
				}
				if (copy_res < 0){
					return -1;
				}
				return num - ((copy_res)/sizeof(log_record));
			}
			else{
				/*
				log_record temp[count];
				for(i=0; i<count; i++){
					temp[i] = record[i];
				}
				*/
				int copy_res = copy_to_user(buf, record, count*sizeof(log_record));
				//printk("copy_res 2: %d\n", copy_res);
				if (copy_res == 0){
				
					return count;
				}
				if (copy_res < 0){
					return -1;
				}
				return count - ((copy_res)/sizeof(log_record));
			}
		}
	}

	return 0;
}

struct file_operations fops0;

struct file_operations fops0 = {
	.open= my_open,
	.release= my_release,
	.read = my_read,
};

int init_module(void) {
	
	major = register_chrdev(0, MY_MODULE, &fops0);
	if (major < 0)
	{
		return major;
	}
	struct _descr idtr;
	store_idt(idtr);
	//printk("base:%u\n", idtr.base);
	//printk("limit:%u\n", idtr.limit);
	sys_call_gate = (idtGate*)(idtr.base);
	sys_call_gate = sys_call_gate+128;
	parts = (uint16_t*)&sys_call_gate->gate;
	orig_offset_1 = parts[0];
	orig_offset_2 = parts[3];
	//printk("orig_offset_1:%u\n", orig_offset_1);
	//printk("orig_offset_2:%u\n", orig_offset_2);
	uint16_t* orig_func_parts = (uint16_t*)&orig_func;
	orig_func_parts[0] = parts[0];
	orig_func_parts[1] = parts[3];
	//printk("orig_func:%u\n", orig_func);

	uint32_t patched_call = (uint32_t)patched_system_call;
	uint16_t* patched_parts = (uint16_t*)&patched_call;
	parts[0] = patched_parts[0];
	parts[3] = patched_parts[1];
	INIT_LIST_HEAD(&logs);
	
    return 0;
}
void cleanup_module(void) {
	parts[0] = orig_offset_1;
	parts[3] = orig_offset_2;
	int ret = unregister_chrdev(major, MY_MODULE);
	if(ret < 0)
	{
		return;
	}
	return;
	
}
