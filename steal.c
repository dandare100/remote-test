#include <linux/kernel.h>
#include <linux/syscalls.h>

//Intercepts open, read and write system calls
//Works on kernel 3.8.1

unsigned long **sys_call_table;

asmlinkage long (*ref_sys_open)(const char __user *filename, int flags, umode_t mode);
asmlinkage long (*ref_sys_read)(unsigned int fd, char __user *buf, size_t count);
asmlinkage long (*ref_sys_write)(unsigned int fd, const char __user *buf, size_t count);

asmlinkage long new_sys_open(const char __user *filename, int flags, umode_t mode)
{
	printk(KERN_INFO "intercept: Opening file %s", filename);
 
	return ref_sys_open(filename, flags, mode);
}

asmlinkage long new_sys_read(unsigned int fd, char __user *buf, size_t count)
{
	long ret;
	ret = ref_sys_read(fd, buf, count);


	return ret;
}

asmlinkage long new_sys_write(unsigned int fd, const char __user *buf, size_t count)
{
	return ref_sys_write(fd, buf, count);
}

static unsigned long **aquire_sys_call_table(void)
{
	unsigned long int offset = PAGE_OFFSET;
	unsigned long **sct;

	while (offset < ULLONG_MAX) {
		sct = (unsigned long **)offset;

		if (sct[__NR_close] == (unsigned long *) sys_close) 
			return sct;

		offset += sizeof(void *);
	}

	return NULL;
}

static void disable_page_protection(void) 
{
	unsigned long value;
	asm volatile("mov %%cr0, %0" : "=r" (value));

	if(!(value & 0x00010000))
		return;

	asm volatile("mov %0, %%cr0" : : "r" (value & ~0x00010000));
}

static void enable_page_protection(void) 
{
	unsigned long value;
	asm volatile("mov %%cr0, %0" : "=r" (value));

	if((value & 0x00010000))
		return;

	asm volatile("mov %0, %%cr0" : : "r" (value | 0x00010000));
}

static int __init interceptor_start(void) 
{
	if(!(sys_call_table = aquire_sys_call_table()))
		return -1;

	disable_page_protection();
	ref_sys_open = (void *)sys_call_table[__NR_open];
	ref_sys_read = (void *)sys_call_table[__NR_read];
	ref_sys_write = (void *)sys_call_table[__NR_write];
	sys_call_table[__NR_open] = (unsigned long *)new_sys_open;
	sys_call_table[__NR_read] = (unsigned long *)new_sys_read;
	sys_call_table[__NR_write] = (unsigned long *)new_sys_write;
	enable_page_protection();

	return 0;
}

static void __exit interceptor_end(void) 
{
	if(!sys_call_table)
		return;

	disable_page_protection();
	sys_call_table[__NR_open] = (unsigned long *)ref_sys_open;
	sys_call_table[__NR_read] = (unsigned long *)ref_sys_read;
	sys_call_table[__NR_write] = (unsigned long *)ref_sys_write;
	enable_page_protection();
}

module_init(interceptor_start);
module_exit(interceptor_end);
