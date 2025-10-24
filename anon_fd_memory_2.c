#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/ioctl.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/anon_inodes.h>
#include <linux/vmalloc.h>
#include <linux/highmem.h>

#define DEVICE_NAME "anon_memory"
#define CLASS_NAME  "anonmem"

// IOCTL commands
#define ANONMEM_IOC_MAGIC 'A'
#define ANONMEM_GET_FD     _IOR(ANONMEM_IOC_MAGIC, 1, int)
#define ANONMEM_WRITE_DATA _IOW(ANONMEM_IOC_MAGIC, 2, struct mem_write_info)

struct mem_write_info {
	unsigned long offset;
	char data[256];
	size_t data_len;
};

// Memory buffer information
struct memory_buffer {
	void *kernel_buffer;
	size_t buffer_size;
	atomic_t ref_count;
	struct list_head list;
};

static int major_number;
static struct class *anonmem_class = NULL;
static struct device *anonmem_device = NULL;
static struct cdev anonmem_cdev;
static dev_t dev_num;

static LIST_HEAD(buffer_list);
static DEFINE_MUTEX(buffer_list_mutex);

#define DEFAULT_BUFFER_SIZE (1024 * 1024)

static int anon_fd_mmap(struct file *file, struct vm_area_struct *vma);
static int anon_fd_release(struct inode *inode, struct file *file);
static void anon_vma_open(struct vm_area_struct *vma);
static void anon_vma_close(struct vm_area_struct *vma);

// File operations for anonymous fd
static const struct file_operations anon_fd_fops = {
	.owner = THIS_MODULE,
	.mmap = anon_fd_mmap,
	.release = anon_fd_release,
};

static const struct vm_operations_struct anon_vm_ops = {
	.open = anon_vma_open,
	.close = anon_vma_close,
};

static void print_kernel_buffer(void *buffer, const char *label, 
                                unsigned long offset, size_t len)
{
	char *buf = (char *)buffer + offset;
	char temp_buf[257];
	size_t print_len = min(len, (size_t)256);

	memcpy(temp_buf, buf, print_len);
	temp_buf[print_len] = '\0';

	printk(KERN_INFO "anonmem: %s (offset %lu): '%s'\n", label, offset, temp_buf);
}

// Allocate memory buffer
static struct memory_buffer *allocate_memory_buffer(size_t size)
{
	struct memory_buffer *mem_buf;
	unsigned long order;

	mem_buf = kzalloc(sizeof(*mem_buf), GFP_KERNEL);
	if (!mem_buf)
		return NULL;

	// Round up to page boundary
	size = PAGE_ALIGN(size);

	// For large allocations, use vmalloc
	if (size > PAGE_SIZE * 4) {
		mem_buf->kernel_buffer = vmalloc(size);
	} else {
		// For smaller allocations, try to get contiguous pages
		order = get_order(size);
		mem_buf->kernel_buffer = (void *)__get_free_pages(GFP_KERNEL, order);
	}

	if (!mem_buf->kernel_buffer) {
		kfree(mem_buf);
		return NULL;
	}

	mem_buf->buffer_size = size;
	atomic_set(&mem_buf->ref_count, 1);

	// Initialize buffer with known pattern
	memset(mem_buf->kernel_buffer, 0xAA, size);
	snprintf((char *)mem_buf->kernel_buffer, 256,"Hello from kernel! Buffer size: %zu bytes.", size);

	mutex_lock(&buffer_list_mutex);
	list_add(&mem_buf->list, &buffer_list);
	mutex_unlock(&buffer_list_mutex);

	printk(KERN_INFO "anonmem: Allocated buffer at %p, size %zu\n", mem_buf->kernel_buffer, size);
	return mem_buf;
}

// Free memory buffer
static void free_memory_buffer(struct memory_buffer *mem_buf)
{
	if (!mem_buf)
		return;

	mutex_lock(&buffer_list_mutex);
	list_del(&mem_buf->list);
	mutex_unlock(&buffer_list_mutex);

	if (mem_buf->buffer_size > PAGE_SIZE * 4) {
		vfree(mem_buf->kernel_buffer);
	} else {
		unsigned long order = get_order(mem_buf->buffer_size);
		free_pages((unsigned long)mem_buf->kernel_buffer, order);
	}

	printk(KERN_INFO "anonmem: Freed buffer at %p\n", mem_buf->kernel_buffer);
	kfree(mem_buf);
}

// VMA operations
static void anon_vma_open(struct vm_area_struct *vma)
{
	struct memory_buffer *mem_buf = vma->vm_private_data;
	if (mem_buf) {
		atomic_inc(&mem_buf->ref_count);
		printk(KERN_INFO "anonmem: VMA opened, ref_count: %d\n", atomic_read(&mem_buf->ref_count));
	}
}

static void anon_vma_close(struct vm_area_struct *vma)
{
	struct memory_buffer *mem_buf = vma->vm_private_data;
	if (mem_buf) {
		int ref_count = atomic_dec_return(&mem_buf->ref_count);
		printk(KERN_INFO "anonmem: VMA closed, ref_count: %d\n", ref_count);
		if (ref_count == 0) {
			free_memory_buffer(mem_buf);
		}
	}
}

static int anon_fd_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct memory_buffer *mem_buf = file->private_data;
	unsigned long size = vma->vm_end - vma->vm_start;
	unsigned long uaddr = vma->vm_start;
	unsigned long kaddr = (unsigned long)mem_buf->kernel_buffer;
	unsigned long remaining = size;
	int ret;

	if (!mem_buf) {
		printk(KERN_ERR "anonmem: No memory buffer associated with fd\n");
		return -EINVAL;
	}

	if (size > mem_buf->buffer_size) {
		printk(KERN_ERR "anonmem: Requested size %lu > buffer size %zu\n", size, mem_buf->buffer_size);
		return -EINVAL;
	}

	vma->vm_private_data = mem_buf;
	vma->vm_ops = &anon_vm_ops;
	atomic_inc(&mem_buf->ref_count);

	while (remaining > 0) {
		struct page *page = vmalloc_to_page((void *)kaddr);
		if (!page) {
			printk(KERN_ERR "anonmem: vmalloc_to_page failed\n");
			return -EFAULT;
		}

		ret = vm_insert_page(vma, uaddr, page);
		if (ret) {
			printk(KERN_ERR "anonmem: vm_insert_page failed: %d\n", ret);
			return ret;
		}

		uaddr += PAGE_SIZE;
		kaddr += PAGE_SIZE;
		remaining -= PAGE_SIZE;
	}

	printk(KERN_INFO "anonmem: Successfully mapped %lu bytes to user space\n", size);
	return 0;
}


// Anonymous fd release
static int anon_fd_release(struct inode *inode, struct file *file)
{
	struct memory_buffer *mem_buf = file->private_data;
	if (mem_buf) {
		int ref_count = atomic_dec_return(&mem_buf->ref_count);
		printk(KERN_INFO "anonmem: Anonymous fd released, ref_count: %d\n", ref_count);
		if (ref_count == 0) {
			free_memory_buffer(mem_buf);
		}
	}
	return 0;
}

// Write data to kernel buffer (for testing)
static int write_to_buffer(struct mem_write_info *write_info)
{
	struct memory_buffer *mem_buf;
	char *target;

	mutex_lock(&buffer_list_mutex);
	if (list_empty(&buffer_list)) {
		mutex_unlock(&buffer_list_mutex);
		return -ENOENT;
	}
	mem_buf = list_first_entry(&buffer_list, struct memory_buffer, list);
	mutex_unlock(&buffer_list_mutex);

	if (write_info->offset + write_info->data_len > mem_buf->buffer_size) {
		return -EINVAL;
	}

	print_kernel_buffer(mem_buf->kernel_buffer, "Target area BEFORE write",
				write_info->offset, write_info->data_len + 16);

	target = (char *)mem_buf->kernel_buffer + write_info->offset;
	memcpy(target, write_info->data, write_info->data_len);

	target[write_info->data_len] = '\0';

	print_kernel_buffer(mem_buf->kernel_buffer, "Target area AFTER write",
				write_info->offset, write_info->data_len + 16);

	printk(KERN_INFO "anonmem: Wrote %zu bytes at offset %lu\n", write_info->data_len, write_info->offset);
	return 0;
}

// Main device IOCTL handler
static long anonmem_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct memory_buffer *mem_buf;
	struct mem_write_info write_info;
	int fd;

	switch (cmd) {
		case ANONMEM_GET_FD:
			// Allocate memory buffer
			mem_buf = allocate_memory_buffer(DEFAULT_BUFFER_SIZE);
			if (!mem_buf) {
				return -ENOMEM;
			}

			// Create anonymous file descriptor
			fd = anon_inode_getfd("anonmem_buffer", &anon_fd_fops, mem_buf, O_RDWR | O_CLOEXEC);
			if (fd < 0) {
			    free_memory_buffer(mem_buf);
			    return fd;
			}

			// Copy fd back to user
			if (copy_to_user((void __user *)arg, &fd, sizeof(fd))) {
			    // Clean up on copy failure
			    free_memory_buffer(mem_buf);
			    return -EFAULT;
			}

			printk(KERN_INFO "anonmem: Created anonymous fd %d\n", fd);
			return 0;

		case ANONMEM_WRITE_DATA:
			if (copy_from_user(&write_info, (void __user *)arg, sizeof(write_info)))
				return -EFAULT;

			write_info.data[sizeof(write_info.data) - 1] = '\0'; // Ensure null termination
			printk("write data from kernel : %s\n", write_info.data);
			return write_to_buffer(&write_info);

		default:
			return -ENOTTY;
	}
}

// Main device file operations
static const struct file_operations anonmem_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = anonmem_ioctl,
};

// Module initialization
static int __init anonmem_init(void)
{
	int ret;

	// Allocate character device numbers
	ret = alloc_chrdev_region(&dev_num, 0, 1, DEVICE_NAME);
	if (ret < 0) {
		printk(KERN_ERR "anonmem: Failed to allocate device numbers\n");
		return ret;
	}
	major_number = MAJOR(dev_num);

	// Initialize and add character device
	cdev_init(&anonmem_cdev, &anonmem_fops);
	anonmem_cdev.owner = THIS_MODULE;
	ret = cdev_add(&anonmem_cdev, dev_num, 1);
	if (ret < 0) {
		unregister_chrdev_region(dev_num, 1);
		printk(KERN_ERR "anonmem: Failed to add character device\n");
		return ret;
	}

	// Create device class
	anonmem_class = class_create(CLASS_NAME);
	if (IS_ERR(anonmem_class)) {
		cdev_del(&anonmem_cdev);
		unregister_chrdev_region(dev_num, 1);
		return PTR_ERR(anonmem_class);
	}

	// Create device
	anonmem_device = device_create(anonmem_class, NULL, dev_num, NULL, DEVICE_NAME);
	if (IS_ERR(anonmem_device)) {
		class_destroy(anonmem_class);
		cdev_del(&anonmem_cdev);
		unregister_chrdev_region(dev_num, 1);
		return PTR_ERR(anonmem_device);
	}

	printk(KERN_INFO "anonmem: Anonymous FD memory driver loaded successfully\n");
	return 0;
}

// Module cleanup
static void __exit anonmem_exit(void)
{
	struct memory_buffer *mem_buf, *tmp;
	// Clean up any remaining buffers
	list_for_each_entry_safe(mem_buf, tmp, &buffer_list, list) {
		free_memory_buffer(mem_buf);
	}

	device_destroy(anonmem_class, dev_num);
	class_destroy(anonmem_class);
	cdev_del(&anonmem_cdev);
	unregister_chrdev_region(dev_num, 1);

	printk(KERN_INFO "anonmem: Anonymous FD memory driver unloaded\n");
}

module_init(anonmem_init);
module_exit(anonmem_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Anonymous File Descriptor Memory Sharing Example");
MODULE_VERSION("1.0");

