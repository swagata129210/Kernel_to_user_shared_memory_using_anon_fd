#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <errno.h>

#define DEVICE_PATH "/dev/anon_memory"

#define ANONMEM_IOC_MAGIC 'A'
#define ANONMEM_GET_FD     _IOR(ANONMEM_IOC_MAGIC, 1, int)
#define ANONMEM_WRITE_DATA _IOW(ANONMEM_IOC_MAGIC, 2, struct mem_write_info)

struct mem_write_info {
	unsigned long offset;
	char data[256];
	size_t data_len;
};

#define BUFFER_SIZE (4096*64)

int main()
{
	int dev_fd, anon_fd;
	void *mapped_memory;
	struct mem_write_info write_info;
	char *buffer;
	int ret;

	printf("=== Anonymous File Descriptor Memory Sharing Test ===\n");

	// Open the main device
	dev_fd = open(DEVICE_PATH, O_RDWR);
	if (dev_fd < 0) {
		perror("Failed to open device");
		return -1;
	}

	// Get anonymous file descriptor
	printf("\n1. Requesting anonymous file descriptor...\n");
	ret = ioctl(dev_fd, ANONMEM_GET_FD, &anon_fd);
	if (ret < 0) {
		perror("ANONMEM_GET_FD failed");
		close(dev_fd);
	return -1;
	}
	printf("Received anonymous fd: %d\n", anon_fd);

	// Map memory using the anonymous fd
	printf("\n2. Mapping memory using anonymous fd...\n");
	mapped_memory = mmap(NULL, BUFFER_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, anon_fd, 0);
	if (mapped_memory == MAP_FAILED) {
		perror("mmap failed");
		close(anon_fd);
		close(dev_fd);
		return -1;
	}
	printf("Memory mapped at: %p\n", mapped_memory);

	

	// Read initial content from kernel buffer
	buffer = (char *)mapped_memory;
	printf("\n3. Initial buffer content from kernel:\n");
	printf("First 256 bytes: '%.256s'\n", buffer);
	// print_hex_dump(buffer, 64, "Initial Memory Content");

	printf("\n4. Filling mapped memory with 'x' from user space...\n");
	memset(mapped_memory, 'x', BUFFER_SIZE);

	// Modify memory from user space
	printf("\n4. Writing data from user space...\n");
	strcpy(buffer + 500, "Hello from user space! This is shared memory.");
	printf("Written to offset 500: 'Hello from user space! This is shared memory.'\n");

	// Ask kernel to write something
	printf("\n5. Asking kernel to write data...\n");
	write_info.offset = 1000;
	strcpy(write_info.data, "Kernel writes: Shared memory works perfectly!");
	write_info.data_len = strlen(write_info.data);

	ret = ioctl(dev_fd, ANONMEM_WRITE_DATA, &write_info);
	if (ret < 0) {
		perror("ANONMEM_WRITE_DATA failed");
	} else {
		printf("Kernel wrote: '%s' at offset %lu\n", write_info.data, write_info.offset);
	}

	// Read both user and kernel modifications
	printf("\n6. Reading final buffer content:\n");
	printf("Offset 0   (kernel initial): '%.100s'\n", buffer);
	printf("Offset 500 (user wrote):     '%.100s'\n", buffer + 500);
	printf("Offset 1000 (kernel wrote):  '%.100s'\n", buffer + 1000);

	// Show memory layout
	printf("\n7. Memory usage verification:\n");
	printf("User space can read/write at: %p\n", mapped_memory);
	printf("Data at offset 500 (user):   '%c%c%c%c%c'\n",
			buffer[500], buffer[501], buffer[502], buffer[503], buffer[504]);
	printf("Data at offset 1000 (kernel): '%c%c%c%c%c%c'\n", 
			buffer[1000], buffer[1001], buffer[1002], buffer[1003], buffer[1004], buffer[1005]);

	printf("\n=== Test completed successfully! ===\n");
	
	munmap(mapped_memory, BUFFER_SIZE);
	close(anon_fd);
	close(dev_fd);

	return 0;
}

