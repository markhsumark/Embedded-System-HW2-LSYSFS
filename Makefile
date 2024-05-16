COMPILER = gcc
FILESYSTEM_FILES = lsysfs.c

build: $(FILESYSTEM_FILES)
	$(COMPILER) $(FILESYSTEM_FILES) aes/aes.c -I aes -o lsysfs `pkg-config fuse --cflags --libs` -lssl -lcrypto
	echo 'To Mount: ./lsysfs -f [mount point]'

clean:
	rm ssfs
