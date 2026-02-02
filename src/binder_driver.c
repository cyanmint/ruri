// SPDX-License-Identifier: MIT
/*
 * Minimal user-space binder driver for ruri
 * 
 * This provides a basic binder device emulation using FUSE
 * to allow redroid to initialize even without kernel binder support.
 * 
 * Note: This is a minimal stub implementation that handles basic
 * operations but does not provide full binder IPC functionality.
 */

#define FUSE_USE_VERSION 31

#include <fuse3/fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/sysmacros.h>
#include <sys/stat.h>
#include <pthread.h>

// Binder ioctl commands (from Android kernel headers)
#define BINDER_WRITE_READ 0xc0306201
#define BINDER_SET_MAX_THREADS 0x40046205
#define BINDER_SET_CONTEXT_MGR 0x40046207
#define BINDER_VERSION 0xc0046209
#define BINDER_SET_IDLE_TIMEOUT 0x40086203
#define BINDER_SET_IDLE_PRIORITY 0x40046206

struct binder_version {
	signed long protocol_version;
};

struct binder_write_read {
	signed long write_size;
	signed long write_consumed;
	unsigned long write_buffer;
	signed long read_size;
	signed long read_consumed;
	unsigned long read_buffer;
};

static int binder_getattr(const char *path, struct stat *stbuf,
			 struct fuse_file_info *fi)
{
	(void) fi;
	memset(stbuf, 0, sizeof(struct stat));
	
	if (strcmp(path, "/") == 0) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
	} else if (strcmp(path, "/binder") == 0 ||
		   strcmp(path, "/hwbinder") == 0 ||
		   strcmp(path, "/vndbinder") == 0) {
		// Character device with rw permissions
		stbuf->st_mode = S_IFCHR | 0666;
		stbuf->st_nlink = 1;
		stbuf->st_rdev = makedev(10, 56); // misc device
	} else {
		return -ENOENT;
	}
	
	return 0;
}

static int binder_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			 off_t offset, struct fuse_file_info *fi,
			 enum fuse_readdir_flags flags)
{
	(void) offset;
	(void) fi;
	(void) flags;

	if (strcmp(path, "/") != 0)
		return -ENOENT;

	filler(buf, ".", NULL, 0, 0);
	filler(buf, "..", NULL, 0, 0);
	filler(buf, "binder", NULL, 0, 0);
	filler(buf, "hwbinder", NULL, 0, 0);
	filler(buf, "vndbinder", NULL, 0, 0);

	return 0;
}

static int binder_open(const char *path, struct fuse_file_info *fi)
{
	// Allow opening binder device files
	if (strcmp(path, "/binder") == 0 ||
	    strcmp(path, "/hwbinder") == 0 ||
	    strcmp(path, "/vndbinder") == 0) {
		return 0;
	}
	
	return -ENOENT;
}

static int binder_read(const char *path, char *buf, size_t size, off_t offset,
		      struct fuse_file_info *fi)
{
	(void) fi;
	(void) offset;
	
	// Return empty data for reads
	memset(buf, 0, size);
	return size;
}

static int binder_write(const char *path, const char *buf, size_t size,
		       off_t offset, struct fuse_file_info *fi)
{
	(void) path;
	(void) buf;
	(void) offset;
	(void) fi;
	
	// Accept writes but do nothing
	return size;
}

static int binder_ioctl(const char *path, int cmd, void *arg,
		       struct fuse_file_info *fi, unsigned int flags, void *data)
{
	(void) path;
	(void) fi;
	(void) flags;
	
	// Handle common binder ioctl commands
	switch (cmd) {
	case BINDER_VERSION: {
		struct binder_version *ver = (struct binder_version *)data;
		ver->protocol_version = 8; // Binder protocol version 8
		return 0;
	}
	
	case BINDER_SET_MAX_THREADS:
	case BINDER_SET_CONTEXT_MGR:
	case BINDER_SET_IDLE_TIMEOUT:
	case BINDER_SET_IDLE_PRIORITY:
		// Accept these commands and return success
		return 0;
	
	case BINDER_WRITE_READ: {
		struct binder_write_read *bwr = (struct binder_write_read *)data;
		// Pretend we consumed all data
		if (bwr) {
			bwr->write_consumed = bwr->write_size;
			bwr->read_consumed = 0;
		}
		return 0;
	}
	
	default:
		// Unknown ioctl - return success anyway to avoid errors
		return 0;
	}
}

static const struct fuse_operations binder_oper = {
	.getattr	= binder_getattr,
	.readdir	= binder_readdir,
	.open		= binder_open,
	.read		= binder_read,
	.write		= binder_write,
	.ioctl		= binder_ioctl,
};

// Launch binder FUSE driver in background
int ruri_start_binder_driver(const char *mountpoint)
{
	// First, ensure mountpoint exists and is a directory
	struct stat st;
	if (stat(mountpoint, &st) != 0) {
		mkdir(mountpoint, 0755);
	}
	
	pid_t pid = fork();
	
	if (pid < 0) {
		perror("fork failed");
		return -1;
	}
	
	if (pid == 0) {
		// Child process - run FUSE
		// Become session leader to detach from parent
		setsid();
		
		// Close standard file descriptors
		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		close(STDERR_FILENO);
		
		// Open /dev/null for stdio
		int devnull = open("/dev/null", O_RDWR);
		if (devnull >= 0) {
			dup2(devnull, STDIN_FILENO);
			dup2(devnull, STDOUT_FILENO);
			dup2(devnull, STDERR_FILENO);
			if (devnull > 2) {
				close(devnull);
			}
		}
		
		char *argv[] = {
			"ruri_binder",
			"-f",  // foreground (required for daemon)
			"-o", "allow_other",
			"-o", "default_permissions",
			(char *)mountpoint,
			NULL
		};
		
		// Run FUSE - this blocks until unmount
		int ret = fuse_main(6, argv, &binder_oper, NULL);
		exit(ret);
	}
	
	// Parent process - wait for FUSE to initialize
	sleep(1); // Give FUSE time to mount
	
	// Verify that FUSE mounted successfully
	char testfile[512];
	snprintf(testfile, sizeof(testfile), "%s/binder", mountpoint);
	if (stat(testfile, &st) == 0) {
		return 0; // Success - binder file exists
	}
	
	// Still not there, wait a bit more
	sleep(1);
	if (stat(testfile, &st) == 0) {
		return 0; // Success
	}
	
	// Failed to mount
	return -1;
}

// Stop binder driver (unmount)
int ruri_stop_binder_driver(const char *mountpoint)
{
	char cmd[512];
	snprintf(cmd, sizeof(cmd), "fusermount3 -u %s 2>/dev/null || fusermount -u %s 2>/dev/null", 
		 mountpoint, mountpoint);
	return system(cmd);
}
