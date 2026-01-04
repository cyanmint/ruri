/*
 * AI-GENERATED FILE NOTICE
 * 
 * This file was generated with the assistance of AI (GitHub Copilot).
 * As an AI-generated work, this file may not be subject to copyright
 * in some jurisdictions. The file is provided "AS IS" without warranty
 * of any kind, express or implied.
 * 
 * Users of this file should verify its correctness and suitability
 * for their specific use case before deployment.
 */

// SPDX-License-Identifier: MIT
/*
 *
 * This file is part of ruri, with ABSOLUTELY NO WARRANTY.
 *
 * MIT License
 *
 * Copyright (c) 2022-2024 Moe-hacker
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 *
 */
#include "include/ruri.h"

#ifndef DISABLE_FUSE
#define FUSE_USE_VERSION 31
#include <fuse3/fuse.h>
#include <pthread.h>
#include <ctype.h>

/*
 * This file implements FUSE-based filesystem virtualization for /proc.
 * When hidepid == 4, we mount a FUSE filesystem over /proc to provide
 * PID virtualization in conjunction with ptrace.
 * 
 * The approach:
 * 1. Pass through most /proc files to the real /proc
 * 2. For /proc/[pid] directories, map real PIDs to fake PIDs
 * 3. For /proc/self, always point to fake PID 1
 */

// FUSE context data
struct fuse_fs_ctx {
	char real_path[PATH_MAX];
	pid_t base_pid;
	char container_dir[PATH_MAX];
};

static struct fuse_fs_ctx proc_ctx = {
	.real_path = "/proc",
	.base_pid = 0,
	.container_dir = ""
};

/*
 * AI-GENERATED FUNCTION NOTICE
 * 
 * This function was generated with the assistance of AI (GitHub Copilot).
 * Users should verify its correctness before use.
 */
// Helper function to check if a path component is all digits (PID)
static bool is_pid_path(const char *name)
{
	if (name == NULL || name[0] == '\0') {
		return false;
	}
	
	for (size_t i = 0; name[i] != '\0'; i++) {
		if (!isdigit((unsigned char)name[i])) {
			return false;
		}
	}
	
	return true;
}

/*
 * AI-GENERATED FUNCTION NOTICE
 * 
 * This function was generated with the assistance of AI (GitHub Copilot).
 * Users should verify its correctness before use.
 */
// FUSE getattr implementation for fake /proc
// This passes through most requests to the real /proc
static int fuse_proc_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi)
{
	(void)fi;
	
	// For root directory
	if (strcmp(path, "/") == 0) {
		return stat(proc_ctx.real_path, stbuf);
	}
	
	// Build path to real /proc
	char real_path[PATH_MAX];
	snprintf(real_path, sizeof(real_path), "%s%s", proc_ctx.real_path, path);
	
	// Pass through to real /proc
	if (stat(real_path, stbuf) == -1) {
		return -errno;
	}
	
	return 0;
}

/*
 * AI-GENERATED FUNCTION NOTICE
 * 
 * This function was generated with the assistance of AI (GitHub Copilot).
 * Users should verify its correctness before use.
 */
// FUSE readdir implementation for fake /proc
// This shows only our container's processes as PID 1, 2, 3, etc.
static int fuse_proc_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                             off_t offset, struct fuse_file_info *fi,
                             enum fuse_readdir_flags flags)
{
	(void)offset;
	(void)fi;
	(void)flags;
	
	filler(buf, ".", NULL, 0, 0);
	filler(buf, "..", NULL, 0, 0);
	
	// For root /proc, we pass through most entries but filter PIDs
	if (strcmp(path, "/") == 0) {
		DIR *dp = opendir(proc_ctx.real_path);
		if (dp == NULL) {
			return -errno;
		}
		
		struct dirent *de;
		while ((de = readdir(dp)) != NULL) {
			// Skip . and ..
			if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) {
				continue;
			}
			
			// For PID directories, only show our base process as PID 1
			if (is_pid_path(de->d_name)) {
				pid_t real_pid = (pid_t)atoi(de->d_name);
				// Only show our container's base process
				if (real_pid == proc_ctx.base_pid) {
					filler(buf, "1", NULL, 0, 0);
				}
			} else {
				// Pass through non-PID entries
				filler(buf, de->d_name, NULL, 0, 0);
			}
		}
		
		closedir(dp);
		return 0;
	}
	
	// For subdirectories under /proc/[pid], pass through
	char real_path[PATH_MAX];
	snprintf(real_path, sizeof(real_path), "%s%s", proc_ctx.real_path, path);
	
	// Special handling for /proc/1 -> map to our base PID
	if (strcmp(path, "/1") == 0) {
		snprintf(real_path, sizeof(real_path), "%s/%d", proc_ctx.real_path, proc_ctx.base_pid);
	}
	
	DIR *dp = opendir(real_path);
	if (dp == NULL) {
		return -errno;
	}
	
	struct dirent *de;
	while ((de = readdir(dp)) != NULL) {
		filler(buf, de->d_name, NULL, 0, 0);
	}
	
	closedir(dp);
	return 0;
}

/*
 * AI-GENERATED FUNCTION NOTICE
 * 
 * This function was generated with the assistance of AI (GitHub Copilot).
 * Users should verify its correctness before use.
 */
// FUSE read implementation for fake /proc
static int fuse_proc_read(const char *path, char *buf, size_t size, off_t offset,
                          struct fuse_file_info *fi)
{
	(void)fi;
	
	char real_path[PATH_MAX];
	
	// Map /proc/1 to our real base PID
	if (strncmp(path, "/1/", 3) == 0 || strcmp(path, "/1") == 0) {
		const char *subpath = (strcmp(path, "/1") == 0) ? "" : (path + 2);
		snprintf(real_path, sizeof(real_path), "%s/%d%s", 
		         proc_ctx.real_path, proc_ctx.base_pid, subpath);
	} else {
		snprintf(real_path, sizeof(real_path), "%s%s", proc_ctx.real_path, path);
	}
	
	int fd = open(real_path, O_RDONLY);
	if (fd == -1) {
		return -errno;
	}
	
	ssize_t res = pread(fd, buf, size, offset);
	int save_errno = errno;
	close(fd);
	
	if (res == -1) {
		return -save_errno;
	}
	
	return (int)res;
}

/*
 * AI-GENERATED FUNCTION NOTICE
 * 
 * This function was generated with the assistance of AI (GitHub Copilot).
 * Users should verify its correctness before use.
 */
// FUSE readlink implementation
static int fuse_proc_readlink(const char *path, char *buf, size_t size)
{
	char real_path[PATH_MAX];
	
	// Special handling for /proc/self -> always point to fake PID 1
	if (strcmp(path, "/self") == 0) {
		snprintf(buf, size, "1");
		return 0;
	}
	
	// Map /proc/1 to our real base PID
	if (strncmp(path, "/1/", 3) == 0 || strcmp(path, "/1") == 0) {
		const char *subpath = (strcmp(path, "/1") == 0) ? "" : (path + 2);
		snprintf(real_path, sizeof(real_path), "%s/%d%s", 
		         proc_ctx.real_path, proc_ctx.base_pid, subpath);
	} else {
		snprintf(real_path, sizeof(real_path), "%s%s", proc_ctx.real_path, path);
	}
	
	ssize_t res = readlink(real_path, buf, size - 1);
	if (res == -1) {
		return -errno;
	}
	
	buf[res] = '\0';
	return 0;
}

/*
 * AI-GENERATED FUNCTION NOTICE
 * 
 * This function was generated with the assistance of AI (GitHub Copilot).
 * Users should verify its correctness before use.
 */
// FUSE open implementation
static int fuse_proc_open(const char *path, struct fuse_file_info *fi)
{
	char real_path[PATH_MAX];
	
	// Map /proc/1 to our real base PID
	if (strncmp(path, "/1/", 3) == 0 || strcmp(path, "/1") == 0) {
		const char *subpath = (strcmp(path, "/1") == 0) ? "" : (path + 2);
		snprintf(real_path, sizeof(real_path), "%s/%d%s", 
		         proc_ctx.real_path, proc_ctx.base_pid, subpath);
	} else {
		snprintf(real_path, sizeof(real_path), "%s%s", proc_ctx.real_path, path);
	}
	
	int fd = open(real_path, fi->flags);
	if (fd == -1) {
		return -errno;
	}
	
	close(fd);
	return 0;
}

static struct fuse_operations fuse_proc_ops = {
	.getattr = fuse_proc_getattr,
	.readdir = fuse_proc_readdir,
	.read = fuse_proc_read,
	.readlink = fuse_proc_readlink,
	.open = fuse_proc_open,
};

// Global FUSE handle for cleanup
static struct fuse *global_fuse = NULL;
static pthread_t global_fuse_thread = 0;

/*
 * AI-GENERATED FUNCTION NOTICE
 * 
 * This function was generated with the assistance of AI (GitHub Copilot).
 * Users should verify its correctness before use.
 */
// Thread function to run FUSE for /proc
static void *fuse_proc_thread(void *arg)
{
	char *mountpoint = (char *)arg;
	
	// FUSE options
	char *fuse_argv[] = {
		"ruri_fuse",
		"-f", // foreground
		"-o", "allow_other",
		"-o", "default_permissions",
		"-o", "fsname=ruri_proc",
		mountpoint,
		NULL
	};
	int fuse_argc = 8;
	
	struct fuse_args args = FUSE_ARGS_INIT(fuse_argc, fuse_argv);
	struct fuse *fuse = fuse_new(&args, &fuse_proc_ops, sizeof(fuse_proc_ops), NULL);
	
	if (fuse == NULL) {
		ruri_warning("{yellow}Failed to create FUSE filesystem\n");
		free(arg);
		return NULL;
	}
	
	global_fuse = fuse;
	
	if (fuse_mount(fuse, mountpoint) != 0) {
		ruri_warning("{yellow}Failed to mount FUSE filesystem at %s\n", mountpoint);
		fuse_destroy(fuse);
		global_fuse = NULL;
		free(arg);
		return NULL;
	}
	
	ruri_log("{base}FUSE /proc mounted at %s\n", mountpoint);
	
	// Run FUSE main loop
	fuse_loop(fuse);
	
	// Cleanup
	fuse_unmount(fuse);
	fuse_destroy(fuse);
	global_fuse = NULL;
	free(arg);
	
	return NULL;
}

/*
 * AI-GENERATED FUNCTION NOTICE
 * 
 * This function was generated with the assistance of AI (GitHub Copilot).
 * Users should verify its correctness before use.
 */
// Initialize FUSE-based filesystem virtualization
void ruri_init_fuse_fs(const char *container_dir, pid_t base_pid)
{
	ruri_log("{base}Initializing FUSE filesystem virtualization (PID %d)\n", base_pid);
	
	proc_ctx.base_pid = base_pid;
	strncpy(proc_ctx.container_dir, container_dir, sizeof(proc_ctx.container_dir) - 1);
	
	// Create mount point for /proc
	char proc_mount[PATH_MAX];
	
	// If container_dir is "/", we're already inside the container
	if (strcmp(container_dir, "/") == 0) {
		snprintf(proc_mount, sizeof(proc_mount), "/proc");
	} else {
		snprintf(proc_mount, sizeof(proc_mount), "%s/proc", container_dir);
	}
	
	// Ensure the directory exists
	if (access(proc_mount, F_OK) != 0) {
		if (mkdir(proc_mount, 0755) != 0 && errno != EEXIST) {
			ruri_warning("{yellow}Failed to create /proc mount point: %s\n", strerror(errno));
			return;
		}
	}
	
	// Allocate string for thread (will be freed by thread)
	char *proc_mount_copy = strdup(proc_mount);
	if (proc_mount_copy == NULL) {
		ruri_warning("{yellow}Failed to allocate memory for mount point\n");
		return;
	}
	
	// Start FUSE in a separate thread
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	
	if (pthread_create(&global_fuse_thread, &attr, fuse_proc_thread, proc_mount_copy) != 0) {
		ruri_warning("{yellow}Failed to create FUSE thread: %s\n", strerror(errno));
		free(proc_mount_copy);
		pthread_attr_destroy(&attr);
		return;
	}
	
	pthread_attr_destroy(&attr);
	
	// Give FUSE time to initialize
	#define FUSE_INIT_DELAY_US 100000
	usleep(FUSE_INIT_DELAY_US); // 100ms
	
	ruri_log("{base}FUSE filesystem virtualization started\n");
}

/*
 * AI-GENERATED FUNCTION NOTICE
 * 
 * This function was generated with the assistance of AI (GitHub Copilot).
 * Users should verify its correctness before use.
 */
// Cleanup FUSE filesystem
// Note: This is called on exit; FUSE will be automatically unmounted when the process exits
void ruri_cleanup_fuse_fs(void)
{
	// FUSE will be automatically cleaned up when the process exits
	// We don't use pthread_cancel as it can leave resources in inconsistent state
	global_fuse = NULL;
	global_fuse_thread = 0;
}

#else
// Stub implementation when FUSE is disabled
void ruri_init_fuse_fs(const char *container_dir, pid_t base_pid)
{
	(void)container_dir;
	(void)base_pid;
	ruri_warning("{yellow}FUSE support is not compiled in, -i 4 mode unavailable\n");
}

void ruri_cleanup_fuse_fs(void)
{
	// Nothing to do
}
#endif
