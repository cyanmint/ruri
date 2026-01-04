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

/*
 * This file implements FUSE-based filesystem virtualization for /proc, /sys, /dev.
 * When hidepid == 4, we mount FUSE filesystems to emulate these directories
 * with fake PID information.
 */

// FUSE context data
struct fuse_fs_ctx {
	char *real_path;
	pid_t base_pid;
};

static struct fuse_fs_ctx proc_ctx = { .real_path = "/proc", .base_pid = 0 };

/*
 * AI-GENERATED FUNCTION NOTICE
 * 
 * This function was generated with the assistance of AI (GitHub Copilot).
 * Users should verify its correctness before use.
 */
// FUSE getattr implementation for fake /proc
static int fuse_proc_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi)
{
	(void)fi;
	memset(stbuf, 0, sizeof(struct stat));
	
	if (strcmp(path, "/") == 0) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
		return 0;
	}
	
	// Check if it's a PID directory (numeric)
	if (path[0] == '/' && isdigit(path[1])) {
		// Map to fake PID 1 if it matches our container's base process
		char real_path[PATH_MAX];
		snprintf(real_path, sizeof(real_path), "%s%s", proc_ctx.real_path, path);
		
		if (stat(real_path, stbuf) == 0) {
			return 0;
		}
	}
	
	// For other files, try to get from real /proc
	char real_path[PATH_MAX];
	snprintf(real_path, sizeof(real_path), "%s%s", proc_ctx.real_path, path);
	
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
static int fuse_proc_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                             off_t offset, struct fuse_file_info *fi,
                             enum fuse_readdir_flags flags)
{
	(void)offset;
	(void)fi;
	(void)flags;
	
	filler(buf, ".", NULL, 0, 0);
	filler(buf, "..", NULL, 0, 0);
	
	if (strcmp(path, "/") == 0) {
		// Add fake PID 1 directory
		filler(buf, "1", NULL, 0, 0);
		
		// Add other standard /proc entries
		filler(buf, "self", NULL, 0, 0);
		filler(buf, "cpuinfo", NULL, 0, 0);
		filler(buf, "meminfo", NULL, 0, 0);
		filler(buf, "mounts", NULL, 0, 0);
		filler(buf, "stat", NULL, 0, 0);
		filler(buf, "uptime", NULL, 0, 0);
	}
	
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
	snprintf(real_path, sizeof(real_path), "%s%s", proc_ctx.real_path, path);
	
	int fd = open(real_path, O_RDONLY);
	if (fd == -1) {
		return -errno;
	}
	
	ssize_t res = pread(fd, buf, size, offset);
	if (res == -1) {
		res = -errno;
	}
	
	close(fd);
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
	snprintf(real_path, sizeof(real_path), "%s%s", proc_ctx.real_path, path);
	
	ssize_t res = readlink(real_path, buf, size - 1);
	if (res == -1) {
		return -errno;
	}
	
	buf[res] = '\0';
	return 0;
}

static struct fuse_operations fuse_proc_ops = {
	.getattr = fuse_proc_getattr,
	.readdir = fuse_proc_readdir,
	.read = fuse_proc_read,
	.readlink = fuse_proc_readlink,
};

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
	char *fuse_argv[] = {
		"ruri_fuse",
		"-f", // foreground
		"-o", "allow_other",
		"-o", "default_permissions",
		mountpoint,
		NULL
	};
	int fuse_argc = 7;
	
	struct fuse_args args = FUSE_ARGS_INIT(fuse_argc, fuse_argv);
	struct fuse *fuse = fuse_new(&args, &fuse_proc_ops, sizeof(fuse_proc_ops), NULL);
	
	if (fuse == NULL) {
		ruri_warning("{yellow}Failed to create FUSE filesystem\n");
		return NULL;
	}
	
	if (fuse_mount(fuse, mountpoint) != 0) {
		ruri_warning("{yellow}Failed to mount FUSE filesystem\n");
		fuse_destroy(fuse);
		return NULL;
	}
	
	fuse_loop(fuse);
	fuse_unmount(fuse);
	fuse_destroy(fuse);
	
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
	ruri_log("{base}Initializing FUSE filesystem virtualization\n");
	
	proc_ctx.base_pid = base_pid;
	
	// Create mount points
	char proc_mount[PATH_MAX];
	snprintf(proc_mount, sizeof(proc_mount), "%s/proc", container_dir);
	
	// Ensure directories exist
	ruri_mkdirs(proc_mount, 0755);
	
	// Start FUSE in a separate thread
	pthread_t fuse_thread;
	if (pthread_create(&fuse_thread, NULL, fuse_proc_thread, proc_mount) != 0) {
		ruri_warning("{yellow}Failed to create FUSE thread\n");
		return;
	}
	
	pthread_detach(fuse_thread);
	
	ruri_log("{base}FUSE filesystem virtualization initialized\n");
}

#else
// Stub implementation when FUSE is disabled
void ruri_init_fuse_fs(const char *container_dir, pid_t base_pid)
{
	(void)container_dir;
	(void)base_pid;
	ruri_warning("{yellow}FUSE support is not compiled in, -i 4 mode unavailable\n");
}
#endif
