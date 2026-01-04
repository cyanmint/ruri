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
 * fakefs.c - FUSE-based passthrough filesystem for /proc, /sys, /dev emulation
 * 
 * This provides a simple FUSE filesystem that mirrors the host's directories.
 * Used by -i 4 mode to provide better compatibility with Android/redroid containers.
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
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <limits.h>
#include <signal.h>

/* Global variable to store source directory */
static char *g_source_dir = NULL;

/* Build full path from source directory and relative path */
static void build_path(char *dest, size_t dest_size, const char *path)
{
	if (g_source_dir) {
		snprintf(dest, dest_size, "%s%s", g_source_dir, path);
	} else {
		snprintf(dest, dest_size, "%s", path);
	}
}

static int fakefs_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi)
{
	(void) fi;
	char fullpath[PATH_MAX];
	
	build_path(fullpath, sizeof(fullpath), path);
	
	if (lstat(fullpath, stbuf) == -1) {
		return -errno;
	}
	
	return 0;
}

static int fakefs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                         off_t offset, struct fuse_file_info *fi,
                         enum fuse_readdir_flags flags)
{
	DIR *dp;
	struct dirent *de;
	char fullpath[PATH_MAX];
	
	(void) offset;
	(void) fi;
	(void) flags;
	
	build_path(fullpath, sizeof(fullpath), path);
	
	dp = opendir(fullpath);
	if (dp == NULL) {
		return -errno;
	}
	
	while ((de = readdir(dp)) != NULL) {
		struct stat st;
		memset(&st, 0, sizeof(st));
		st.st_ino = de->d_ino;
		st.st_mode = de->d_type << 12;
		if (filler(buf, de->d_name, &st, 0, 0))
			break;
	}
	
	closedir(dp);
	return 0;
}

static int fakefs_open(const char *path, struct fuse_file_info *fi)
{
	int fd;
	char fullpath[PATH_MAX];
	
	build_path(fullpath, sizeof(fullpath), path);
	
	fd = open(fullpath, fi->flags);
	if (fd == -1) {
		return -errno;
	}
	
	fi->fh = fd;
	return 0;
}

static int fakefs_read(const char *path, char *buf, size_t size, off_t offset,
                      struct fuse_file_info *fi)
{
	int res;
	
	(void) path;
	res = pread(fi->fh, buf, size, offset);
	if (res == -1) {
		res = -errno;
	}
	
	return res;
}

static int fakefs_release(const char *path, struct fuse_file_info *fi)
{
	(void) path;
	close(fi->fh);
	return 0;
}

static int fakefs_readlink(const char *path, char *buf, size_t size)
{
	int res;
	char fullpath[PATH_MAX];
	
	build_path(fullpath, sizeof(fullpath), path);
	
	res = readlink(fullpath, buf, size - 1);
	if (res == -1) {
		return -errno;
	}
	
	buf[res] = '\0';
	return 0;
}

static const struct fuse_operations fakefs_oper = {
	.getattr	= fakefs_getattr,
	.readdir	= fakefs_readdir,
	.open		= fakefs_open,
	.read		= fakefs_read,
	.release	= fakefs_release,
	.readlink	= fakefs_readlink,
};

/* Start FUSE filesystem in background */
int ruri_start_fuse_mount(const char *mountpoint, const char *source)
{
	pid_t pid;
	
	/* Allocate and copy source directory */
	g_source_dir = strdup(source);
	if (!g_source_dir) {
		return -1;
	}
	
	pid = fork();
	if (pid == -1) {
		free(g_source_dir);
		return -1;
	}
	
	if (pid == 0) {
		/* Child process - run FUSE */
		char *fuse_argv[] = {
			"ruri-fuse",
			"-f",  /* foreground (in child process) */
			"-o", "ro",  /* read-only */
			"-o", "allow_other",
			"-o", "default_permissions",
			(char *)mountpoint,
			NULL
		};
		int fuse_argc = 8;
		
		/* Run FUSE main loop - this won't return */
		fuse_main(fuse_argc, fuse_argv, &fakefs_oper, g_source_dir);
		
		/* If we get here, FUSE failed */
		exit(1);
	}
	
	/* Parent process - wait a bit for FUSE to mount */
	usleep(200000); /* 200ms */
	
	return pid;
}

/* Stop FUSE filesystem */
int ruri_stop_fuse_mount(int pid)
{
	if (pid > 0) {
		kill(pid, SIGTERM);
		/* Wait a bit for graceful shutdown */
		usleep(100000); /* 100ms */
	}
	return 0;
}

