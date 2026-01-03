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
 * fakepid.c - LD_PRELOAD library to fake PID-related syscalls
 * 
 * This library intercepts getpid(), getppid(), and related syscalls
 * to make processes think they are running with different PIDs.
 * This is used to fool init systems like systemd into thinking they
 * are PID 1 even when they're not.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Real PID of the container init process
static pid_t real_init_pid = 0;
static int initialized = 0;

// Function pointers to real syscalls
static pid_t (*real_getpid)(void) = NULL;
static pid_t (*real_getppid)(void) = NULL;

// Initialize the library
static void init_fakepid(void) __attribute__((constructor));

static void init_fakepid(void)
{
	if (initialized) {
		return;
	}
	
	// Get the real syscall functions
	real_getpid = dlsym(RTLD_NEXT, "getpid");
	real_getppid = dlsym(RTLD_NEXT, "getppid");
	
	// Get the real init PID from environment variable
	const char *init_pid_str = getenv("RURI_FAKE_INIT_PID");
	if (init_pid_str) {
		real_init_pid = atoi(init_pid_str);
	} else {
		// If not set, use current PID as init
		real_init_pid = real_getpid();
	}
	
	initialized = 1;
}

// Fake getpid() - returns 1 if this is the init process
pid_t getpid(void)
{
	if (!initialized) {
		init_fakepid();
	}
	
	pid_t real_pid = real_getpid();
	
	// If this is the init process, return 1
	if (real_pid == real_init_pid) {
		return 1;
	}
	
	// For other processes, return a fake PID based on real PID
	// This keeps PIDs sequential-looking
	// We subtract (real_init_pid - 1) to make init's children start at 2
	if (real_pid > real_init_pid) {
		return real_pid - real_init_pid + 1;
	}
	
	// Fallback: return real PID
	return real_pid;
}

// Fake getppid() - returns 0 if parent is the fake init, 1 if parent is something else
pid_t getppid(void)
{
	if (!initialized) {
		init_fakepid();
	}
	
	pid_t real_ppid = real_getppid();
	
	// If parent is the init process, return 0 (init has no parent)
	if (real_ppid == real_init_pid) {
		return 0;
	}
	
	// If this is the init process, return 0
	pid_t real_pid = real_getpid();
	if (real_pid == real_init_pid) {
		return 0;
	}
	
	// For other processes, try to fake the parent PID
	if (real_ppid > real_init_pid) {
		return real_ppid - real_init_pid + 1;
	}
	
	// If parent is before init, return 1 (init)
	return 1;
}
