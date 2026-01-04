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
#include <sys/ptrace.h>

// Platform-specific includes for register access
#if defined(__x86_64__) || defined(__aarch64__)
#include <sys/user.h>
#endif

#ifdef __aarch64__
#include <linux/elf.h>
#endif

/*
 * This file implements PID namespace virtualization using ptrace.
 * When hidepid >= 3, we use ptrace to intercept PID-related syscalls
 * and return fake PIDs to make processes think they're in a proper
 * container with PID 1 as init.
 * 
 * Platform-specific implementation available for:
 * - x86_64 (amd64)
 * - aarch64 (ARM64)
 */

// Syscall numbers for different architectures
#ifdef __x86_64__
#define SYS_getpid_arch 39
#define SYS_getppid_arch 110
#define SYS_getpgid_arch 121
#define SYS_getsid_arch 124
#define SYS_gettid_arch 186
#elif defined(__aarch64__)
#define SYS_getpid_arch 172
#define SYS_getppid_arch 173
#define SYS_getpgid_arch 155
#define SYS_getsid_arch 156
#define SYS_gettid_arch 178
#endif

// PID mapping structure
struct pid_map {
	pid_t real_pid;
	pid_t fake_pid;
	struct pid_map *next;
};

static struct pid_map *pid_map_head = NULL;
static pid_t next_fake_pid = 1;
static pid_t base_real_pid = 0;

/*
 * AI-GENERATED FUNCTION NOTICE
 * 
 * This function was generated with the assistance of AI (GitHub Copilot).
 * Users should verify its correctness before use.
 */
// Get or create fake PID for a real PID
static pid_t get_fake_pid(pid_t real_pid)
{
	struct pid_map *map = pid_map_head;
	
	// Check if we already have a mapping
	while (map != NULL) {
		if (map->real_pid == real_pid) {
			return map->fake_pid;
		}
		map = map->next;
	}
	
	// Create new mapping
	map = (struct pid_map *)malloc(sizeof(struct pid_map));
	if (map == NULL) {
		return real_pid; // Fallback to real PID
	}
	
	map->real_pid = real_pid;
	map->fake_pid = next_fake_pid++;
	map->next = pid_map_head;
	pid_map_head = map;
	
	return map->fake_pid;
}

/*
 * AI-GENERATED FUNCTION NOTICE
 * 
 * This function was generated with the assistance of AI (GitHub Copilot).
 * Users should verify its correctness before use.
 */
// Ptrace wrapper to intercept and modify PID-related syscalls
// Platform-specific implementation for x86_64 and aarch64
void ruri_ptrace_pid_wrapper(pid_t child_pid)
{
	int status;
	bool in_syscall = false;
	
	base_real_pid = child_pid;
	
	// First PID should be mapped to 1
	get_fake_pid(child_pid);
	
	// Wait for child to be ready
	if (waitpid(child_pid, &status, 0) == -1) {
		return;
	}
	
	// Enable ptrace options to trace syscalls
	if (ptrace(PTRACE_SETOPTIONS, child_pid, 0,
	           PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK | 
	           PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE) == -1) {
		// Ptrace failed, continue without PID virtualization
		ruri_warning("{yellow}Failed to enable ptrace, PID virtualization disabled\n");
		ptrace(PTRACE_DETACH, child_pid, 0, 0);
		return;
	}
	
#if defined(__x86_64__) || defined(__aarch64__)
	// Platform-specific implementation
	ruri_log("{base}Starting PID virtualization for %s\n", 
#ifdef __x86_64__
	         "x86_64"
#else
	         "aarch64"
#endif
	);
	
	// Main ptrace loop - intercept syscalls
	while (1) {
		// Continue and wait for next syscall
		if (ptrace(PTRACE_SYSCALL, child_pid, 0, 0) == -1) {
			break;
		}
		
		if (waitpid(child_pid, &status, 0) == -1) {
			break;
		}
		
		if (WIFEXITED(status) || WIFSIGNALED(status)) {
			break;
		}
		
		// Handle new child processes from fork/vfork/clone
		if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_FORK << 8)) ||
		    status >> 8 == (SIGTRAP | (PTRACE_EVENT_VFORK << 8)) ||
		    status >> 8 == (SIGTRAP | (PTRACE_EVENT_CLONE << 8))) {
			unsigned long new_pid = 0;
			ptrace(PTRACE_GETEVENTMSG, child_pid, 0, &new_pid);
			if (new_pid > 0) {
				get_fake_pid((pid_t)new_pid);
			}
			continue;
		}
		
#ifdef __x86_64__
		// x86_64 implementation
		struct user_regs_struct regs;
		if (ptrace(PTRACE_GETREGS, child_pid, 0, &regs) == -1) {
			continue;
		}
		
		if (!in_syscall) {
			// Entering syscall
			in_syscall = true;
		} else {
			// Exiting syscall - check if it's a PID-related syscall
			long syscall_num = regs.orig_rax;
			
			if (syscall_num == SYS_getpid_arch || 
			    syscall_num == SYS_getppid_arch ||
			    syscall_num == SYS_gettid_arch ||
			    syscall_num == SYS_getpgid_arch ||
			    syscall_num == SYS_getsid_arch) {
				// Get the return value (real PID)
				pid_t real_pid = (pid_t)regs.rax;
				if (real_pid > 0) {
					pid_t fake_pid = get_fake_pid(real_pid);
					// Modify the return value
					regs.rax = fake_pid;
					ptrace(PTRACE_SETREGS, child_pid, 0, &regs);
					
					ruri_log("{base}Mapped PID %d -> %d for syscall %ld\n", 
					         real_pid, fake_pid, syscall_num);
				}
			}
			
			in_syscall = false;
		}
#elif defined(__aarch64__)
		// aarch64 implementation
		struct user_pt_regs regs;
		struct iovec iov;
		iov.iov_base = &regs;
		iov.iov_len = sizeof(regs);
		
		if (ptrace(PTRACE_GETREGSET, child_pid, NT_PRSTATUS, &iov) == -1) {
			continue;
		}
		
		if (!in_syscall) {
			// Entering syscall
			in_syscall = true;
		} else {
			// Exiting syscall - check if it's a PID-related syscall
			long syscall_num = regs.regs[8];
			
			if (syscall_num == SYS_getpid_arch || 
			    syscall_num == SYS_getppid_arch ||
			    syscall_num == SYS_gettid_arch ||
			    syscall_num == SYS_getpgid_arch ||
			    syscall_num == SYS_getsid_arch) {
				// Get the return value (real PID)
				pid_t real_pid = (pid_t)regs.regs[0];
				if (real_pid > 0) {
					pid_t fake_pid = get_fake_pid(real_pid);
					// Modify the return value
					regs.regs[0] = fake_pid;
					
					iov.iov_base = &regs;
					iov.iov_len = sizeof(regs);
					ptrace(PTRACE_SETREGSET, child_pid, NT_PRSTATUS, &iov);
					
					ruri_log("{base}Mapped PID %d -> %d for syscall %ld\n", 
					         real_pid, fake_pid, syscall_num);
				}
			}
			
			in_syscall = false;
		}
#endif
	}
#else
	// Non-supported architecture - basic loop without PID mapping
	ruri_warning("{yellow}PID virtualization not implemented for this architecture\n");
	while (1) {
		if (ptrace(PTRACE_SYSCALL, child_pid, 0, 0) == -1) {
			break;
		}
		
		if (waitpid(child_pid, &status, 0) == -1) {
			break;
		}
		
		if (WIFEXITED(status) || WIFSIGNALED(status)) {
			break;
		}
	}
#endif
	
	// Cleanup
	ruri_cleanup_ptrace_pid();
}

/*
 * AI-GENERATED FUNCTION NOTICE
 * 
 * This function was generated with the assistance of AI (GitHub Copilot).
 * Users should verify its correctness before use.
 */
// Initialize ptrace-based PID virtualization
void ruri_init_ptrace_pid(void)
{
	ruri_log("{base}Initializing ptrace PID virtualization\n");
	
	// Request to be traced
	if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
		ruri_warning("{yellow}Failed to initialize ptrace for PID virtualization\n");
		return;
	}
	
	// Send signal to parent to start tracing
	raise(SIGSTOP);
}

/*
 * AI-GENERATED FUNCTION NOTICE
 * 
 * This function was generated with the assistance of AI (GitHub Copilot).
 * Users should verify its correctness before use.
 */
// Cleanup PID mapping
void ruri_cleanup_ptrace_pid(void)
{
	struct pid_map *map = pid_map_head;
	struct pid_map *next;
	
	while (map != NULL) {
		next = map->next;
		free(map);
		map = next;
	}
	
	pid_map_head = NULL;
	next_fake_pid = 1;
}
