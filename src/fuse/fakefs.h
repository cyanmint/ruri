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
#ifndef RURI_FUSE_H
#define RURI_FUSE_H

/* Start FUSE filesystem that mirrors source directory to mountpoint */
int ruri_start_fuse_mount(const char *mountpoint, const char *source);

/* Stop FUSE filesystem by PID */
int ruri_stop_fuse_mount(int pid);

#endif /* RURI_FUSE_H */
