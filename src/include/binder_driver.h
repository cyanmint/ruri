// SPDX-License-Identifier: MIT
/*
 * Header for minimal user-space binder driver
 */

#ifndef BINDER_DRIVER_H
#define BINDER_DRIVER_H

// Start the binder FUSE driver at the given mountpoint
int ruri_start_binder_driver(const char *mountpoint);

// Stop (unmount) the binder driver
int ruri_stop_binder_driver(const char *mountpoint);

#endif // BINDER_DRIVER_H
