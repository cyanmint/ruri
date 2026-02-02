# User-Space Binder Driver

## Overview

This directory contains the user-space binder driver implementation for ruri's `-B` option. The driver uses FUSE (Filesystem in Userspace) to emulate Android binder devices without requiring kernel modules.

## Implementation

### Files
- `binder_driver.c` - FUSE-based binder driver implementation
- `include/binder_driver.h` - Public API header

### Features
- Emulates `/dev/binderfs/` filesystem
- Provides binder, hwbinder, and vndbinder character devices
- Handles basic binder ioctl commands
- Complete isolation from host binder devices
- No kernel module requirements

### Binder Protocol Support
- `BINDER_VERSION` - Protocol version reporting
- `BINDER_SET_MAX_THREADS` - Thread management
- `BINDER_SET_CONTEXT_MGR` - Context manager
- `BINDER_WRITE_READ` - Transaction handling  
- Additional ioctl stubs for compatibility

## Usage

The driver is automatically used by the `-B` option when kernel binder modules are not available:

```bash
# Try kernel modules first, fall back to user-space driver
sudo ruri -B /path/to/container

# With unshare mode
sudo ruri -u -B /path/to/container
```

## Testing

Standalone FUSE test:
```bash
gcc -o test_binder src/binder_driver.c $(pkg-config fuse3 --cflags --libs) -DSTANDALONE_TEST
./test_binder -f /tmp/binderfs &
ls -la /tmp/binderfs/
fusermount3 -u /tmp/binderfs
```

## Dependencies

- libfuse3-dev
- FUSE kernel module (standard on most Linux distributions)

## Limitations

This is a stub implementation that:
- Provides device presence for Android initialization
- Returns success for ioctl calls
- Does NOT implement actual IPC functionality
- Sufficient for basic redroid startup
- Apps requiring real binder IPC will need kernel modules

## Architecture

```
Android App
    ↓
/dev/binder (symlink)
    ↓
/dev/binderfs/binder (FUSE)
    ↓
binder_driver.c (userspace)
    ↓
Stub responses
```

## Future Work

- Complete IPC implementation using shared memory
- Performance optimizations
- Additional binder command support
- Better error handling and logging
- Ashmem emulation via FUSE

## References

- [Android Binder Documentation](https://source.android.com/devices/architecture/hidl/binder-ipc)
- [FUSE Documentation](https://www.kernel.org/doc/html/latest/filesystems/fuse.html)
- [Redroid Project](https://github.com/remote-android/redroid-doc)
