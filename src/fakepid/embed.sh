#!/bin/sh
# Script to convert libfakepid.so to embedded C header

if [ ! -f "libfakepid.so" ]; then
    echo "Error: libfakepid.so not found"
    exit 1
fi

cat > libfakepid_embedded.h << 'EOF'
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

// Embedded libfakepid.so binary data
// This file is auto-generated from libfakepid.so

#ifndef LIBFAKEPID_EMBEDDED_H
#define LIBFAKEPID_EMBEDDED_H

#include <stddef.h>

EOF

# Get file size (portable way)
SIZE=$(wc -c < libfakepid.so | tr -d ' ')

echo "static const size_t libfakepid_so_len = ${SIZE};" >> libfakepid_embedded.h
echo "static const unsigned char libfakepid_so_data[] = {" >> libfakepid_embedded.h

# Convert binary to hex array
xxd -i < libfakepid.so | sed 's/^/  /' >> libfakepid_embedded.h

echo "};" >> libfakepid_embedded.h
echo "" >> libfakepid_embedded.h
echo "#endif // LIBFAKEPID_EMBEDDED_H" >> libfakepid_embedded.h

echo "Generated libfakepid_embedded.h (${SIZE} bytes)"
