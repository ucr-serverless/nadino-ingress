#!/usr/bin/env python3
import sys

MAKEFILE = "objs/Makefile"  # change if needed

OLD = """objs/src/core/pdi_rdma.o:\t$(CORE_DEPS) \\
\tsrc/core/pdi_rdma.c
\t$(CC) -c $(CFLAGS) $(CORE_INCS) \\
\t\t-o objs/src/core/pdi_rdma.o \\
\t\tsrc/core/pdi_rdma.c"""

NEW = """objs/src/core/pdi_rdma.o:\t$(CORE_DEPS) $(HTTP_DEPS) \\
\tsrc/core/pdi_rdma.c
\t$(CC) -c $(CFLAGS) $(CORE_INCS) $(HTTP_INCS) \\
\t\t-o objs/src/core/pdi_rdma.o \\
\t\tsrc/core/pdi_rdma.c"""

with open(MAKEFILE, 'r') as f:
    content = f.read()

if OLD not in content:
    print("ERROR: pattern not found in Makefile", file=sys.stderr)
    sys.exit(1)

new_content = content.replace(OLD, NEW, 1)

with open(MAKEFILE, 'w') as f:
    f.write(new_content)

print("Done.")
