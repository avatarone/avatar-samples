#!/bin/sh

echo "This script is optimized for the path layout of the Avatar vagrant machine."
echo "avatar is supposed to be located in ~/projects/avatar-python, S2E is supposed"
echo "to be in ~/projects/s2e-build, and gdb in ~/projects/gdb-build."

AVATAR_PATH="${HOME}/projects/avatar-python"
GDB_PATH="${HOME}/projects/gdb-build"
GDB="${HOME}/projects/gdb-build/gdb/gdb"
QEMU="${HOME}/projects/s2e-build/qemu-release/arm-softmmu/qemu-system-arm"
S2E="${HOME}/projects/s2e-build/qemu-release/arm-s2e-softmmu/qemu-system-arm"

PYTHONPATH=${AVATAR_PATH} QEMU=${QEMU} python3 full_forwarding_demo.py --gdb-path "${GDB_PATH}" --gdb "${GDB}" --s2e "${S2E}" $@
