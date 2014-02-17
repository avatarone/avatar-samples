#!/bin/sh

# Copy this file to another name (e.g., my_qemu_forward_all_memory.sh) and change the paths below
# to the right paths on your system.

export PYTHONPATH=<Put path to avatar-python here>
export LINARO_QEMU_ARM=<Put path to qemu-system-arm binary from linaro-qemu here>
export UBOOT_DIR=<Put path to u-boot directory here. The program expects an SD-Card image named sdcard.img inside>
export QEMU_S2E=<Path to qemu-system-arm binary>

python3.2 qemu_forward_all_memory.py
