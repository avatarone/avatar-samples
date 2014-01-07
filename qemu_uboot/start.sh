#!/bin/sh

AVATAR_SCRIPT="../../run.py"
QEMU_EXECUTABLE="qemu-system-arm"
PYTHON_LIB_PATH="../../../pylib"


${QEMU_EXECUTABLE} -M versatilepb -m 20M -serial udp:127.0.0.1:2000 -kernel ../../example_binaries/qemu_versatilepb/u-boot -gdb tcp:127.0.0.1:1234 -S &
PYTHONPATH=${PYTHON_LIB_PATH} python ${AVATAR_SCRIPT} config.json "$1"



