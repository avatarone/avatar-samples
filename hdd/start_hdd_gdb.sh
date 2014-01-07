#!/bin/sh

MULTIPLEXER_SCRIPT=/home/zaddach/projects/hdd-svn/gdbstubs/run.py

if ! ps aux | grep "${MULTIPLEXER_SCRIPT}" | grep -v grep 2>/dev/null 1>/dev/null
then
    python "${MULTIPLEXER_SCRIPT}" /dev/ttyUSB1 /dev/ttyUSB0 1234 2010 2011 &
fi

sleep 5
echo "reset_bootmenu" | netcat -u -w 500 127.0.0.1 1234 | head -0
echo "boot_write_and_run_file 0x7000 /home/zaddach/projects/hdd-svn/gdbstubs2/experimental/build/gdbstub-ST3320413AS-0x7000.bin false" | netcat -u -w 500 127.0.0.1 1234 | head -0

while true
do
    socat UDP:localhost:2011 TCP-LISTEN:2011
    sleep 1
done
