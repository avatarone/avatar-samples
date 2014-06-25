Description of the reverse engineering of the Seagate ST3320413AS HDD with Avatar:

- Discover the ROM bootloader menu and its RD, WR and GO commands
- Reverse engineer the serial port hardware functionality
- Write a GDB stub for the platform that can be executed from the ROM bootloader
- Inject the GDB stub and make Avatar speak with it
- Configure Avatar to forward all memory accesses except those to the ROM memory range to the HDD 
- Fix a polling loop in the ROM code that checks if the UART is currently busy - this does not work on 
  QEMU, since the emulator is too fast and the UART never will appear busy
  -> Write 0x46c0 (nop) to address 0x100852 to skip this polling loop
- See from memory map that region 0x04000400 - 0x0400c200 seems to be stack .. -> make not-forwarded

=== Installation ===
All installation assumes that the avatar-pandora repository has been checked out to ${HOME}/projects/avatar-pandora.

== Install required packages ==
```sudo apt-get-get install texinfo libexpat1-dev python2.7-dev liblua5.1-0-dev libsigc++-dev libsigc++-2.0-dev
sudo usermod -a -G dialout ${USER}```

== Install pyusb ==
```cd ${HOME}/projects/incubator
   git clone git@github.com:walac/pyusb.git
   cd pyusb
   sudo python setup.py install
   sudo python3 setup.py install
   sudo bash -c "echo 'SUBSYSTEMS==\"usb\", ATTRS{idVendor}==\"152d\", ATTRS{idProduct}==\"2338\", GROUP=\"plugdev\", MODE=\"660\"' > /etc/udev/rules.d/99-libusb.rules"```

== Prepare the HDD ==
- Disable BGMS background activity: Serial menu, /TF1E4,0

== Build S2E ==
```mkdir s2e-build && cd s2e-build
make -f ../s2e/Makefile```

== Build GDB ==
```cd gdb-arm
./configure --with-python --with-expat=yes --target=arm-none-eabi*
make```

== Install arm-none-eabi-gcc compiler ==
```cd /tmp
wget https://sourcery.mentor.com/GNUToolchain/package12774/public/arm-none-eabi/arm-2014.05-28-arm-none-eabi-i686-pc-linux-gnu.tar.bz2
cd /opt
tar xvf /tmp/arm-2014.05-28-arm-none-eabi-i686-pc-linux-gnu.tar.bz2
export PATH=$PATH:/opt/arm-2014.05/bin```

== Build GDB stub ==
```mkdir avatar-gdbstub-build && cd avatar-gdbstub-build
cmake -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=MinSizeRel ${HOME}/projects/avatar-pandora/avatar-gdbstub
make```

== Pitfalls ==
- If Avatar starts successfully, but gets stuck early during bootloader execution with a memory error,
  most probably the gdb stub was not compiled with Os. Use ```cmake -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=MinSizeRel ${REPO_PATH}```
  to compile the GDB stub for the HDD, as otherwise it will wrap in memory and overwrite code.
