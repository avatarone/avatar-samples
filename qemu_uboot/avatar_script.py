#!/usr/bin/env python

from avatar.system import System

system = System()
#Loads the configuration for all modules from the old JSON format
system.load_configuration("config.json", "/tmp/1")

#Starts S2E, any service neccessary for connecting to the target as specified in the configuration
system.start()

#Now the firmware should be loaded into S2E, and the memory be connected to the embedded device
#S2E should have broken at the first instruction


#You can actually send GDB commands to the emulator or the target
# NOT TRUE YET

