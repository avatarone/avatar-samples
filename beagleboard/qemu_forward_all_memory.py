'''
Created on Jun 26, 2013

@author: Jonas Zaddach <zaddach@eurecom.fr>
'''
from avatar.system import System
import logging
from avatar.emulators.s2e import init_s2e_emulator
import threading
import subprocess
import os
import time
import sys
from avatar.targets.avatarstub_target import init_avatarstub_target
from avatar.emulators.s2e.debug_s2e_emulator import init_debug_s2e_emulator
from avatar.targets.gdbserver_target import init_gdbserver_target

LINARO_QEMU_ARM = "LINARO_QEMU_ARM" in os.environ and os.environ["LINARO_QEMU_ARM"] or None
UBOOT_DIR = "UBOOT_DIR" in os.environ and os.environ["UBOOT_DIR"] or None

log = logging.getLogger(__name__)



configuration = {
    "output_directory": "/tmp/2/",
    "configuration_directory": os.getcwd(),
    "s2e": {
        "klee": {
        },
        "plugins": {
            "BaseInstructions": {},
            "Initializer": {},
            "MemoryInterceptor": """
                verbose = true
            """,
            "RemoteMemory": {
                "verbose": True,
                "listen_address": "localhost:3333",
                "ranges": {
                    "everything" : {
                        "address" : 0x00000000,
                        "size" : 0xFFFFFFFF,
                        "access" : ["read", "write", "execute"]
                    }
                }
            },
        }
    },
    "qemu_configuration": {
            "halt_processor_on_startup": True,
            "trace_instructions": True,
            "trace_microops": False,
            "gdb": "tcp::1235,server,nowait",
#            "append": ["-serial", "tcp::8888,server,nowait", "-nographic"]
#            "append": ["-serial", "tcp::8888,server,nowait", "-qmp", "tcp::1238,server,nowait"]
            "append": ["-serial", "tcp::8888,server,nowait"]
        },
    "machine_configuration": {
        "architecture": "arm",
        "cpu_model": "cortex-a8",
        "entry_address": 0x40014000, #Gotten by connecting with GDB to qemu-linaro stopped at first inst
        "memory_map": [
            { #Put a dummy memory that qemu is happy
                "size" : 0x20000, 
                "name" : "dummy",
                "map": [
                    {
                        "address" : 0,
                        "type": "code",
                        "permissions": "rwx",
                    }
                ]
            },
            { #Put a dummy memory that qemu is happy
                "size" : 0x2000000, 
                "name" : "qemu_maskrom",
                "map": [
                    {
                        "address" : 0x40014000,
                        "type": "code",
                        "permissions": "rwx",
                    }
                ]
            },
        ]
    },
    "avatar_configuration": {
        "target_gdb_address": "tcp:localhost:4444",
        "target_gdb_path": "arm-none-eabi-gdb"
    }
}

class TargetLauncher():
    def __init__(self, cmd):
        self._cmd = cmd
        self._process = None
        self._thread = threading.Thread(target = self.run)
        self._thread.start()
        
    def stop(self):
        if self._process:
            self._process.kill()
            
    def run(self):
        self._process = subprocess.call(self._cmd)
        
class RWMonitor():
    def emulator_pre_read_request(self, params):
        log.info("Emulator is requesting read 0x%08x[%d]", params["address"], params["size"])
     
    def emulator_post_read_request(self, params):
        log.info("Executed read 0x%08x[%d] = 0x%x", params["address"], params["size"], params["value"])
    
    def emulator_pre_write_request(self, params):
        log.info("Emulator is requesting write 0x%08x[%d] = 0x%x", params["address"], params["size"], params["value"])
        pass
    
    def emulator_post_write_request(self, params):
        log.info("Executed write 0x%08x[%d] = 0x%x", params["address"], params["size"], params["value"])
        pass
    
    def stop(self):
        pass
        
def main(args):
    #TODO: Build stuff here (u-boot)
    ava = System(configuration, init_s2e_emulator, init_gdbserver_target)
    print("System generated")
    target_runner = TargetLauncher([LINARO_QEMU_ARM, 
                    "-M",  "beagle", 
                    "-m", "256M", 
                    "-serial", "udp:127.0.0.1:2000",
                    "-sd", os.path.join(UBOOT_DIR, "sdcard.img"),
                    "-gdb", "tcp:127.0.0.1:4444",
                    "-S"])
    ava.init()
    ava.add_monitor(RWMonitor())
    time.sleep(3)
    ava.start()
    
    ava.get_emulator().cont()
    
if __name__ == "__main__":
    main(sys.argv)