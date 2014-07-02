from avatar.system import System
import logging
from avatar.emulators.s2e import init_s2e_emulator
import threading
import subprocess
from avatar.targets.gdbserver_target import init_gdbserver_target
import os
import time

log = logging.getLogger(__name__)



configuration = {
    "output_directory": "/tmp/1",
    "configuration_directory": os.getcwd(),
    "s2e": {
        "klee": {
        },
        "plugins": {
            "BaseInstructions": {},
            "Initializer": {},
            "MemoryInterceptor": "",
            "RemoteMemory": {
                "verbose": True,
                "listen_address": "localhost:3333",
                "ranges":  {
                    "sram_code": {
                        "address": 32768,
                        "size": 1048575,
                        "access": ["read", "write", "execute", "io", "memory", "concrete_value", "concrete_address"]
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
            "append": ["-serial", "tcp::8888,server,nowait"]
        },
    "machine_configuration": {
            "architecture": "arm",
            "cpu_model": "arm926",
            "entry_address": 0x1000000,
            "memory_map": [
                {
                "size": 0x1000,
                "name": "interrupts",
                "map": [
                    {"address": 0,
                     "type": "code",
                     "permissions": "rwx"}
                ]
            },
            {
                "size": 0x19000,
                "name": "text_data_bss",
                "file": "u-boot.bin",
                "map": [{
                    "address": 0x1000000,
                    "type": "code",
                    "permissions": "rwx"}]
            }
                                    ],
                                    "devices": [
                                        {
                                            "type": "serial",
                                            "name": "uart16550",
                                            "qemu_name": "sysbus-serial",
                                            "address": 0x101f1000,
                                            "bus": "sysbus"
                                        }
                                    ]
                                },
    "avatar_configuration": {
        "target_gdb_address": "tcp:localhost:1234"
    }
}

class TargetLauncher(object):
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
        

class DumbTarget():
    def start(self):
        pass
    
def init_emulator(system):
    log.info("init_emulator called")
    
def init_target(system):
    system.set_target(DumbTarget())
    log.info("init_target called")
    
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

ava = System(configuration, init_s2e_emulator, init_gdbserver_target)
ava.init()
target_runner = TargetLauncher(["qemu-system-arm", 
                                "-M",  "versatilepb", 
                                "-m", "20M", 
                                "-serial", "udp:127.0.0.1:2000",
                                "-kernel", "u-boot",
                                "-gdb", "tcp:127.0.0.1:1234",
                                "-S"])
ava.add_monitor(RWMonitor())

time.sleep(3)
ava.start()
ava.get_emulator().cont()
