#!/usr/bin/env python3
'''
This is an Avatar script to analyze the SMS reception on Compal E88 phone
Execution is halted at 0x0008a892  cmhSMS_cpyMsgInd)

@author: Luca Bruno <lucab@debian.org>
'''

import os
import sys

from avatar.system import System
import logging
from avatar.emulators.s2e import init_s2e_emulator
import threading
import subprocess
from avatar.targets.gdbserver_target import *
from avatar.targets.openocd_target import *
from avatar.targets.openocd_jig import *
import time

log = logging.getLogger(__name__)

configuration = {
    "output_directory" : "/tmp/avatar_e88/",
    "configuration_directory" : os.getcwd(),
    "s2e" : {
        "s2e_binary" : "/home/lucab/build/build/qemu-debug/arm-s2e-softmmu/qemu-system-arm",
        "verbose" : True,
        "klee" : {
        "batch-time" : 1.0,
        "use-batching-search" : "true",
        "use-concolic-execution" : "true",
        "use-random-path" : "true",
        },
        "plugins": {
            "BaseInstructions": {},
            "Initializer": {},
            "FunctionMonitor": {},
            "InstructionPrinter": "",
            "MemoryInterceptorMediator": {
                "verbose": True,
                "interceptors": {
                    "RemoteMemory": {
                        "sram": {
                            "range_start": 0x00800000,
                            "range_end": 0xFFFFFFFF,
                            "priority": 0,
                            "access_type": ["read", "write", "execute", "io", "memory", "concrete_value", "concrete_address"]
                        }
                    }
                }
            },
            "RemoteMemory": {
                "verbose": True,
                "listen_address": "localhost:9999"
            },
            "RawMonitor" : 
                """
                kernelStart = 0,
                sms = {
                    delay      = false,      
                    name       = "sms",
                    start      = 0x0008A000,
                    size       = 0x10000,
                    nativebase = 0x0008A000,
                    kernelmode = false
                }
                """,
            "ModuleExecutionDetector" :
                """
                trackAllModules = true,
                configureAllModules = true,
                sms = {
                  moduleName = "sms",
                  kernelMode = true,
                }
                """,
            "Annotation" : 
                """
                sms_deliver = {
                  module  = "sms",
                  active  = true,
                  address = 0x8a892,
                  instructionAnnotation = "cmhSMS_cpyMsgInd",
                  beforeInstruction = true,
                  switchInstructionToSymbolic = true,

                }
                """
        },
    },
    "qemu_configuration": {
            "gdbserver": False,
            "halt_processor_on_startup": True,
            "trace_instructions": False,
            "trace_microops": False,
            "gdb": "tcp::1235,server,nowait",
            "append": ["-serial", "tcp::8888,server,nowait"]
        },
    "machine_configuration": {
            "architecture": "arm",
            "cpu_model": "arm926",
            "entry_address": 0x0,
            "memory_map": [
                {
                    "size": 0x2000,
                    "name": "rom_bootloader",
                    "file": "firmware/romloader_BOOT.90.04.bin",
                    "map": [{
                            "address": 0,
                            "type": "code",
                            "permissions": "rx"
                            }]
                },
                {
                    "size": 0x00200000,
                    "name": "flash_firmware",
                    "file": "firmware/motorola-e88_1.0.38.E.bin",
                    "map":  [{
                            "address": 0x2000,
                            "type": "code",
                            "permissions": "rx"
                            }]
                },
                {
                    "size": 0x00400000,
                    "name": "sram",
                    "map":  [{
                            "address": 0x00800000,
                            "type": "data",
                            "permissions": "rw"
                            }]
                }
            ],
        },
    "avatar_configuration": {
        "target_gdb_address": "tcp:localhost:3333",
        "target_gdb_path": "/usr/local/bin/arm-none-eabi-gdb"
    },
    "openocd_configuration": {
        "config_file": "compal_e88-openocd.cfg"
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

hwmon=OpenocdJig(configuration)

cmd = OpenocdTarget(hwmon.get_telnet_jigsock())
cmd.put_bp(0x0008a892)  # cmhSMS_cpyMsgInd
cmd.wait()              # block for bkpt trigger

configuration = cmd.initstate(configuration)
del cmd

ava = System(configuration, init_s2e_emulator, init_gdbserver_target)
ava.init()

ava.add_monitor(RWMonitor())

time.sleep(3)
ava.start()
ava.get_emulator().cont()
