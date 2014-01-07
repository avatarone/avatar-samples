#!/usr/bin/env python3
# Lucian Cojocar <cojocar@gmail.com>
# Avatar config file for PandaBoard (ES) and U-Boot, based on Aurélien Francillon's econotag config
# Mon Sep  9 09:39:21 CEST 2013
import argparse
import logging
import os

from collections import OrderedDict

from avatar.emulators.s2e import init_s2e_emulator
from avatar.system import System
from avatar.targets.gdbserver_target import *
from avatar.targets.openocd_jig import *
from avatar.targets.openocd_target import *

cwd = os.getcwd()
s2e_output = "/tmp/s2e_output/"
s2e_binary = os.path.join(cwd, "./../../../../s2e-build-release/qemu-release/arm-s2e-softmmu/qemu-system-arm")

configuration = {
        "output_directory" : s2e_output,
        "configuration_directory" : cwd,
        "s2e" : {
            "s2e-max-processes": 4,
            "verbose" : True,
            "s2e_binary" : s2e_binary,
            "klee" : {
                "use-batching-search" : True,
                "batch-time" : 1.0,
                #"dump-states-on-halt": True,
                #"simplify-sym-indices": False,
                #"fork-on-symbolic-address": False,
                #"verbose-state-switching": True,
                #"use-concolic-execution": True,
                },
            "plugins": OrderedDict([
                ("BaseInstructions", {}),
                ("MemoryInterceptorMediator", {
                    "verbose": False,
                    "interceptors": {
                        "RemoteMemory": {
                            "IOMem": {
                                "range_start": 0x4a000000,
                                "range_end": 0x4a000000+0x01000000,
                                "priority": 0,
                                "access_type": ["read", "write",
                                    "execute", "io", "memory",
                                    "concrete_value",
                                    "concrete_address"]
                                }
                            }
                        }
                    }),
                ("Initializer", {}),
                ("ExecutionTracer", "" ),
                ("FunctionMonitor", {}),
                ("RemoteMemory", {
                    "verbose": True,
                    "listen_address": "localhost:9999"
                    }),
                ("RawMonitor" , 
                    """
                kernelStart = 0,
                -- we consider RAM
                ram_module = {
                    delay      = false,      
                    name       = "ram_module",
                    start      = 0x80000000,
                    size       = 0x4000000,
                    nativebase = 0x80000000,
                    kernelmode = false
                },

                """),
                ("ModuleExecutionDetector" ,
                    """
                trackAllModules = true,
                configureAllModules = true,
                ram_module = {
                  moduleName = "ram_module",
                  kernelMode = true,
                },
                """),
                ]),
            "include" : ["lua/common.lua"],
            },
    "qemu_configuration": {
            "gdbserver": False,
            "halt_processor_on_startup": False,
            "trace_instructions": True,
            "append": ["-serial", "tcp::8888,server,nowait"]
            #"append": ["-serial", "file:/tmp/serial.out"]
            },
    "machine_configuration": {
        "architecture": "arm",
        "cpu_model": "arm926",
        "entry_address": 0x80000000,
        "memory_map": [
            {
                # 64 MB
                "size": 0x4000000,
                "name": "SRAM",
                # check readelf output
                # dd if=u-boot.bin of=u-boot.txt.bin bs=1 skip=0x8000
                "file": os.path.join(cwd, "files/u-boot.txt.bin"),
                "map":  [{
                    "address": 0x80000000,
                    "type": "code",
                    "permissions": "rwx"
                    }]
                },
            ],
        # XXX: this serial device is a hack
        # it is not located in the MMIO area, therefore the output
        # will be only in the S2E emulator
        "devices": [
            # the serial is emulated in qemu
            {
                "qemu_name": "pl011",
                "address": 0x101f1000,
                "bus":"sysbus",
                },
            # timers are emulated qemu
            {
                "qemu_name": "sp804",
                "address": 0x101e2000,
                "bus":"sysbus",
                },
            {
                "qemu_name": "sp804",
                "address": 0x101e3000,
                "bus":"sysbus",
                },
            ],
        },
    "avatar_configuration": {
            "target_gdb_address": "tcp:localhost:3333",
            "target_gdb_path":os.path.join(cwd,"files/toolchain", "arm-none-eabi-gdb")
            },
    "openocd_configuration": {
            "config_file": os.path.join(cwd, "panda_openocd.cfg")
            }
    }

def set_config(cfg, buggy):
    # 0x80007720 call of himport_r (the buggy function)
    cfg['s2e']['plugins']['Annotation'] = """
                        stop_state = {
                          module  = "ram_module",
                          active  = true,
                          --address = 0x80005590+0x03fb7000, -- getc()
                          --address = 0x80007758+0x03fb7000, -- exit from default env
                          address = 0x4+0x80007720+0x03fb7000, -- after himport_r call
                          instructionAnnotation = "end_state",
                          beforeInstruction = true,
                          switchInstructionToSymbolic = true,
                        },
                        mark_env_symbolic = {
                          module  = "ram_module",
                          active  = true,
                          --address = 0x800076b8+0x03fb7000, -- set_default_env()
                          --address = 0x80014f8c+0x03fb7000, -- himport_r()
                          address = 0x80007720+0x03fb7000, -- before himport_r call
                          instructionAnnotation = "make_env_symbolic_buggy",
                          beforeInstruction = true,
                          switchInstructionToSymbolic = true,
                        }
                    """
    cfg['machine_configuration']['memory_map'][0]['file'] = \
            os.path.join(cwd, "files/u-boot-buggy.txt.bin")
    if buggy is True:
        log.info("Using the buggy configuration")
        return
    log.info("Using the NON-buggy configuration")
    cfg['s2e']['plugins']['Annotation'] = """
                        stop_state = {
                          module  = "ram_module",
                          active  = true,
                          --address = 0x80005590+0x03fb7000, -- getc()
                          address = 0x4+0x80007720+0x03fb7000, -- after himport_r call
                          instructionAnnotation = "end_state",
                          beforeInstruction = true,
                          switchInstructionToSymbolic = true,
                        },
                        mark_env_symbolic = {
                          module  = "ram_module",
                          active  = true,
                          --address = 0x800076b8+0x03fb7000, -- set_default_env()
                          --address = 0x80014f8c+0x03fb7000, -- himport_r()
                          address = 0x80007720+0x03fb7000, -- before himport_r call
                          instructionAnnotation = "make_env_symbolic",
                          beforeInstruction = true,
                          switchInstructionToSymbolic = true,
                        }
                    """
    cfg['machine_configuration']['memory_map'][0]['file'] = \
            os.path.join(cwd, "files/u-boot.txt.bin")

__args = {}
def parse_args():
    parser = argparse.ArgumentParser(description='Avatar on the pandaboard.')
    parser.add_argument('-v', '--verbose', action='store_true', 
                        help='More log data ')
    parser.add_argument('-vv', '--veryverbose', action='store_true', 
                        help='Even more log data ')
    parser.add_argument('-b', '--buggy', action='store_true',
                        help='Run the buggy version')
    global __args, log
    __args = parser.parse_args()

    # config logger
    log = logging.getLogger("panda_avatar")
    log.setLevel(logging.WARNING)
    if __args.verbose:
        log.setLevel(logging.INFO)
    if __args.veryverbose:
        log.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    log.addHandler(ch)

if __name__ == "__main__":
    parse_args()
    set_config(configuration, __args.buggy)

    hwmon = OpenocdJig(configuration)
    log.debug("Openocd jig done")

    cmd = OpenocdTarget(hwmon.get_telnet_jigsock())
    log.debug("Openocd target done")

    log.info("Loading image on device...")

    # The image is on the SD card, nothing to load
    cmd.raw_cmd("halt")

    #cmd.initstate(configuration)
    # execute from the beginning
    log.info("AVATAR: loading avatar")
    ava = System(configuration, init_s2e_emulator, init_gdbserver_target)
    ava.init()

    # log.info("AVATAR: inserting monitor")
    # TODO
    # ava.add_monitor(RWMonitor()) #??

    log.info("AVATAR: starting avatar...")
    time.sleep(1)
    ava.start()

    log.info("done -- RESUMING!!")

    ava.get_emulator().cont()
