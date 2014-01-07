#!/usr/bin/env python3

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
from avatar.interfaces.gdb.gdb_server import GdbServer

import argparse


from collections import OrderedDict

log = logging.getLogger(__name__)


buggy=False

configuration = {
    "output_directory" : os.getcwd()+"/s2e_output/",
    "configuration_directory" : os.getcwd(),
    "s2e" : {
        #"s2e-max-processes": 4,
        "verbose" : True,
        "s2e_binary" : os.getcwd()+"/../../../../s2e-build/qemu-release/arm-s2e-softmmu/qemu-system-arm",
        "klee" : {
            "use-batching-search" : True,       
            "batch-time" : 1.0,
        },
        "plugins": OrderedDict([
            ("BaseInstructions", {}),
            #("InstructionPrinter", ""),
            ("Initializer", {}),
            ("ExecutionTracer", "" ),
            ("ArbitraryExecChecker", ""),  # checking for obvious bugs 
            ("TestCaseGenerator", "" ),
            ("FunctionMonitor", {}),
            ("MemoryInterceptorMediator", {
                "verbose": True,
                "interceptors": {
                    "RemoteMemory": {
                        "IOMem": {
                            "range_start": 0x80000000,
                            "range_end": 0x80030000,
                            "priority": 0,
                            "access_type": ["read", "write", "execute", "io", "memory", "concrete_value", "concrete_address"]
                        }
                    }
                    #, "RemoteMemory": {
                    #     "sram_data": {
                    #         #"range_start": 0x400000,
                    #         "range_start": 0x4031DA,
                    #         "range_end": 0x418000,
                    #         "priority": 0,
                    #         "access_type": ["read", "write", "execute", "io", "memory", "concrete_value", "concrete_address"]
                    #     }
                    # }
                }
            }),
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
                    start      = 0x400000,
                    size       = 0x018000,
                    nativebase = 0x400000,
                    kernelmode = false
                },
                rom_module = {
                    delay      = false,      
                    name       = "rom_module",
                    start      = 0x0,
                    size       = 0x3FFFFF,
                    nativebase = 0x0,
                    kernelmode = false
                }
                
                """),
            ("ModuleExecutionDetector" ,
                """
                trackAllModules = true,
                configureAllModules = true,
                ram_module = {
                  moduleName = "ram_module",
                  kernelMode = true,
                },
                rom_module = {
                  moduleName = "rom_module",
                  kernelMode = true,
                }
                """),
            ("Annotation" , 
                """
               reset_fun = {
                   module  = "rom_module",
                   active  = true,
                   address = 0x0,
                   instructionAnnotation = "reset",
                },
                undef_fun = {
                   module  = "rom_module",
                   active  = true,
                   address = 0x4,
                   instructionAnnotation = "undef_instr",
                },
                symbolic_pkt = {
                  module  = "ram_module",
                  active  = true,
                  address = 0x40219E,   
                  instructionAnnotation = "make_pkt_symbolic",
                  beforeInstruction = true,
                  switchInstructionToSymbolic = true,
                },
                stop_state = {
                  module  = "ram_module",
                  active  = true,
                  address = 0x401E6C,-- after the return of the function  
                  instructionAnnotation = "end_analysis_region",
                  beforeInstruction = true,
                  switchInstructionToSymbolic = true,
                }

                """),
        ]),
        "include" : ["lua/test.lua", "lua/common.lua"]
    },
    "qemu_configuration": {
            "gdbserver": False,
            "halt_processor_on_startup": True,
            "trace_instructions": True,
            #"trace_microops": True,
            # "gdb": "tcp::1235,server,nowait", # not used anymore 
            "append": ["-serial", "tcp::8888,server,nowait"]
        },
    "machine_configuration": {
            "architecture": "arm",
            "cpu_model": "arm926",
            "entry_address": 0x0,
            "memory_map": [
                {
                    "size": 0x14000,
                    "name": "rom",
                    "file": os.getcwd()+"/econotag_src/ROMDump/mc1322x_rom_0_0x14000.bin",
                    "map": [{
                            "address": 0,
                            "type": "code",
                            "permissions": "rx"
                            }]
                },
                {
                    # 96K bytes
                    "size": 0x18000,
                    #"size" : 0x31DA, # only import the txt section, ro data and data not needed here as we forward them
                    "name": "SRAM",
                    "file": os.getcwd()+"/econotag_src/with freescale tools/My UART/Wireless UART/Debug/Exe/Wireless UART.bin_txt_only.bin",
                    "map":  [{
                            "address": 0x400000,
                            "type": "code",
                            "permissions": "rwx"
                            }]
                },
            ],
        },
    "avatar_configuration": {
        "target_gdb_address": "tcp:localhost:3333",
        "target_gdb_path":"/opt/arm-none-eabi-sourcery-2012.09-63/bin/arm-none-eabi-gdb"
    },
    "openocd_configuration": {
        "config_file": "econotag_openocd.cfg"
    }
}

if buggy:
# that's for the buggy version 

    configuration["machine_configuration"]["memory_map"]=[{
                        "size": 0x14000,
                        "name": "rom",
                        "file": "/home/aurel/work/sensors/econotag/ROMDump/mc1322x_rom_0_0x14000.bin",
                        "map": [{
                                "address": 0,
                                "type": "code",
                                "permissions": "rx"
                                }]
                    },
                    {
                        # 96K bytes
                        "size": 0x18000,
                        #"size" : 0x31DA, # only import the txt section, ro data and data not needed here as we forward them
                        "name": "SRAM",
                        "file": "/home/aurel/work/sensors/econotag/with freescale tools/My buggyUart/Wireless UART/Debug/Exe/Wireless UART.bin_cut_12808",
                        "map":  [{
                                "address": 0x400000,
                                "type": "code",
                                "permissions": "rwx"
                                }]
                    }]

    configuration["s2e"]["plugins"]["Annotation"]="""
                   reset_fun = {
                       module  = "rom_module",
                       active  = true,
                       address = 0x0,
                       beforeInstruction = true,
                       instructionAnnotation = "reset",
                    },
                    undef_fun = {
                       module  = "rom_module",
                       active  = true,
                       address = 0x4,
                       beforeInstruction = true,
                       instructionAnnotation = "undef_instr",
                    },
                    symbolic_pkt = {
                      module  = "ram_module",
                      active  = true,
                      address = 0x004021a6, --  <= where we  put the annotation, has to be begining of a tcb but not hte 1st one 
                      instructionAnnotation = "make_pkt_symbolic",
                      beforeInstruction = true,
                      switchInstructionToSymbolic = true,
                    },
                    stop_state = {
                      module  = "ram_module",
                      active  = true,
                      address = 0x401E6C, -- lets now stop after the return so that we actually notice a stack based buffer overflow 
--0x40224C, --0x402220, -- <= stop analysis at the end of the function
                      instructionAnnotation = "end_analysis_region",
                      beforeInstruction = true,
                      switchInstructionToSymbolic = true,
                    },
                    skip_uart = {
                        module = "ram_module",
                        active = false,
                        address = "0x40278E",
                        callAnnotation = "skip_uart",
                        beforeInstruction = true,
                        switchInstructionToSymbolic =true,
                        paramcount = 0
               }
    """
    configuration["s2e"]["include"]=["lua/test_buggy.lua", "lua/common.lua"]

    print("\n\n")
    print("%s",configuration)
    print("\n\n")

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
        #log.info("Emulator at PC=%s is requesting read 0x%08x[%d]", params['cpu_state']['pc'],  params["address"], params["size"])
        pass

    def emulator_post_read_request(self, params):
        log.info("Executed at PC=%s read 0x%08x[%d] = 0x%x", params['cpu_state']['pc'], params["address"], params["size"], params["value"])
    
    def emulator_pre_write_request(self, params):
        #log.info("Emulator at PC=%s is requesting write 0x%08x[%d] = 0x%x", params['cpu_state']['pc'], params["address"], params["size"], params["value"])
        pass
    
    def emulator_post_write_request(self, params):
        log.info("Executed at PC=%s write 0x%08x[%d] = 0x%x", params['cpu_state']['pc'], params["address"], params["size"], params["value"])
        pass
    
    def stop(self):
        pass


def transfer_cpu_state_to_emulator(ava, debug=False, verbose=False):
    """  
    Transfers state from emulator to device, 
    Parameter:  avatar object
    Parameter: Debug:  stores state to a file
    Parameter: verbose : prints transfered state 
    """

    cpu_state = {}
    for reg in ["r0", "r1", "r2", "r3", 
                "r4", "r5", "r6", "r7", 
                "r8", "r9", "r10", "r11", 
                "r12", "sp", "lr", "pc", "cpsr"]:
        value = ava.get_emulator().get_register(reg)
        cpu_state[reg] = hex(value)
        ava.get_target().set_register(reg, ava.get_emulator().get_register(reg))

    if debug:
        f = open("cpu_state.gdb", "w")
        for (reg, val) in cpu_state.items():
            f.write("set $%s = %s\n" % (reg, val))
        f.close()
    if vebose:
        print("transfered CPU state to device: %s" % cpu_state.__str__())




def transfer_cpu_state_to_device(ava, debug=False, verbose=False):
    """    
    Transfers state from emulator to device, 
    Parameter: avatar object
    Parameter: Debug:  stores state to a file
    Parameter: verbose : prints transfered state    
    """

    cpu_state = {}
    for reg in ["r0", "r1", "r2", "r3", 
                "r4", "r5", "r6", "r7", 
                "r8", "r9", "r10", "r11", 
                "r12", "sp", "lr", "pc", "cpsr"]:
        value = ava.get_emulator().get_register(reg)
        cpu_state[reg] = hex(value)
        ava.get_target().set_register(reg, ava.get_emulator().get_register(reg))
    if debug:
        f = open("cpu_state.gdb", "w")
        for (reg, val) in cpu_state.items():
            f.write("set $%s = %s\n" % (reg, val))
        f.close()
    if vebose:
        print("transfered CPU state to device: %s" % cpu_state.__str__())


def transfer_mem_to_target(ava, addr, length):
    """
    copies memory region to target
    """
    memory = ava.get_emulator().read_untyped_memory(addr, length)
    # is this file needed ? 
    f = open("/tmp/ava_memory", "wb")
    f.write(memory)
    f.close()
    ava.get_target().write_untyped_memory(addr, memory)

def transfer_mem_to_emulator(ava, addr, length):
    """
    copies memory region to target
    """
    memory = ava.get_target().read_untyped_memory(addr, length)
    # is this file needed ? 
    f = open("/tmp/ava_memory", "wb")
    f.write(memory)
    f.close()
    ava.get_emulator().write_untyped_memory(addr, memory)



# s_fw_start = 0x400000
# s_Main = 0x401E4C
# s_process_radio_msg = 0x400A84

# # function that recieves messages
# s_data_indication_execute = 0x402120
#s_in_data_indication_execute = 0x40219E #  <= this is where we put the annotation
if buggy:
    s_in_data_indication_execute = 0x40217A
    dataRamFrom=0x403206
    dataRamToTransf=0x404840-dataRamFrom
    s_UART_TX=0x402240 # buggy firmware


else:
    s_in_data_indication_execute = 0x402174 #  <= this is where we put the annotation
    dataRamFrom=0x4031DA
    dataRamToTransf=0x404810-dataRamFrom
    s_UART_TX=0x402214 # valid firmware


# function that sends messages 
# s_wireless_uart_execute = 401E72 
# s_in_wireless_uart_execute = 0x401fb6
    
# break at address :
# data_indication_execute 0x402120

# display RX_msg
# /c  (char [33]) *RX_msg.pu8Buffer->u8Data
# data_rx 
# pu buffer  {
# smac_pdu_tag {
#  uint8_t  reserved[2];
#  uint8_t  u8Data[1];
#} smac_pdu_t;
# uint8_t buff[31]

#RX_msg.pu8Buffer->u8Data
# packet buffer : 
# 0x4033aa len 33


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Avatar on the econotag.')
    parser.add_argument('-v', '--verbose', action='store_true', 
                        help='More log data ')
    parser.add_argument('-vv', '--veryverbose', action='store_true', 
                        help='Even more log data ')
    parser.add_argument('-d', '--debug', action='store_true', 
                        help='When done, start a gdb stub on the emulator ')
    parser.add_argument('-r', '--reset', action='store_true', 
                        help='Once attached reset and load firmware image with jtag (not confirmed to work)')
    parser.add_argument('-g', '--gdb_verbose', action='store_true', 
                        help='Show details of gdb protocol messages')
    args = parser.parse_args()

    if args.verbose: 
        log.info("OpenOcd jig");
    hwmon=OpenocdJig(configuration)

    if args.verbose: 
        log.info("OpenOcd target");
    cmd = OpenocdTarget(hwmon.get_telnet_jigsock())


    # reset and load the software
    if args.reset:
        if args.verbose: 
            log.info("AVATAR: resetting the target and loading image");
            
        cmd.raw_cmd("load_image /home/aurel/work/sensors/econotag/with\ freescale\ tools/My\ UART/Wireless\ UART/Debug/Exe/Wireless\ UART.bin 0x00400000 bin", True)
        cmd.put_bp(s_Main) # run until Main
        cmd.wait()
        cmd.remove_bp(s_Main)

    else: # attach to a running target    
        cmd.put_bp(s_in_data_indication_execute)
        log.info("Waiting for a packet to be proceesed")
        cmd.wait()        # block for bp trigger
        # Bp was hit, remove it to avoid lockup  
        cmd.remove_raw_bp(s_in_data_indication_execute) 

    if args.verbose: 
        log.info("AVATAR: fetching configuration from target");
    
    configuration = cmd.initstate(configuration)
    del cmd
    if args.veryverbose:
        print("configuraton is : %s" % configuration)

    if args.verbose: 
        log.info("AVATAR: loading avatar ");
    ava = System(configuration, init_s2e_emulator, init_gdbserver_target)
    ava.init()

    if args.verbose: 
        log.info("AVATAR: inserting monitor");
    ava.add_monitor(RWMonitor())

    if args.verbose: 
        log.info("AVATAR: starting avatar ");
    time.sleep(1)
    ava.start()

    if args.verbose: 
        log.info("AVATAR: avatar Started ");

    log.info("transfering data section + stack from device to emulator %d Kb form %x", dataRamToTransf/1024, dataRamFrom)
    transfer_mem_to_emulator(ava,dataRamFrom,dataRamToTransf)

    # Kill calls to UART
    #ava.get_emulator().write_typed_memory(s_UART_TX,2,0x46C0)
    #ava.get_emulator().write_typed_memory(s_UART_TX,2,0x46C0)



    if args.debug:
        log.info("Launching GDB server to emulator on 127.0.0.1:5555, attach with ")
        log.info("target remote 127.0.0.1:5555")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 5555))
        sock.listen(1)                
        (s, _) = sock.accept()
        gdb = GdbServer(ava.get_emulator(), s, ava, verbose=args.gdb_verbose)
        log.info("GDB connected")
    else:
        ava.get_emulator().cont()
        # wait for termination 
