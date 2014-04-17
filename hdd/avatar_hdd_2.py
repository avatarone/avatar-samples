'''
Created on April 9, 2014

@author: Jonas Zaddach <zaddach@eurecom.fr>

This script serves to extract traces from the HDD while it is running the bootloader,
or while it receives SATA packets.
'''

DESCRIPTION = "This is an AVATAR driver script for the Seagate ST3320413AS HDD. Its purpose is to record " + \
    "traces of interactions with the bootloader, and when the HDD receives SATA packets"
    
from avatar.system import System
import logging
from avatar.emulators.s2e import init_s2e_emulator
import threading
import subprocess
import os
import time
import sys
import argparse
import serial
from avatar.targets.avatarstub_target import init_avatarstub_target
from avatar.emulators.s2e.debug_s2e_emulator import init_debug_s2e_emulator
from avatar.targets.gdbserver_target import init_gdbserver_target
from collections import OrderedDict


from Seagate_ST3320413AS_flasher import ResetController, StubDownloader

log = logging.getLogger(__name__)



configuration = {
    "output_directory": "/tmp/2",
    "configuration_directory": os.getcwd(),
    "s2e": {
        "s2e_binary": "QEMU_S2E" in os.environ and os.environ["QEMU_S2E"] or os.path.expanduser("~/projects/avatar-pandora/s2e-build/qemu-release/arm-s2e-softmmu/qemu-system-arm"),
        "emulator_gdb_path":"../../gdb-arm/gdb/gdb",
        "klee": {
        },
        "plugins": OrderedDict([
            ("BaseInstructions", {}),
            ("Initializer", {}),
            ("MemoryInterceptor", ""),
            ("RemoteMemory", {
                "verbose": True,
                "listen_address": "localhost:3333",
                "ranges": {
                    "sram_code": {
                        "address": 0x8000, 
                        "size": 0x100000 - 0x8000,
                        "access": ["read", "write", "execute"]
                    },
                    "dram": {
                        "address": 0x120000, 
                        "size": 0x4000000 - 0x120000,
                        "access": ["read", "write", "execute"]
                    },
                    "after_stack_before_uart": {
                        "address": 0x4010000, 
                        "size": 0x400d3000 - 0x4010000,
                        "access": ["read", "write", "execute"]
                    },
                    "io_after_uart": {
                        "address": 0x400d4000, 
                        "size": 0x100000000 - 0x400d4000,
                        "access": ["read", "write", "execute"]
                    }
                }
            }),
       ]) 
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
            "endianness": "little",
            "cpu_model": "arm926",
            "entry_address": 0x100000,
            "memory_map": [
                {
                "size": 0x8000,
                "name": "sram_code",
                "map": [
                    {
                        "address": 0,
                        "type": "code",
                        "permissions": "rwx"
                    }
                ]
            },
            {
                "size": 0x20000,
                "name": "rom_bootloader",
                "file": "hdd_rom.bin",
                "is_rom": True,
                "map": [
                    {
                        "address": 0x100000,
                        "type": "code",
                        "permissions": "rx"
                    }
                ]
            },
            {
                "size": 0x200000,
                "name": "dram_code",
                "map": [
                    {
                        "address": 0x200000,
                        "type": "code",
                        "permissions": "rx"
                    },
                    {
                        "address": 0x6000000,
                        "type": "data", 
                        "permissions": "rw"
                    }]
            },
            {
                "size": 0x10000,
                "name": "sram_data",
                "map": [
                    {
                        "address": 0x4000000,
                        "type": "data",
                        "permissions": "rw"
                    }
                ]
            },
            {
                "size": 0xe00000,
                "name": "dram_data",
                "map": [
                    {
                        "address": 0x6200000,
                        "type": "data",
                        "permissions": "rw"
                    }
                ]
            }
                                    ],
                                    "devices": [
                                        {
                                            "type": "serial",
                                            "name": "uart16550",
                                            "qemu_name": "sysbus-serial",
                                            "address": 0x400d3000,
                                            "bus": "sysbus"
                                        }
                                    ]
                                },
    "avatar_configuration": {
        "target_gdb_path":"../../gdb-arm/gdb/gdb"
    }
}

class TargetLauncher(threading.Thread):
    def __init__(self, gdbstub_file, load_address, entry_point, reset_controller_script, serial_port, serve_port):
        super(TargetLauncher, self).__init__()
        self._load_address = load_address
        self._entry_point = entry_point
        self._serve_port = serve_port
        self._gdbstub_file = gdbstub_file
        self._reset_controller_script = reset_controller_script
        self._serial = serial_port
        self._event = threading.Event()
            
    def run(self):
        while not self._event.is_set():
            stub_downloader = None
            try:
                stub_downloader = StubDownloader(ResetController(self._reset_controller_script), self._serial)
                log.info("[TargetLauncher] Opened serial connection to the HDD, now downloading GDB stub")
                stub_downloader.load_stub(self._gdbstub_file, self._load_address, self._entry_point)
                log.info("[TargetLauncher] Stub download finished, waiting for TCP connection")
                self._event.set()
            except serial.serialutil.SerialException as ex:
                if not str(ex).startswith("write failed: [Errno 5]"):
                    raise ex
                if not stub_downloader is None:
                    del stub_downloader
        stub_downloader.serve_serial_port(self._serve_port)
        log.error("[TargetLauncher] Client disconnected, shutting down")
        
    def wait(self):
        while not self._event.is_set():
            time.sleep(1)


def parse_arguments():
    parser = argparse.ArgumentParser(description = DESCRIPTION)
    parser.add_argument("-v", "--verbose", action = "count", default = 0, dest = "verbosity",
        help = "Increase verbosity (Can be specified several times to increase more)")
    parser.add_argument("--power-control", type = str, metavar = "FILE", dest = "power_control",
        default = os.path.expanduser("~/projects/avatar-pandora/avatar-samples/hdd/on_off.sh"),
        help = "Executable that can switch the HDD on and off (\"on\" or \"off\" is passed as first argument)")
    parser.add_argument("--serial", type = str, metavar = "FILE", dest = "serial", default = "/dev/ttyUSB0",
        help = "Serial port to which the HDD is connected")
    parser.add_argument("--gdbstub", type = str, metavar = "FILE", dest = "gdbstub",
        default = os.path.expanduser("~/projects/avatar-pandora/avatar-gdbstub-build/cmake/"),
        help = "GDB stub that is injected in the HDD")
    parser.add_argument("--gdbstub-loadaddress", type = int, dest = "gdbstub_loadaddress", default = 0x7000,
        help = "Load address of GDB stub")
    parser.add_argument("-o", "--output", type = str, metavar = "DIRECTORY", dest = "output_directory",
        default = "/tmp/avatar-output",
        help = "Directory where resulting configuration and log files will be stored")
    parser.add_argument("--hdd-port", type = int, default = 2000, dest = "hdd_port",
        help = "Port where HDD flasher is listening")
        
    return parser.parse_args()
        
def set_verbosity(verbosity):
    if verbosity >= 3:
        logging.basicConfig(level = logging.DEBUG)
    elif verbosity >= 2:
        logging.basicConfig(level = logging.INFO)
    elif verbosity >= 1:
        logging.basicConfig(level = logging.WARN)
    else:
        logging.basicConfig(level = logging.ERROR)
        
def main():
    args = parse_arguments()
    set_verbosity(args.verbosity)
    
    configuration["output_directory"] = args.output_directory
    flasher_port = args.hdd_port #TODO: If flasher_port is None, assign a port
    configuration["avatar_configuration"]["target_gdb_address"] = "tcp:127.0.0.1:%d" % flasher_port
    
    
    #Start target
    hdd_launcher = TargetLauncher(args.gdbstub, 
                                  args.gdbstub_loadaddress, 
                                  args.gdbstub_loadaddress, 
                                  args.power_control,
                                  args.serial,
                                  flasher_port)
    hdd_launcher.start()
    hdd_launcher.wait()

    log.info("HDD gdb stub installed and running")

    ava = System(configuration, init_s2e_emulator, init_gdbserver_target)
    ava.init()
    ava.start()
    
    print("Target is started!")
    
    

if __name__ == "__main__":
    main()
    

# ava = System(configuration, init_s2e_emulator, init_avatarstub_target)
# #ava = System(configuration, init_s2e_emulator, init_gdbserver_target)
# ava.init()
# # target_runner = TargetLauncher(["qemu-system-arm", 
# #                                 "-M",  "versatilepb", 
# #                                 "-m", "20M", 
# #                                 "-serial", "udp:127.0.0.1:2000",
# #                                 "-kernel", "/home/zaddach/projects/eurecom-s2e/avatar/avatar/example_binaries/qemu_versatilepb/u-boot",
# #                                 "-gdb", "tcp:127.0.0.1:1234",
# #                                 "-S"])
# #TODO: Start target here
# ava.add_monitor(RWMonitor())
# 
# time.sleep(3)
# ava.start()
# 
# print("blablabla")
# bkpt_load_from_flash_rom = ava.get_emulator().set_breakpoint(0x100aae)
# def load_from_flash_handler(system, bkpt):
#     ram_addr = system.get_emulator().get_register("r1")
#     flash_addr = system.get_emulator().get_register("r2")
#     len_in_words = system.get_emulator().get_register("r3")
#     return_address = system.get_emulator().get_register("lr")
#     log.info("Loading 0x%x bytes from flash address 0x%x to ram address 0x%x", len_in_words * 4, flash_addr, ram_addr)
#     if len_in_words > 0:
#         f = open(os.path.join(os.getcwd(), "JC49_flash.raw"), "rb")
#         f.seek(flash_addr)
#         system.get_emulator().write_untyped_memory(ram_addr, f.read(len_in_words * 4))
#  
#     system.get_emulator().set_register("pc", return_address & 0xFFFFFFFE)
#     system.get_emulator().set_register("cpsr", (system.get_emulator().get_register("cpsr") & 0xFFFFFFDF) | ((return_address & 0x1) << 5))
#     system.get_emulator().cont()
#      
# bkpt_load_from_flash_rom.set_handler(load_from_flash_handler)
# bkpt_loaded_code_entry = ava.get_emulator().set_breakpoint(0x10087c)
# ava.get_emulator().cont()
#  
# bkpt_loaded_code_entry.wait()
# bkpt_loaded_code_entry.delete()
# print("QQQ Starting execution of loaded code ...")
#  
# bkpt_boot_fw_entry = ava.get_emulator().set_breakpoint(0x23e)
# ava.get_emulator().cont()
#  
# bkpt_boot_fw_entry.wait()
# bkpt_boot_fw_entry.delete()
# print("QQQ Starting execution of boot FW")
#  
# bkpt_load_from_flash_bootfw = ava.get_emulator().set_breakpoint(0x301e)
# bkpt_load_from_flash_bootfw.set_handler(load_from_flash_handler)
#  
# bkpt_before_sdram_initialization = ava.get_emulator().set_breakpoint(0x1146)
# ava.get_emulator().cont()
#  
# bkpt_before_sdram_initialization.wait()
# print("SDRAM initialization reached")
#  
# #Transfer state from emulator to device
# cpu_state = {}
# for reg in ["r0", "r1", "r2", "r3", 
#             "r4", "r5", "r6", "r7", 
#             "r8", "r9", "r10", "r11", 
#             "r12", "sp", "lr", "pc", "cpsr"]:
#     value = ava.get_emulator().get_register(reg)
#     cpu_state[reg] = hex(value)
#     ava.get_target().set_register(reg, ava.get_emulator().get_register(reg))
#  
# f = open("cpu_state.gdb", "w")
# for (reg, val) in cpu_state.items():
#     f.write("set $%s = %s\n" % (reg, val))
# f.close()
# print("CPU state: %s" % cpu_state.__str__())
# #At this point we have a problem:
# #The DDR memory initialization function is time-critical, i.e. 
# #its execution fails when run in emulator, since the forwarding
# #is too slow.
# #So we extract that bit of code that is time-critical (0x1146-0x1218) plus
# #its dependencies (0x1314-0x134c) and copy it to the VM
# code_memory = ava.get_emulator().read_untyped_memory(0x1146, 0x1218 - 0x1146)
# constant_pool = ava.get_emulator().read_untyped_memory(0x1314, 0x134c - 0x1314)
# f = open("code_memory", "wb")
# f.write(code_memory)
# f.close()
# f = open("constant_pool", "wb")
# f.write(constant_pool)
# f.close()
# ava.get_target().write_untyped_memory(0x1146, code_memory)
# ava.get_target().write_untyped_memory(0x1314, constant_pool)
# 
# 
# #Only testing stuff
# #     ava.get_target().write_typed_memory(0x1000, 2, 0x4801) #LDR r0, [pc, #4]
# #     ava.get_target().write_typed_memory(0x1002, 2, 0x2158) #MOVS r1, #'X'
# #     ava.get_target().write_typed_memory(0x1004, 2, 0x6001) #STR r1, [r0, #0]
# #     ava.get_target().write_typed_memory(0x1006, 2, 0xe7fb) #B .-10
# #     ava.get_target().write_typed_memory(0x1008, 4, 0x400d3000) 
# #     ava.get_target().set_register("pc", 0x1000)
# #     ava.get_target().set_register("cpsr", 0xf3)
# #bkpt_after_ram_init = ava.get_target().set_breakpoint(0x1006, thumb = True)
# 
# bkpt_after_ram_init = ava.get_target().set_breakpoint(0x1218, thumb = True)
# 
# ava.get_target().cont()
# 
# bkpt_after_ram_init.wait()
# 
# print("YESSSSSSSSSSSSSSS! We hit the breakpoint!")
# 
# #Transfer state to emulator
# for reg in ["r0", "r1", "r2", "r3", 
#             "r4", "r5", "r6", "r7", 
#             "r8", "r9", "r10", "r11", 
#             "r12", "sp", "lr", "pc", "cpsr"]:
#     value = ava.get_target().get_register(reg)
#     ava.get_emulator().set_register(reg, value)
#     
# bkpt_boot_fw_init = ava.get_emulator().set_breakpoint(0x4fc)
#     
# ava.get_emulator().cont()
# 
# bkpt_boot_fw_init.wait()
# 
# bkpt_dev_0x400d2000_init = ava.get_emulator().set_breakpoint(0x14aa)
# ava.get_emulator().cont()
# bkpt_dev_0x400d2000_init.wait()
# #Transfer state to target
# for reg in ["r0", "r1", "r2", "r3", 
#             "r4", "r5", "r6", "r7", 
#             "r8", "r9", "r10", "r11", 
#             "r12", "sp", "lr", "pc", "cpsr"]:
#     value = ava.get_emulator().get_register(reg)
#     ava.get_target().set_register(reg, value)
# ava.get_target().write_untyped_memory(0x14aa, ava.get_emulator().read_untyped_memory(0x14aa, 0x14b6 - 0x14aa))
# bkpt_after_dev_0x400d2000_init = ava.get_target().set_breakpoint(0x14b6)
# ava.get_target().cont()
# 
# bkpt_after_dev_0x400d2000_init.wait()
# 
# #Transfer state to emulator
# for reg in ["r0", "r1", "r2", "r3", 
#             "r4", "r5", "r6", "r7", 
#             "r8", "r9", "r10", "r11", 
#             "r12", "sp", "lr", "pc", "cpsr"]:
#     value = ava.get_target().get_register(reg)
#     ava.get_emulator().set_register(reg, value)
#     
# bkpt_in_timer_read_function = ava.get_emulator().set_breakpoint(0x103c3a)
# 
# def skip_timer_loop_handler(system, bkpt):
#     log.debug("Skipping timer loop")
#     system.get_emulator().set_register("pc", 0x103c42)
#     system.get_emulator().cont()
# bkpt_in_timer_read_function.set_handler(skip_timer_loop_handler)
# 
# bkpt_before_ddram_setup = ava.get_target().set_breakpoint(0xfa2)
# bkpt_in_timer_function = ava.get_target().set_breakpoint(0x103c36)
# ava.get_emulator().cont()
# bkpt_in_timer_function.wait()
# #bkpt_before_ddram_setup.wait()
#     
# print("YESSSSSSSSSSSSSSS! We hit the breakpoint X!")
#     
# # bkpt_in_boot_fw_task_2 = ava.get_target().set_breakpoint(0x29ea)
# # ava.get_emulator().cont()
# # 
# # bkpt_in_boot_fw_task_2.wait()
# 
# # CODE_ADDRESS= 0x1000
# # def get_code_callback(address, length):
# #     try:
# #         print("We are supposed to fetch memory 0x%x (%d bytes) from emulator" % (address, length))
# #         data = ava.get_emulator().read_untyped_memory(address, length)
# #         return data
# #     except:
# #         log.exception("Exception in Callback")
# # 
# # instrumented_code = binary_translator.instrument_memory_access(
# #     architecture = "thumb", 
# #     entry_point = 0x1146, 
# #     valid_pc_ranges = [(0x1146, 0x1218)] , 
# #     generated_code_address = CODE_ADDRESS, 
# #     get_code_callback = get_code_callback, 
# #     opts = {})
# # f = open("code.bin", "wb")
# # f.write(instrumented_code["generated_code"])
# # f.close()
# # ava.get_target().install_codelet(CODE_ADDRESS, instrumented_code["generated_code"])
# # ava.get_target().execute_codelet(CODE_ADDRESS | 1)
# 
# 
# print("YESSSSSSSSSSSSSSS! We hit the breakpoint 2!")
# 
# #CODE_ADDRESS = 0x2000
# #READ_INSTRUMENTATION_HANDLER = 0x4001 #TODO
# #WRITE_INSTRUMENTATION_HANDLER = 0x4003 #TODO
# #
# ##For now we use a simple entry stub into the generated code that just consists of a call function
# ##(arguments will be set up through this script a bit down)
# ##BL <CODE_ADDRESS>
# #avatar.get_target().write_typed_memory(0x1000, 2, 0xF000 | ((CODE_ADDRESS >> 12) & 0x7ff))
# #avatar.get_target().write_typed_memory(0x1002, 2, 0xF800 | ((CODE_ADDRESS >> 1) & 0x7ff))
# ##NOP where breakpoint will be put
# #avatar.get_target().write_typed_memory(0x1004, 2, 0x46c0)
# #avatar.get_target().write_typed_memory(0x1006, 2, 0x46c0)
# #avatar.get_target().write_typed_memory(0x1008, 2, 0x46c0)
# #avatar.get_target().write_typed_memory(0x100a, 2, 0x46c0)
# #avatar.get_target().write_typed_memory(0x100c, 2, 0x46c0)
# ##now translate the code
# #instrumented_code = binary_translator.instrument_memory_access(
# #    architecture = "thumb", 
# #    entry_point = 0x1146, 
# #    valid_pc_ranges = [(0x1146, 0x1218)] , 
# #    generated_code_address = CODE_ADDRESS, 
# #    get_code_callback = avatar.get_emulator().read_untyped_memory, 
# #    opts = {})
# #avatar.get_target().write_untyped_memory(0x2000, instrumented_code)
# ##Set up the register map
# #avatar.get_target().write_typed_memory(0x1010, 4, avatar.get_emulator().get_register("r0"))
# #avatar.get_target().write_typed_memory(0x1014, 4, avatar.get_emulator().get_register("r1"))
# #avatar.get_target().write_typed_memory(0x1018, 4, avatar.get_emulator().get_register("r2"))
# #avatar.get_target().write_typed_memory(0x101c, 4, avatar.get_emulator().get_register("r3"))
# #avatar.get_target().write_typed_memory(0x1020, 4, avatar.get_emulator().get_register("r4"))
# #avatar.get_target().write_typed_memory(0x1024, 4, avatar.get_emulator().get_register("r5"))
# #avatar.get_target().write_typed_memory(0x1028, 4, avatar.get_emulator().get_register("r6"))
# #avatar.get_target().write_typed_memory(0x102c, 4, avatar.get_emulator().get_register("r7"))
# #avatar.get_target().write_typed_memory(0x1030, 4, avatar.get_emulator().get_register("r8"))
# #avatar.get_target().write_typed_memory(0x1034, 4, avatar.get_emulator().get_register("r9"))
# #avatar.get_target().write_typed_memory(0x1038, 4, avatar.get_emulator().get_register("r10"))
# #avatar.get_target().write_typed_memory(0x103c, 4, avatar.get_emulator().get_register("r11"))
# #avatar.get_target().write_typed_memory(0x1040, 4, avatar.get_emulator().get_register("r12"))
# #avatar.get_target().write_typed_memory(0x1044, 4, avatar.get_emulator().get_register("sp"))
# #avatar.get_target().write_typed_memory(0x1048, 4, avatar.get_emulator().get_register("lr"))
# #avatar.get_target().write_typed_memory(0x104c, 4, avatar.get_emulator().get_register("cpsr"))
# ##Write handler addresses
# #avatar.get_target().write_typed_memory(0x1100, 4, READ_INSTRUMENTATION_HANDLER)
# #avatar.get_target().write_typed_memory(0x1104, 4, WRITE_INSTRUMENTATION_HANDLER)
# ##Set up function arguments
# #avatar.get_target().set_register("r0", 0x1010)
# #avatar.get_target().set_register("r1", 0x1100)
# #avatar.get_target().set_register("pc", 0x1000)
# #avatar.get_target().set_register("cpsr", 0x1f | 0x20 | 0xc0) #System mode, thumb, interrupts disabled
# ##AAAAAAAAAAAAND now - execute the shit!
# #bkpt_code_finished = avatar.get_target().set_breakpoint(0x1004, thumb = True)
# #avatar.get_target().cont()
# 
# 
# while True:
#     ava.get_emulator()._gdb_interface._gdb.sync_cmd(sys.stdin.readline().split(" "), "done")
# 
# #ava.emulator.set_breakpoint(0x650)
# #bkpt = avatar.emulator.set_breakpoint(0x650)
# #bkpt.wait()
# #avatar.copy_state_to_target()
# #avatar.target.continue()
