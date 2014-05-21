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
import qmp
import json
from avatar.targets.avatarstub_target import init_avatarstub_target
from avatar.emulators.s2e.debug_s2e_emulator import init_debug_s2e_emulator
from avatar.targets.gdbserver_target import init_gdbserver_target
from collections import OrderedDict
from usb_adapter import UsbScsiDevice

from Seagate_ST3320413AS_flasher import ResetController, StubDownloader

log = logging.getLogger(__name__)

MAINFW_EMULATOR_LOCAL_MEMORY = [
    {"address": 0x00000000, "size": 0x00000040, "type": "ro", "file": "binary/0x00000000_mainfw_IRQ_table.bin"},
    {"address": 0x00000040, "size": 0x00007b00, "type": "ro", "file": "binary/0x00000040_mainfw_SRAM_code.bin"},
    {"address": 0x00010000, "size": 0x00020000, "type": "ro", "file": "binary/0x00010000_mainfw_cache_code.bin"},
    {"address": 0x00100000, "size": 0x00020000, "type": "ro", "file": "binary/0x00100000_ROM.bin"},
    {"address": 0x00242f00, "size": 0x0006e454, "type": "ro", "file": "binary/0x00242f00_mainfw_DRAM_code.bin"},
    {"address": 0x002b1354, "size": 0x00000040, "type": "ro", "file": "binary/0x002b1354_mainfw_DRAM.bin"},
    {"address": 0x04000000, "size": 0x00004000, "type": "rw"},
    {"address": 0x060b0000, "size": 0x00020000, "type": "rw"},
    {"address": 0x06180000, "size": 0x00020000, "type": "rw"},
    {"address": 0x400d3000, "size": 0x00001000, "type": "io"}]
    
    
MEMORY_MAP = [
    {"size": 0x00008000, "name": "sram_code",      "map": [{"address": 0x00000000, "type": "code", "permissions": "rwx"}]},
    {"size": 0x00020000, "name": "sram_code_2",    "map": [{"address": 0x00010000, "type": "code", "permissions": "rx"}]},
    {"size": 0x00010000, "name": "rom_bootloader", "map": [{"address": 0x00100000, "type": "code", "permissions": "rx"}]},
    {"size": 0x00004000, "name": "sram_data",      "map": [{"address": 0x04000000, "type": "data", "permissions": "rw"}]},
    {"size": 0x00200000, "name": "dram_1",         "map": [{"address": 0x00200000, "type": "code", "permissions": "rx"}, {"address": 0x06000000, "type": "data", "permissions": "rw"}]},
    {"size": 0x00e00000, "name": "dram_2",         "map": [{"address": 0x06200000, "type": "data", "permissions": "rw"}]}]
    
GDB_ADDRESS = ('127.0.0.1', 1235)
QMP_ADDRESS = ('127.0.0.1', 1236)


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
       ]) 
    },
    "qemu_configuration": {
            "halt_processor_on_startup": True,
            "trace_instructions": True,
            "trace_microops": False,
            "gdb": "tcp::%d,server,nowait" % GDB_ADDRESS[1],
            "append": ["-qmp", "tcp::%d,server,nowait" % QMP_ADDRESS[1]],
            "qmp": "tcp::%d,server,nowait" % QMP_ADDRESS[1],
#            "append": ["-serial", "tcp::8888,server,nowait", "-nographic"]
#            "append": ["-serial", "tcp::8888,server,nowait", "-qmp", "tcp::1238,server,nowait"]
#            "append": ["-serial", "tcp::8888,server,nowait"]
        },
    "machine_configuration": {
            "architecture": "arm",
            "endianness": "little",
            "cpu_model": "arm926",
            "entry_address": 0x100000,
            "memory_map": MEMORY_MAP,
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
        "target_gdb_path":"../../gdb-arm/gdb/gdb",
        "target_gdb_description": "../../avatar-gdbstub/xml/arm-gdbstub.xml"
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
                if str(ex).startswith("write failed: [Errno 5]"):
                    if not stub_downloader is None:
                        del stub_downloader
                elif str(ex).startswith("could not open port"):
                    log.warn("Received exception \"%s\"; check that you specified a valid port", str(ex))
                    if not stub_downloader is None:
                        del stub_downloader
                    time.sleep(10)
                else:
                    raise ex
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
    parser.add_argument("--gdbstub-sram", type = str, metavar = "FILE", dest = "gdbstub",
        default = os.path.expanduser("~/projects/avatar-pandora/avatar-gdbstub-build/cmake/"),
        help = "GDB stub that is injected in the HDD")
    parser.add_argument("--gdbstub-sram-address", type = int, dest = "gdbstub_loadaddress", default = 0x7000,
        help = "Load address of GDB stub")
    parser.add_argument("--gdbstub-high", type = str, metavar = "FILE", dest = "gdbstub_high",
        default = os.path.expanduser("~/projects/avatar-pandora/avatar-gdbstub-build/cmake/"),
        help = "GDB stub that is injected in the HDD")
    parser.add_argument("--gdbstub-high-address", type = int, dest = "gdbstub_high_loadaddress", default = 0x3fc000,
        help = "Load address of GDB stub")
    parser.add_argument("-o", "--output", type = str, metavar = "DIRECTORY", dest = "output_directory",
        default = "/tmp/avatar-output",
        help = "Directory where resulting configuration and log files will be stored")
    parser.add_argument("--hdd-port", type = int, default = 2000, dest = "hdd_port",
        help = "Port where HDD flasher is listening")
    parser.add_argument("--dump-main-fw", action = "store_true", default = False, dest = "dump_main_fw", 
        help = "Dump main FW when copying")
    action = parser.add_mutually_exclusive_group(required = True)
    action.add_argument("--trace-bootloader", dest = "action", action = "store_const", const = "TRACE_BOOTLOADER", help = "Trace bootloader access for CCS experiments")
    action.add_argument("--trace-ata-identify", dest = "action", action = "store_const", const = "TRACE_IDENTIFY_ATA_CMD", help = "Trace ATA identify command (0xec) for CCS experiments")
    action.add_argument("--debug-main-fw", dest = "action", action = "store_const", const = "DEBUG_MAIN_FW", help = "Start HDD with avatar attached until main fw is loaded")
        
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


def boot_hdd_until_bootloader_firmware_entry(ava):
    ava.get_target().set_register("pc", 0x40)
    ava.get_target().set_register("cpsr", ava.get_target().get_register("cpsr") & ~0x20)
    bkpt_end_of_bootstrapper = ava.get_target().set_breakpoint(0x23e)
    ava.get_target().cont()

    # Execute till 0x23e, the end of the bootstrapper
    bkpt_end_of_bootstrapper.wait()
    bkpt_end_of_bootstrapper.delete()

    # Replace memory protection activation with nops
    ava.get_target().write_typed_memory(0x105e, 2, 0x46c0)
    ava.get_target().write_typed_memory(0x1060, 2, 0x46c0)

    # Intercept flash loads
    bkpt_beginning_of_flash_load_function = ava.get_target().set_breakpoint(0x301e)
    def handle_hdd_flash_load(ava, bkpt):
        TEMP_READ_IRQ_TABLE_ADDRESS = 0x7fb0
        ram_address = ava.get_target().get_register("r1")
        flash_address = ava.get_target().get_register("r2")
        size_in_words = ava.get_target().get_register("r3")

        log.debug("Loading 0x%x bytes from flash address 0x%x to ram address 0x%08x", size_in_words * 4, flash_address, ram_address)

        if ram_address == 0 and size_in_words > 0:
            #Divert flash loading to another address
            ava.get_target().set_register("r1", TEMP_READ_IRQ_TABLE_ADDRESS)

            bkpt_after_flash_load = ava.get_target().set_breakpoint(0x3044)
            def handle_after_flash_load(ava, bkpt):
                #Copy all exception vector entries except the ones that the GDB stub needs
                for offset in [0x0, 0x4, 0x8, 0x14, 0x18, 0x1c, 0x20, 0x24, 0x28, 0x34, 0x38, 0x3c]:
                    ava.get_target().write_typed_memory(0x0 + offset, 4, ava.get_target().read_typed_memory(TEMP_READ_IRQ_TABLE_ADDRESS + offset, 4))
                bkpt.delete()
                ava.get_target().cont()
            bkpt_after_flash_load.set_handler(handle_after_flash_load)
        ava.get_target().cont()
    bkpt_beginning_of_flash_load_function.set_handler(handle_hdd_flash_load)



    # Continue until entry to bootloader firmware, intercept flash loads on the way 
    bkpt_entry_to_bootloader_firmware = ava.get_target().set_breakpoint(0x10a4)
    ava.get_target().cont()

    bkpt_entry_to_bootloader_firmware.wait()
    bkpt_beginning_of_flash_load_function.delete()
    bkpt_entry_to_bootloader_firmware.delete()

    # Debug print output from bootloader firmware
#    bkpt_print_output_from_bootloader_fw = ava.get_target().set_breakpoint(0x244518)
#    def handle_print_output_from_bootloader_fw(ava, bkpt):
#        ptr = ava.get_target().get_register("r0")
#        i = 0
#        buffer = []
#        while True:
#            byte = ava.get_target().read_typed_memory(ptr + i, 1)
#            if byte == 0:
#                break
#            buffer.append(byte)
#            i += 1
#
#        print("Print from bootloader FW: %s" % bytes(buffer).decode(encoding = 'iso-8859-1'))
#        ava.get_target().cont()
#
#    bkpt_print_output_from_bootloader_fw.set_handler(handle_print_output_from_bootloader_fw)
    print("Apparently everything went well ...")

def boot_hdd_from_boot_firmware_entry_to_main_firmware_entry(ava, dump_main_fw = False):
    # Move GDB stub to high memory
    ava.get_target().execute_gdb_command(
        ["restore", 
         configuration["avatar_configuration"]["gdbstub_high"],
         "binary",
         "0x%x" % configuration["avatar_configuration"]["gdbstub_high_address"]])
    ava.get_target().write_typed_memory(0x2c, 4, configuration["avatar_configuration"]["gdbstub_high_address"] + 4)
    ava.get_target().write_typed_memory(0x30, 4, configuration["avatar_configuration"]["gdbstub_high_address"] + 8)

    print("GDB stub moved")

    # Break right before entering bootstrapper to main fw
    bkpt_before_bootstrapper_to_main_Fw = ava.get_target().set_breakpoint(0x246c30)
    ava.get_target().cont()
    bkpt_before_bootstrapper_to_main_Fw.wait()
    bkpt_before_bootstrapper_to_main_Fw.delete()

    log.debug("Main FW bootstrapper: arg0 = 0x%08x, arg1 = 0x%08x, arg2 = 0x%08x, arg3 = 0x%08x", 
              ava.get_target().get_register("r0"),
              ava.get_target().get_register("r1"),
              ava.get_target().get_register("r2"),
              ava.get_target().get_register("r3"))
#    ava.get_target().execute_gdb_command(["dump", "memory", os.path.join(configuration["output_directory"], "memdump_0x06300000.bin"),
#                    "0x%x" % 0x6300000, "0x%x" % 0x6400000])

    bkpt_main_fw_bootstrapper_copy_section = ava.get_target().set_breakpoint(0x22ba1e)
    def handle_main_fw_bootstrapper_load_section(ava, bkpt):
        TEMP_READ_IRQ_TABLE_ADDRESS = 0x358000
        from_address = ava.get_target().get_register("r4")
        to_address = ava.get_target().get_register("r6")
        size = (ava.get_target().read_typed_memory(ava.get_target().get_register("r7"), 4) >> 12) * 4
        
        log.debug("Main FW bootstrapper: Copying section from 0x%08x to 0x%08x (size 0x%x)", from_address, to_address, size)

        if size != 0 and dump_main_fw:
            ava.get_target().execute_gdb_command(
                ["dump", 
                 "memory", 
                 os.path.join(configuration["output_directory"], "mainfw_0x%08x.bin" % to_address),
                "0x%x" % from_address, "0x%x" % (from_address + size)])

        if to_address == 0 and size != 0:
            for offset in [0, 4, 8, 0x14, 0x18, 0x1c, 0x20, 0x24, 0x28, 0x34, 0x38, 0x3c]:
                ava.get_target().write_typed_memory(to_address + offset, 4, ava.get_target().read_typed_memory(from_address + offset, 4))

            ava.get_target().set_register("r4", ava.get_target().get_register("r4") + 0x40)
            ava.get_target().set_register("r6", ava.get_target().get_register("r6") + 0x40)
            ava.get_target().set_register("r5", ava.get_target().get_register("r5") + 0x10)
#            bkpt_main_fw_bootstrapper_copy_section.delete()
        ava.get_target().cont()
    bkpt_main_fw_bootstrapper_copy_section.set_handler(handle_main_fw_bootstrapper_load_section)
    bkpt_jump_to_main_fw = ava.get_target().set_breakpoint(0x22ba44)
    
    ava.get_target().cont()
    bkpt_jump_to_main_fw.wait()
    bkpt_main_fw_bootstrapper_copy_section.delete()
    bkpt_jump_to_main_fw.delete()

    #Overwrite call to mprotect
    ava.get_target().write_typed_memory(0xa48, 2, 0x46c0)
    ava.get_target().write_typed_memory(0xa4a, 2, 0x46c0)

    #Overwrite default UART baudrate in UART initialization
    ava.get_target().write_typed_memory(0x40003bc, 2, 0x36)
    

def start_in_emulator(ava):
    bkpt_load_from_flash = ava.get_emulator().set_breakpoint(0x100aae)
    def handle_load_from_flash(ava, bkpt):
        ram_addr = ava.get_emulator().get_register("r1")
        flash_addr = ava.get_emulator().get_register("r2")
        len_in_words = ava.get_emulator().get_register("r3")
        return_address = ava.get_emulator().get_register("lr")

        log.info("Loading 0x%x bytes from flash address 0x%x to ram address 0x%x", len_in_words * 4, flash_addr, ram_addr)
        if len_in_words > 0:
            ava.get_emulator().execute_gdb_command(["restore", 
                                                    os.path.join(configuration["configuration_directory"], "JC49_flash.raw"), 
                                                    "binary", 
                                                    "%d" % (ram_addr - flash_addr), 
                                                    "0x%x" % flash_addr,
                                                    "0x%x" % (flash_addr + 4 * len_in_words)])

        #Return to caller
        ava.get_emulator().set_register("pc", return_address & 0xFFFFFFFE)
        thumb_bit = (return_address & 1) << 5
        cpsr = ava.get_emulator().get_register("cpsr")
        ava.get_emulator().set_register("cpsr", (cpsr & 0xFFFFFFDF) | thumb_bit)
        ava.get_emulator().cont()
    bkpt_load_from_flash.set_handler(handle_load_from_flash)
    ava.get_emulator().cont()

def configure(args):
    configuration["output_directory"] = args.output_directory
    configuration["flasher_port"] = args.hdd_port
    flasher_port = args.hdd_port #TODO: If flasher_port is None, assign a port
    configuration["avatar_configuration"]["target_gdb_address"] = "tcp:127.0.0.1:%d" % flasher_port
    configuration["avatar_configuration"]["gdbstub_high"] = args.gdbstub_high
    configuration["avatar_configuration"]["gdbstub_high_address"] = args.gdbstub_high_loadaddress
    
def start_hdd(args):
    #Start target
    hdd_launcher = TargetLauncher(args.gdbstub, 
                                  args.gdbstub_loadaddress, 
                                  args.gdbstub_loadaddress, 
                                  args.power_control,
                                  args.serial,
                                  configuration["flasher_port"])
    hdd_launcher.start()
    hdd_launcher.wait()

    log.info("HDD gdb stub installed and running")

def start_avatar():
    ava = System(configuration, init_s2e_emulator, init_gdbserver_target)
    ava.init()
    ava.start()

    # Configure target GDB
    ava.get_target().execute_gdb_command(["set", "arm", "frame-register", "off"])
    ava.get_target().execute_gdb_command(["set", "arm", "force-mode", "thumb"])
    ava.get_target().execute_gdb_command(["set", "tdesc", "filename", configuration["avatar_configuration"]["target_gdb_description"]])

    return ava

def add_emulated_serial_port_to_emulator_configuration(data_string):
    """Add a memory interceptor that injects serial port data"""
    configuration["s2e"]["plugins"]["ModuleExecutionDetector"] = """
            trackAllModules = true,
            configureAllModules = true,
            ram_module = {
                moduleName = "ram_module",
                kernelMode = true,
            },
        """
    configuration["s2e"]["plugins"]["RawMonitor"] = """
            kernelStart = 0,
            -- we consider RAM
            ram_module = {
                delay      = false,
                name       = "ram_module",
                start      = 0x00000000,
                size       = 0xffffffff,
                nativebase = 0x00000000,
                kernelmode = false
            }
        """
    configuration["s2e"]["plugins"]["MemoryInterceptor"] = ""
    configuration["s2e"]["plugins"]["Annotation"] = ""
    configuration["s2e"]["plugins"]["MemoryInterceptorAnnotation"] = """
            verbose = true,
            interceptors = {
                uart_data = {
                    address = 0x400d3000,
                    size = 4 * 10,
                    access_type = {"read", "concrete_address", "concrete_value"},
                    read_handler = "ann_uart_read_data"
                }
            }
        """

    uart_lua_file = os.path.join(configuration["output_directory"], "uart.lua") 
    with open(uart_lua_file, 'w') as file:
        file.write("""
            UART_DATA = {%s}
            function ann_uart_read_data(state, plg, address, size, is_io, is_code)
                pc = state:readRegister("pc")
                if pc == 0x100bca then
                    return 0, 0 -- Do not bother with writes to serial port
                end
                reg = (address - 0x400d3000) / 4
                io.write(string.format("Reading UART register %%d at 0x%%08x\\n", reg, pc)) 
                if reg == 0 then
                    counter = plg:getValue("uart_counter")
                    plg:setValue("uart_counter", counter + 1)  
                    if counter < table.getn(UART_DATA) then
                        return 1, UART_DATA[counter]
                    else
                        plg:exit()
                    end
                elseif reg == 5 then --Flag register
                    return 1, 0xc1 -- return always TX empty, RX full
                elseif reg == 1 then --Status register 
                    return 1, 0
                end
            end
            """ % ", ".join(["0x%02x" % x for x in data_string]))

    if not "include" in configuration["s2e"]:
        configuration["s2e"]["include"] = []
    configuration["s2e"]["include"].append(uart_lua_file)
    

first_load_from_flash = True

def trace_bootloader(args):
    """Start execution in the emulator, then input some commands to the bootloader, and finally boot the firmware. Stop before entering code
       loaded from flash."""
    configure(args)
    #Configure serial port to read data from text file

    if not "append" in configuration["qemu_configuration"]:
        configuration["qemu_configuration"]["append"] = []
    configuration["qemu_configuration"]["append"] += ["-serial", "file:%s" % os.path.join(configuration["output_directory"], "serial_output.txt")]
    configuration["s2e"]["plugins"]["MemoryInterceptor"] = ""
    configuration["s2e"]["plugins"]["RemoteMemory"] = {
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
            }
    configuration["s2e"]["plugins"]["ExecutionTracer"] = ""
    configuration["s2e"]["plugins"]["InstructionTracer"] = "" #"compression = \"gzip\""
    configuration["s2e"]["plugins"]["MemoryTracer"] = """
        monitorMemory = true, 
        manualTrigger = false, 
        timeTrigger = false
    """

    add_emulated_serial_port_to_emulator_configuration("UUAP 0\rRD\rBT\rAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".encode(encoding = 'ascii'))
     
    start_hdd(args)
    ava = start_avatar()

    
    bkpt_load_from_flash = ava.get_emulator().set_breakpoint(0x100aae)
    def handle_load_from_flash(ava, bkpt):
        global first_load_from_flash
        ram_addr = ava.get_emulator().get_register("r1")
        flash_addr = ava.get_emulator().get_register("r2")
        len_in_words = ava.get_emulator().get_register("r3")
        return_address = ava.get_emulator().get_register("lr")

        if first_load_from_flash:
            #First flash load needs to fail so we enter the serial menu 
            ava.get_emulator().set_register("r0", 0xdead)
            first_call = False
        else:
            log.info("Loading 0x%x bytes from flash address 0x%x to ram address 0x%x", len_in_words * 4, flash_addr, ram_addr)
            if len_in_words > 0:
                flash_file = os.path.join(configuration["configuration_directory"], "JC49_flash.raw")
                ava.get_emulator().execute_gdb_command(["restore", 
                                                    flash_file, 
                                                    "binary", 
                                                    "%d" % (ram_addr - flash_addr), 
                                                    "0x%x" % flash_addr,
                                                    "0x%x" % (flash_addr + 4 * len_in_words)])
                with open(flash_file, 'rb') as file:
                    file.seek(flash_addr)
                    checksum = sum(file.read(len_in_words * 4))
                ava.get_emulator().set_register("r0", checksum & 0xffff)
            else:
                ava.get_emulator().set_register("r0", 0)
                 

        #Return to caller
        ava.get_emulator().set_register("pc", return_address & 0xFFFFFFFE)
        thumb_bit = (return_address & 1) << 5
        cpsr = ava.get_emulator().get_register("cpsr")
        ava.get_emulator().set_register("cpsr", (cpsr & 0xFFFFFFDF) | thumb_bit)
        ava.get_emulator().cont()
    bkpt_load_from_flash.set_handler(handle_load_from_flash)
        
    #Set breakpoint before entry to main FW
    bkpt_enter_fw_loaded_from_flash = ava.get_emulator().set_breakpoint(0x010065A)
    ava.get_emulator().cont()
    bkpt_enter_fw_loaded_from_flash.wait()
    print("################### Reached the end, Avatar should terminate ###################")

    sys.exit(0)

def execute_main_fw_on_device(args):
    configure(args)
    start_hdd(args)
    ava = start_avatar()
    boot_hdd_until_bootloader_firmware_entry(ava)
    boot_hdd_from_boot_firmware_entry_to_main_firmware_entry(ava, args.dump_main_fw)
    print("Now connect wih arm-none-eabi-gdb to localhost:2000")

def configure_full_forwarding(args):
    sorted_ro_ranges = sorted(MAINFW_EMULATOR_LOCAL_MEMORY, key = lambda x: x["address"])
    start = 0
    ranges = {}
    for ro_range in sorted_ro_ranges:
        if ro_range["address"] - start > 0:
            end = ro_range["address"]
            ranges["range_0x%08x_0x%08x" % (start, end)] = {
                "address": start,
                "size": end - start,
                "access": ["read", "write", "execute"]
            }
        start = ro_range["address"] + ro_range["size"]
    if start != 0x100000000:
        end = 0x100000000
        ranges["range_0x%08x_0x%08x" % (start, end)] = {
            "address": start,
            "size": end - start,
            "access": ["read", "write", "execute"]
        }

    configuration["s2e"]["plugins"]["MemoryInterceptor"] = ""
    configuration["s2e"]["plugins"]["RemoteMemory"] = {
        "verbose": True,
        "listen_address": "127.0.0.1:3333",
        "ranges" : ranges
    }

def load_mainfw_ro_memory_into_emulator(ava):
    for mem_range in filter(lambda x: x["type"] == "ro", MAINFW_EMULATOR_LOCAL_MEMORY):
        ava.get_emulator().execute_gdb_command([
            "restore",
            os.path.join(configuration["configuration_directory"], mem_range["file"]),
            "binary",
            "0x%x" % mem_range["address"]])

def copy_rw_memory(fro, to):
    for rw_range in filter(lambda x: x["type"] == "rw", MAINFW_EMULATOR_LOCAL_MEMORY):
        filename = os.path.join(configuration["output_directory"], "s2e-last", "mem_0x%08x.bin" % rw_range["address"])
        fro.execute_gdb_command(["dump", "memory", filename, "0x%x" % rw_range["address"], "0x%x" % (rw_range["address"] + rw_range["size"])])
        to.execute_gdb_command(["restore", filename, "binary", "0x%x" % rw_range["address"]])

def copy_cpu_registers(fro, to):
    #We never use FIQ, do not copy this state (also there are some problems :) 
    #Also do not copy abort, this is just the GDB stub stuff, and undefined, which is not used
    #Order of the registers is important! (Which before cpsr and which after)
    registers = {}
    for reg in ["cpsr", "r0", "r1", "r2", "r3", 
                "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "sp",
                "lr", "pc", "sp_usr", "lr_usr", "spsr_usr", "sp_svc", "lr_svc", 
                "spsr_svc", "sp_irq", "lr_irq", "spsr_irq"]: 
        
        reg_value = fro.get_register(reg)
        to.set_register(reg, reg_value)
        registers[reg] = reg_value
        
    with open(os.path.join(configuration["output_directory"], "s2e-last", "registers.json"), 'w') as file:
        json.dump(registers, file)

def trace_ata_identify(args):
    configure(args)
    configure_full_forwarding(args)
    #Do more configuration here
    configuration["s2e"]["plugins"]["LuaMonitorCommand"] = "verbose = true"
    configuration["s2e"]["plugins"]["Snapshot"] = "verbose = true"
    configuration["s2e"]["plugins"]["ExecutionTracer"] = "" #"compression = \"gzip\""
    configuration["s2e"]["plugins"]["InstructionTracer"] = ""
    configuration["s2e"]["plugins"]["MemoryTracer"] = """
        monitorMemory = true,
        manualTrigger = false, 
        timeTrigger = false
    """
    start_hdd(args)
    ava = start_avatar()
    boot_hdd_until_bootloader_firmware_entry(ava)
    boot_hdd_from_boot_firmware_entry_to_main_firmware_entry(ava)

    #Now ... 
    #Set breakpoint in serial character receive handler, used to regain control afterwards
    bkpt_interrupt = ava.get_target().set_breakpoint(0x2442aa)
    #Change program a bit to handle 0x03 (break) instead of 0xdb and put a breakpoint on that handler
#    ava.get_target().write_typed_memory(0x243d06, 2, 0x2c03) #cmp r4, #0x03
#    ava.get_target().write_typed_memory(0x243d52, 2, 0xe7fa) #b loc243d4a
#    bkpt_interrupt = ava.get_target().set_breakpoint(0x243d52)
    ava.get_target().cont()

#    bkpt_interrupt.wait()
#    ava.get_target().cont()

    #Wait for JMicron USB-SATA bridge to show up
    #TODO: Prints LSUSB output, use Popen with PIPE to avoid
    while True:
        try:
            subprocess.check_call(["lsusb", "-d", "152d:2338"])
            break
        except subprocess.CalledProcessError:
            time.sleep(1)
            continue

    log.debug("USB SATA bridge showed up")

    #Leave the OS some time to play with the disk ...
    time.sleep(5)

    #TODO: This should work, but it does not ... so work around by directly sending CTRL+C to the HDD
#    ava.get_target().execute_gdb_command(["-exec-interrupt"])
    with open(args.serial, 'wb') as serial_port:
        serial_port.write(bytes([0x03]))

    #Target should be stopped now
    #Set breakpoint at SATA interrupt handler
    bkpt_sata_irq = ava.get_target().set_breakpoint(0x1f42)
    ava.get_target().cont()

    #Send ATA identify packet (0xec)
    usb_ata_bridge = UsbScsiDevice()
#    usb_ata_bridge.send_ata_command(0x00, False, 0, 0, 0, 0x7654321, 0)
    usb_ata_bridge.send_ata_command(0xec, False, 512, 1, 0, 0, 0)
#    usb_ata_bridge.send_scsi_read(0x12345678, 0x42)
#    usb_ata_bridge.send_scsi_write(0xdeadbeef, bytes([(x & 0xff) for x in range(0, 2048)]))

    #Breakpoint should have been hit now, just call wait to make sure
    bkpt_sata_irq.wait()

    print("Bkpt after waiting for SATA irq hit")


    #TODO: Trigger snapshot of all RW-areas

    #We need to execute one instruction in the emulator so that everything 
    #works ... especially the Snapshot plugin
    ava.get_emulator().write_typed_memory(0x0, 4, 0)
    ava.get_emulator().write_typed_memory(0x4, 4, 0)
    ava.get_emulator().set_register("pc", 0)
    bkpt_init_emulator = ava.get_emulator().set_breakpoint(0x4)
    ava.get_emulator().cont()
    bkpt_init_emulator.wait()
    bkpt_init_emulator.delete()
    
    #Load RO memory from files
    load_mainfw_ro_memory_into_emulator(ava)
    
    copy_cpu_registers(ava.get_target(), ava.get_emulator())
    copy_rw_memory(ava.get_target(), ava.get_emulator())

    print("Now happily tracing ... ")

    #Add a quirk to avoid getting stuck in the timer anti-jitter loop
    ava.get_emulator().write_typed_memory(0x103c40, 2, 0x46c0) #NOP
    ava.get_emulator().write_typed_memory(0x181c, 2, 0x46c0) #NOP
    ava.get_emulator().write_typed_memory(0x1027A4, 2, 0x4770) #BX LR
    
    
    #Take a snapshot that can be used to restore stuff for symbolic execution
    qmp_console = qmp.QEMUMonitorProtocol(QMP_ADDRESS)
    qmp_console.connect()
    
    qmp_console.cmd("s2e-exec", 
        {
            "cmd": "lua", 
            "lua": "Snapshot.takeSnapshot('before_trace', 7, " + \
                "{" + \
                    "{address = 0x00000000, size = 0x00008000}, " + \
                    "{address = 0x00010000, size = 0x00020000}, " + \
                    "{address = 0x00100000, size = 0x00020000}, " + \
                    "{address = 0x04000000, size = 0x00004000}, " + \
                    "{address = 0x06000000, size = 0x01000000}})"
        })

    #This breakpoint is in the idle task, which is only called when all other tasks have no work
    #(i.e., when the current request has been served)
    bkpt_end_of_trace = ava.get_emulator().set_breakpoint(0x00253a06)

    #Trace execution
    ava.get_emulator().cont()

    bkpt_end_of_trace.wait()
    #Hara kiri!
    os.kill(os.getpid(), 9)
    
#    usb_ata_bridge.receive_mass_storage_response(512)

def replay_ata_identify(args):
    pass
        
def main():
    args = parse_arguments()
    set_verbosity(args.verbosity)
   
    if args.action == "TRACE_BOOTLOADER":
        trace_bootloader(args)
    elif args.action == "TRACE_IDENTIFY_ATA_CMD":
        trace_ata_identify(args)
    elif args.action == "DEBUG_MAIN_FW":
        execute_main_fw_on_device(args)        
    elif args.action == "REPLAY_IDENTIFY_ATA_CMD":
        replay_ata_identify(args)

if __name__ == "__main__":
    main()
