from avatar.system import System
import logging
from avatar.emulators.s2e import init_s2e_emulator
import threading
import subprocess
from avatar.targets.gdbserver_target import init_gdbserver_target
import os
import time
import tempfile
import argparse
from collections import OrderedDict

log = logging.getLogger(__name__)


FORWARDED_MEMORY = {
    "all_memory": {"address": 0x00000000, "size": 0xffffffff, "access": ["read", "write", "execute", "io", "memory", "concrete_value", "concrete_address"]}
}

EMULATOR_MAPPED_MEMORY = [
    {"size": 0x00001000, "name": "interrupts", "map": [{"address": 0, "type": "code", "permissions": "rwx"}]},
    {"size": 0x00019000, "name": "text_data_bss", "file": "u-boot.bin", "map": [{"address": 0x1000000, "type": "code", "permissions": "rwx"}],}
]



def build_configuration(args, env):
    output_dir = args.output_directory
    if output_dir is None:
        output_dir = tempfile.mkdtemp()
        print("No output directory specified, output files are written to %s" % (output_dir, ))
    configuration = {
        "output_directory": output_dir,
        "configuration_directory": os.getcwd(),
        "s2e": {
            "s2e_binary": args.s2e,
            "emulator_gdb_path": args.gdb,
            "emulator_gdb_additional_arguments": ["--data-directory=%s" % os.path.join(args.gdb_path, "gdb/data-directory")],
            "klee": {
            },
            "plugins": OrderedDict([
                ("BaseInstructions", {}),
                ("Initializer", {}),
                ("MemoryInterceptor", ""),
                ("RemoteMemory", {
                    "verbose": True,
                    "listen_address": "localhost:3333",
                    "ranges":  FORWARDED_MEMORY
                }),
            ])
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
            "memory_map": EMULATOR_MAPPED_MEMORY,
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
            "target_gdb_address": "tcp:localhost:1234",
            "target_gdb_additional_arguments": ["--data-directory=%s" % os.path.join(args.gdb_path, "gdb/data-directory")],
            "target_gdb_path": args.gdb
        }
    }

    configuration["s2e"]["plugins"]["ExecutionTracer"] = ""
    configuration["s2e"]["plugins"]["InstructionTracer"] = "" #"compression = \"gzip\""

    return configuration

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
        
def main(args, env):
    configuration = build_configuration(args, env)
    ava = System(configuration, init_s2e_emulator, init_gdbserver_target)
    ava.init()
    qemu = env["QEMU"] if "QEMU" in env else None
    if qemu is None:
        print("ERROR: Qemu emulator path is not set (QEMU env variable)")
        return 1
    target_runner = TargetLauncher([qemu, 
                                    "-M",  "versatilepb", 
                                    "-m", "20M", 
                                    "-serial", "udp:127.0.0.1:2000",
                                    "-kernel", "u-boot",
                                    "-gdb", "tcp:127.0.0.1:1234",
                                    "-S"])
    time.sleep(3)
    ava.start()

    bkpt_clear_bss = ava.get_emulator().set_breakpoint(0x010000b4)
    ava.get_emulator().cont()
    bkpt_clear_bss.wait()
    print("==================== Arrived at clear_bss ===========================")
#    bkpt_main_loop = ava.get_emulator().set_breakpoint(0x0100af34)
#    ava.get_emulator().cont()
#    bkpt_main_loop.wait()
#    print("Arrived at main loop, demo is over")
    
def parse_args():
    parser = argparse.ArgumentParser(description = "Minimal Avatar script with Qemu as target")
    parser.add_argument("-v", "--verbose", action = "count", default = 0, help = "Increase verbosity (specify several times for more)")
    parser.add_argument("--gdb-path", dest = "gdb_path", default = os.path.expanduser("~/projects/gdb"), type = str, help = "Path to ARM gdb, used for to get gdb's data_directory")
    parser.add_argument("--gdb", dest = "gdb", default = os.path.expanduser("~/projects/gdb-build/gdb/gdb"), type = str, help = "Path to ARM gdb executable")
    parser.add_argument("--s2e", dest = "s2e", default = os.path.expanduser("~/projects/s2e-build/qemu-release/arm-s2e-softmmu/qemu-system-arm"), type = str, help = "Path to S2E executable")
    parser.add_argument("--output-directory", dest = "output_directory", default = None, type = str, help = "Path where output files are generated")


    args = parser.parse_args()
    try:
        log_level = {
            0: logging.ERROR,
            1: logging.WARN,
            2: logging.INFO,
            3: logging.DEBUG}[args.verbose]
    except KeyError:
        log_level = logging.DEBUG

    logging.basicConfig(level = log_level)
    return args

if __name__ == "__main__":
    exit_code = main(parse_args(), os.environ)
    if not exit_code is None:
        sys.exit(exit_code)
