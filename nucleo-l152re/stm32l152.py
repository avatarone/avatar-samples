
import os

from avatar.emulators.s2e import init_s2e_emulator
from avatar.system import System
from avatar.targets.gdbserver_target import *
from avatar.targets.openocd_jig import *
from avatar.targets.openocd_target import *

configuration = {
    'output_directory': '/tmp/avatar_nucleo/',
    'configuration_directory': os.getcwd(),
    "s2e": {
        "emulator_gdb_path": "/home/vagrant/projects/gdb-build/gdb/gdb",
        "emulator_gdb_additional_arguments": ["--data-directory=/home/vagrant/projects/gdb-build/gdb/data-directory/"],
        's2e_binary': '/home/vagrant/projects/s2e-build/qemu-release/arm-s2e-softmmu/qemu-system-arm',
        "klee": {
        },
        "plugins": {
            "BaseInstructions": {},
            "Initializer": {},
            "MemoryInterceptor": "",
            "RemoteMemory": {
                "verbose": True,
                "listen_address": "localhost:9998",
                "ranges":  {
                    "peripherals": {
                        "address": 0x40000000,
                        "size":    0x10000000,
                        "access": ["read", "write", "execute", "io", "memory", "concrete_value", "concrete_address"]
                    }
                }
            }
        }
    },

    "qemu_configuration": {
        "gdbserver": False,
        "halt_processor_on_startup": True,
        "trace_instructions": True,
        "trace_microops": False,
        "append": ["-serial", "tcp::8888,server,nowait","-S"]
    },

    'machine_configuration': {
        'architecture': 'arm',
        'cpu_model': 'cortex-m3',
        'entry_address': 0x00,
        "memory_map": [
            {
                "size": 0x1000000,
                "name": "rom",
                "file": "./Nucleo_printf_NUCLEO_L152RE.bin",
                "map": [
                    {"address": 0x8000000,
                     "type": "code",
                     "permissions": "rwx"}
                ]
            },
            {
                "size": 0x100000,
                "name": "sram",
                "file": "./sram_after_init.bin",
                "map": [
                    {"address": 0x20000000,
                     "type": "code",
                     "permissions": "rw"}
                ]
            },
        ],
    },

    "avatar_configuration": {
        "target_gdb_address": "tcp:localhost:3333",
        "target_gdb_additional_arguments": ["--data-directory=/home/vagrant/projects/gdb-build/gdb/data-directory/"],
        "target_gdb_path": "/home/vagrant/projects/gdb-build/gdb/gdb",
    },
    'openocd_configuration': {
        'config_file': 'nucleo-l152re.cfg'
    }
    }


REGISTERS = [
    'r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11',
    'r12', 'sp', 'lr', 'pc', 'cpsr'
]

def get_regs(debuggable):
    regs = []
    for r in REGISTERS:
        regs.append(debuggable.get_register(r))
    return regs

def set_regs(debuggable, regs):
    for i in range(len(regs)):
        debuggable.set_register(REGISTERS[i], regs[i])

def main():

    main_addr = 0x8005104

    print("[!] Starting the Nucleo-L152RE demo")


    print("[+] Resetting target via openocd")
    hwmon = OpenocdJig(configuration)
    cmd = OpenocdTarget(hwmon.get_telnet_jigsock())
    cmd.raw_cmd("reset halt")


    print("[+] Initilializing avatar")
    ava = System(configuration, init_s2e_emulator, init_gdbserver_target)
    ava.init()
    ava.start()
    t = ava.get_target()
    e = ava.get_emulator()


    print("[+] Running initilization procedures on the target")
    main_bkt = t.set_breakpoint(main_addr)
    t.cont()
    main_bkt.wait()


    print("[+] Target arrived at main(). Transferring state to the emulator")
    set_regs(e, get_regs(t))

    #Cortex-M executes only in thumb-node, so the T-flag does not need to be set on these cpus.
    #However, qemu still needs to know the processore mode, so we are setting the flag manually.
    cpsr = e.get_register('cpsr')
    cpsr |= 0x20
    e.set_register('cpsr',cpsr)

    print("[+] Continuing execution in the emulator!")
    e.cont()

    #Further analyses code goes here
    while True:
        pass

if __name__ == '__main__':
    main()
