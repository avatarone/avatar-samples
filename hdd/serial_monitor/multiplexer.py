# -*- coding: utf-8 -*-
import twisted.internet.protocol
import twisted.internet.reactor
import twisted.internet.serialport
from twisted.internet.serialport import EIGHTBITS
from twisted.internet.serialport import PARITY_NONE
from twisted.internet.serialport import STOPBITS_ONE
import socket
import logging
import types
import functools
import sys
import re
import Queue
import time
import random
import pickle
import serial
from itertools import chain

HDD_ON_RTS_STATE = True

log = logging.getLogger('multiplexer')
onoff_port = True

#class ConcurrencyChecker(object):
#    STATE_NEW = 0
#    STATE_EXECUTE = 1
#    STATE_TEMP_FAIL = 2
#    STATE_PERMANENT_FAIL = 3
#    STATE_SUCCESS = 4
#
#    STATE_MAP = {("__init__", None): STATE_NEW, ("execute", None): STATE_EXECUTE, ("_success", None): STATE_SUCCESS, ("_fail", "temporary"): STATE_TEMP_FAIL, ("_fail", "permanent"): STATE_PERMANENT_FAIL, ("handle_input", None): STATE_EXECUTE}
#
#    def __init__(self):
#        self.file = open('/tmp/concurrency.pickle', 'a+')
#        self.log_file = open('/tmp/concurrency.log', 'a+')
#        self.commands = {}
#
#    def notify(self, command, method, comment = None):
##        pickle.dump((command, method, comment), self.file)
#        self.log_file.write("%d (%s, %d), %s, %s\n" % (int(time.time()), command.command_name(), id(command), method.im_func.func_name, comment))
#
#        if method.im_func.func_name == "__init__":
#            self.commands[command] = self.STATE_NEW
#        elif not command in self.commands:
#            self.error(command, "%s called before __init__" % method.im_func.func_name)
#        elif method.im_func.func_name == "execute" and self.commands[command] in [self.STATE_EXECUTE, self.STATE_PERMANENT_FAIL, self.STATE_SUCCESS]:
#            self.error(command, "execute called from invalid state")
#        elif method.im_func.func_name == "handle_input":
#            if self.commands[command] != self.STATE_EXECUTE:
#                self.error(command, "handle_input called while not in execute state")
#        else:
#            try:
#                self.commands[command] = self.STATE_MAP[(method.im_func.func_name, comment)]
#            except KeyError, e:
#                self.error(command, "init not called")
#            
#    def error(self, command, message):
#        self.log_file.write("%d ERROR: (%s, %d): %s\n" % (int(time.time()), command.command_name(), id(command), message))
#
#
#concurrency_checker = ConcurrencyChecker()

class CommandParser(object):
    def __init__(self, format):
        format = format.split()
        self.command = format[0]
        self.options = map(lambda x: OptionParser(x), format[1:])

    def parse(self, cmd):
        cmd_arr = cmd.strip().split()

        if not cmd_arr:
            raise SyntaxError("No command line given!")

        if not cmd_arr[0] == self.command:
            raise SyntaxError("Parsed command '%s' not equal to expected command '%s'" % (cmd_arr[0], self.command))

        return dict(map(lambda (x, y): (x.name, x.parse_option(y)), zip(self.options, cmd_arr[1:])))

class OptionParser(object):
    REX_OPTIONAL = re.compile('^\((.*)\)$')
    REX_NAME = re.compile('^[A-Za-z0-9_]+')
    REX_TYPE = re.compile('\[[a-z]+\]')

    def __init__(self, format):
        format = format.strip()
        if self.REX_OPTIONAL.match(format):
            #Currently we just use the optional marker as information to the programmer
            format = self.REX_OPTIONAL.match(format).group(1).strip()    

        rex_name = self.REX_NAME.search(format)
        rex_type = self.REX_TYPE.search(format)
    
        if rex_name and rex_type:
            self.name = rex_name.group(0)
            self.type = rex_type.group(0)
        else:
            raise SyntaxError("Unable to parse option specification %s" % format)

    def parse_option(self, value):
        if self.type == "[int]":
            if value.strip().startswith("0x"):
                return int(value, 16)
            else:
                return int(value)
        elif self.type == "[string]":
            return value
        elif self.type == "[float]":
            return float(value)
        elif self.type == "[bool]":
            value = value.lower()
            if value == "on" or value == "true":
                return True
            elif value == "off" or value == "false":
                return False
            else:
                raise SyntaxError("Cannot parse option %d%d = %d" % (self.name, self.type, value))
        elif self.type == "[hexstring]":
            #split the string of hex numbers in pairs of two characters
            twochars = map("".join, (zip(*[iter(value)] * 2)))
            #and then convert these to chars and put the string back together
            return "".join(map(lambda x: chr(int(x, 16)), twochars))
        else:
            raise SyntaxError("Unknown type %d" % self.type)




class GDBProtocolFilter(object):
    IDLE_STATE = 0
    PACKET_BEGINNING_SEEN = 1
    IN_PACKET = 4
    PACKET_ENDING_SEEN = 2
    PACKET_FIRST_CHECKSUM_CHAR_SEEN = 3
        
    def __init__(self):
        self.state = 0
        self.to_stub_handler = None
        self.from_stub_handler = None
        self.from_stub_buffer = []

    def filter(self, handler, data):
        result = []
        
        if self.from_stub_handler is None:
            self.from_stub_handler = handler
            self.from_stub_handler("".join(self.from_stub_buffer))
            self.from_stub_buffer = []

        for c in data:
            if self.state == self.IDLE_STATE and c == '$':
                self.state = self.PACKET_BEGINNING_SEEN
                result.append(c)
            elif self.state == self.IDLE_STATE and (c == '+' or c == '-'):
                result.append(c)
            elif self.state == self.PACKET_BEGINNING_SEEN or self.state == self.IN_PACKET:
                self.state = self.IN_PACKET
                if c == '#':
                    self.state = self.PACKET_ENDING_SEEN
                result.append(c)
            elif self.state == self.PACKET_ENDING_SEEN:
               self.state = self.PACKET_FIRST_CHECKSUM_CHAR_SEEN
               result.append(c)
            elif self.state == self.PACKET_FIRST_CHECKSUM_CHAR_SEEN:
               self.state = self.IDLE_STATE
               result.append(c)

        result = "".join(result)
        if result:
            handler(result)
            
#    def filter_to_stub(self, handler, data):
#        #result = []
#        handler(data)
        
        #for c in data:
            #if self.state == self.IDLE_STATE and c == '$':
                #self.state = self.PACKET_BEGINNING_SEEN
            #elif self.state == self.PACKET_BEGINNING_SEEN:
                #if c == 'q':
                    #self.state = self.IN_INTERCEPTED_PACKET
                    #self.intercepted_packet = ['q']
                    #self.intercepted_packet_state = self.IN_PACKET
                #else:
                    #self.state = self.IN_PACKET
            #elif self.state == self.IN_INTERCEPTED_PACKET:
                #if self.intercepted_packet_state == self.IN_PACKET:
                    #if c == '#':
                        #self.intercepted_packet_state = self.PACKET_ENDING_SEEN
                    #else:
                        #self.query_packet.append(c)
                #elif self.intercepted_packet_state == self.PACKET_ENDING_SEEN:
                    #self.intercepted_packet_checksum_chars = c
                    #self.intercepted_packet_state = self.PACKET_FIRST_CHECKSUM_CHAR_SEEN
                #elif self.intercepted_packet_state == self.PACKET_FIRST_CHECKSUM_CHAR_SEEN:
                    #received_checksum = int(self.intercepted_packet_checksum_chars + c, 16)
                    #calculated_checksum = 0
                    #received_packet = "".join(self.intercepted_packet)
                    #for d in received_packet:
                        #calculated_checksum += ord(d)
                    #calculated_checksum &= 0xFF
                    #if calculated_checksum == received_checksum:
                        #self.send_to_gdb('+')
                        #self.handle_intercepted_packet("".join(self.query_packet)
                    #else:
                        #self.send_to_gdb('-')
                    #self.intercepted_packet_state = None
                    #self.state = self.IDLE_STATE
            #elif self.state == self.IN_PACKET:
                #if c == '#':
                    #self.state = self.PACKET_ENDING_SEEN
            #elif self.state == self.PACKET_ENDING_SEEN
                #self.state = self.PACKET_FIRST_CHECKSUM_CHAR_SEEN
            #elif self.state == self.PACKET_FIRST_CHECKSUM_CHAR_SEEN
                #self.state = self.IDLE_STATE
                
#    def send_to_gdb(self, str):
#        if self.from_stub_handler is None:
#            self.from_stub_buffer.append(str)
#        else:
#            self.from_stub_handler(str)
            
#    def handle_intercepted_packet(self, packet):
#        if packet == 'qSymbol::':
#            #spew out all the symbols we know
#        elif packet.startswith('qSymbol:'):
            
            
                
class NotGDBProtocolFilter(object):
    IDLE_STATE = 0
    PACKET_BEGINNING_SEEN = 1
    IN_PACKET = 4
    PACKET_ENDING_SEEN = 2
    PACKET_FIRST_CHECKSUM_CHAR_SEEN = 3
        
    def __init__(self):
        self.state = 0
        self.to_stub_handler = None
        self.from_stub_handler = None
        self.from_stub_buffer = []

    def filter(self, handler, data, address):
        result = []
        
        if self.from_stub_handler is None:
            self.from_stub_handler = handler
            self.from_stub_handler("".join(self.from_stub_buffer), address)
            self.from_stub_buffer = []
            #Drop GDB data
        for c in data:
            if self.state == self.IDLE_STATE and c == '$':
                self.state = self.PACKET_BEGINNING_SEEN
            #TODO: this filtering is maybe too aggressive, since it filters all '+' and '-' ...
            elif self.state == self.IDLE_STATE and (c == '+' or c == '-'):
                #Drop GDB data
                pass
            elif self.state == self.PACKET_BEGINNING_SEEN or self.state == self.IN_PACKET:
                self.state = self.IN_PACKET
                if c == '#':
                    self.state = self.PACKET_ENDING_SEEN
                #drop GDB data
            elif self.state == self.PACKET_ENDING_SEEN:
                self.state = self.PACKET_FIRST_CHECKSUM_CHAR_SEEN
                #Drop GDB data
            elif self.state == self.PACKET_FIRST_CHECKSUM_CHAR_SEEN:
                self.state = self.IDLE_STATE
                #Drop GDB data
            else:
                result.append(c)

        result = "".join(result)
        if result:
            handler(result, address)
        


class Command(object):
    """The abstract implementation of a command. 
       This class should never be visible to the user, only subclasses should be exposed.
    """

    #Needs to be defined by each command implementation to specify how a command is parsed from the command line
    PARSE_SPEC = "command"


    def __init__(self, reactor, serial_port, command_options = {}, timeout = 5, retries = 3):
        self.command_id = random.randint(0, sys.maxsize)
        self.log = logging.getLogger("multiplexer.Command")
        self.reactor = reactor
        self.executing = False
        self.buffer = ""
        self.timeout = timeout
        self.serial_port = serial_port
        self.retries = retries
        self.command_options = command_options
        if 'retries' in command_options:
            self.retries = command_options['retries']
        if 'timeout' in command_options:
            self.retries = command_options['timeout']
#        concurrency_checker.notify(self, self.__init__)

    def command_name(self):
        return self.PARSE_SPEC.split()[0]


    def abort(self):
        self.retries = 0
        self._abort()
        self._fail("aborted")

    def execute(self):
#        concurrency_checker.notify(self, self.execute)
        self.log.info("Command %s with arguments %s started", self.PARSE_SPEC.split()[0], self.command_options)
        self.executing = True
        self.timeout_aborter = self.reactor.callLater(self.timeout, functools.partial(self._fail, "timeout"))
        self._execute()

    def handle_input(self, data):
        if self.executing:
#            concurrency_checker.notify(self, self.handle_input)
            self.buffer += data
            self._handle_input(data) 

    #To be overridden by children
    #Called when the command is aborted (p.ex. due to timeout)
    def _abort(self):
        pass

    #To be overridden by children
    #Start the actual execution of the command
    def _execute(self):
        pass

    #To be overridden by children
    #handle the new input
    def _handle_input(self, data):
        pass

    def set_success_handler(self, handler):
        self.success_handler = handler

    def set_fail_handler(self, handler):
        self.fail_handler = handler

    def _success(self, result = None):
#        concurrency_checker.notify(self, self._success)
        self.executing = False
        self.log.info("Command %s with arguments %s executed successfully", self.PARSE_SPEC.split()[0], self.command_options)
        self._cleanup()
        if self.timeout_aborter.active():
            self.timeout_aborter.cancel()
        try:
            self.success_handler(result)
        except AttributeError:
            pass

    def _fail(self, reason = ""):
#        concurrency_checker.notify(self, self._fail, "temporary")
        self.executing = False
        self._cleanup()

        if self.retries > 0:
            self.retries -= 1
            self.execute()
        else:
            if self.timeout_aborter.active():
                self.timeout_aborter.cancel()
            self.log.warning("Command %s with arguments %s failed after retries: %s", self.PARSE_SPEC.split()[0], self.command_options, reason)
#            concurrency_checker.notify(self, self._fail, "permanent")
            try:
                if (not hasattr(self, 'failed_permanently')) or (not self.failed_permanently):
                    self.fail_handler(reason)
                    self.failed_permanently = True

            except AttributeError:
                pass

    #To be overridden by children
    #Do cleanup of any resources that you have allocated previously (both in success and fail cases)
    def _cleanup(self):
        pass


class CombinedCommand(Command):
    """This is a command composed of several other (basic) commands"""

    def _handle_input(self, data):
        try:
            self.current_cmd.handle_input(data)
        except AttributeError, e:
            pass

    def _abort(self):
        try:
            self.current_cmd.abort()
        except AttributeError, e:
            pass




class GoIntoFirmwareMenuCommand(Command):
    """Go from the freshly booted state into the firmware diagnostic menu. The command only works when the HDD is in the expected state"""

    REX_FW_MENU_PROMPT = re.compile("F3 T>")
    PARSE_SPEC = "go_into_fw_menu"

    def __init__(self, reactor, serial_port, command_options = {}):
        super(GoIntoFirmwareMenuCommand, self).__init__(reactor, serial_port, command_options, 3)

    def _execute(self):
        self.serial_port.write("\x1A")

    def _handle_input(self, data):
        if self.REX_FW_MENU_PROMPT.search(self.buffer):
            self._success() 

class GoIntoBootMenuCommand(Command):
    """From the firmware diagnostic menu, go to the boot menu. The HDD needs to be in the diagnostic menu, the change takes about 15 seconds"""

    REX_BOOT_MENU_PROMPT = re.compile("Boot Cmds:")
    PARSE_SPEC = "go_into_boot_menu"

    def __init__(self, reactor, serial_port, command_options = {}):
        super(GoIntoBootMenuCommand, self).__init__(reactor, serial_port, command_options, 15)
        self.hit_boot_menu_key = twisted.internet.task.LoopingCall(functools.partial(self.serial_port.write, 'UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU'))

    def _execute(self):
        self.hit_boot_menu_key.start(0.01)

    def _cleanup(self):
        if self.hit_boot_menu_key.running:
            self.hit_boot_menu_key.stop()

    def _handle_input(self, data):
        if self.REX_BOOT_MENU_PROMPT.search(self.buffer):
            self.hit_boot_menu_key.stop()
            self._success()

class CyclePowerCommand(Command):
    """Switch power off for three seconds using the relais attached to the RTS pin of the serial port, and then switch it on again. Resets the HDD"""

    PARSE_SPEC = "cycle_power"

    def __init__(self, reactor, serial_port, command_options = {}):
        super(CyclePowerCommand, self).__init__(reactor, serial_port, command_options, 10)
        self.turn_on_off = command_options["turn_on_off"]

    def _execute(self):
        def back_on():
#            onoff_port.setRTS(HDD_ON_RTS_STATE)
            self.turn_on_off(HDD_ON_RTS_STATE)
#            self.serial_port.setRTS(HDD_ON_RTS_STATE)
            self._success()
#        onoff_port.setRTS(not HDD_ON_RTS_STATE)
#        self.serial_port.setRTS(not HDD_ON_RTS_STATE)
        self.turn_on_off(not HDD_ON_RTS_STATE)
        self.reactor.callLater(3, back_on)

class SwitchTerminalEchoCommand(Command):
    """Switch the terminal echo. Used by the SetTerminalEchoCommand"""

    REX_TE_REPLY = re.compile("Echo (on|off)")
    PARSE_SPEC = "boot_switch_terminal_echo"

    def __init__(self, reactor, serial_port, command_options = {}):
        super(SwitchTerminalEchoCommand, self).__init__(reactor, serial_port, command_options, 1)
        
    def _execute(self):
        self.serial_port.write("TE\r")

    def _handle_input(self, data):
        if self.REX_TE_REPLY.search(self.buffer):
            state = self.REX_TE_REPLY.search(self.buffer).group(1)
            self._success(state == "on")


class SetTerminalEchoCommand(CombinedCommand):
    """Switch the terminal echo on or off. 
       Most commands have a different output when the terminal echo is enabled. 
       For our software to work properly, the echo has to be disabled, so change only if you know what you do.
    """
    REX_TE_REPLY = re.compile("Echo (on|off)")
    PARSE_SPEC = "boot_set_terminal_echo state[bool]"

    def __init__(self, reactor, serial_port, command_options = {}):
        super(SetTerminalEchoCommand, self).__init__(reactor, serial_port, command_options, 2)
        try:
            self.echo_state = command_options['state']
        except KeyError, e:
            raise SyntaxError("Mandatory parameter 'state' not given for command boot_set_terminal_echo")

        try:
            self.retries = command_options['retries']
        except KeyError, e:
            self.retries = 6

    def _execute(self):
        def switch_done(current_state):
            if self.echo_state == current_state:
                self._success(current_state)
            else:
                self.retries -= 1
                if self.retries > 0:
                    self.current_cmd = SwitchTerminalEchoCommand(self.reactor, self.serial_port)
                    self.current_cmd.set_fail_handler(self._fail)
                    self.current_cmd.set_success_handler(switch_done)
                    self.current_cmd.execute()
                else:
                    self.fail("exceeded retries")

        switch_done(not self.echo_state)

class SetAddressPointerCommand(Command):
    """Set the address pointer of the bootloader."""

    REX_AP_REPLY = re.compile("Addr Ptr = 0x([0-9A-F]{8})\r\n> ")
    PARSE_SPEC =  "boot_set_address_pointer address[int]"

    def __init__(self, reactor, serial_port, command_options = {}):
        super(SetAddressPointerCommand, self).__init__(reactor, serial_port, command_options, 1)
        try:
            self.address = command_options['address']
        except KeyError, e:
            raise SyntaxError("Mandatory parameter 'address' not given for command boot_set_address_pointer")

    def _execute(self):
        self.serial_port.write("AP %08X\r" %  self.address)

    def _handle_input(self, data):
        if self.REX_AP_REPLY.search(self.buffer):
            address = int(self.REX_AP_REPLY.search(self.buffer).group(1), 16)
            if address == self.address:
                self._success(address)
            else:
                self._fail("Written address not equal to returned address")

class WriteByteCommand(Command):
    """Write one byte of data to the location pointed to by the bootloader's address pointer and increment the address pointer"""

    REX_WT_REPLY = re.compile("\r\n> ")
    REX_WT_ECHO_REPLY = re.compile("Addr 0x([0-9A-F]{8}) = 0x([0-9A-F]{2})\r\n> ")
    REX_BAD_CMD = re.compile("Bad cmd: 0x([0-9A-F]{4})")
    PARSE_SPEC =  "boot_write_byte byte[int]"

    def __init__(self, reactor, serial_port, command_options = {}):
        super(WriteByteCommand, self).__init__(reactor, serial_port, command_options, 1, 0)
        try:
            self.byte = command_options['byte']
        except KeyError, e:
            raise SyntaxError("Mandatory parameter 'byte' not given for command boot_write_byte")

    def _execute(self):
        self.serial_port.write("WT %02X\r" %  self.byte)

    def _handle_input(self, data):
        if self.REX_BAD_CMD.search(self.buffer):
            self._fail("Menu desynchronized")
        elif self.REX_WT_ECHO_REPLY.search(self.buffer):
            match = self.REX_WT_ECHO_REPLY.search(self.buffer)
            address = int(match.group(1), 16) 
            value = int(match.group(2), 16)

            if not value == self.byte:
                self._fail("Written value not equal to returned one")

            self._success((address, value))

        elif self.REX_WT_REPLY.search(self.buffer):
            self._success()

class ReadByteCommand(Command):
    """Read one byte from the current address pointer of the bootloader, and increment the address pointer"""

    REX_RD_REPLY = re.compile("0x([0-9A-F]{2})\r\n> ")
    REX_RD_ECHO_REPLY = re.compile("Addr 0x([0-9A-F]{8}) = 0x([0-9A-F]{2})\r\n> ")
    REX_BAD_CMD = re.compile("Bad cmd: 0x([0-9A-F]{4})")
    PARSE_SPEC =  "boot_read_byte"

    def __init__(self, reactor, serial_port, command_options = {}):
        super(ReadByteCommand, self).__init__(reactor, serial_port, command_options, 1, 0)

    def _execute(self):
        self.serial_port.write("RD\r")

    def _handle_input(self, data):
        if self.REX_BAD_CMD.search(self.buffer):
            self._fail("Menu desynchronized")
        elif self.REX_RD_ECHO_REPLY.search(self.buffer):
            match = self.REX_RD_ECHO_REPLY.search(self.buffer)
            address = int(match.group(1), 16)
            value = int(match.group(2), 16)

            self._success((address, value))
        elif self.REX_RD_REPLY.search(self.buffer):
            self._success((None, int(self.REX_RD_REPLY.search(self.buffer).group(1), 16)))

class ReadDataCommand(CombinedCommand):
    """Read several bytes of memory from a specified location of the disc's memory"""

    PARSE_SPEC =  "boot_read_data address[int] length[int]"

    def __init__(self, reactor, serial_port, command_options = {}):
        super(ReadDataCommand, self).__init__(reactor, serial_port, command_options, 3600)
        try:
            self.address = command_options['address']
        except KeyError, e:
            raise SyntaxError("Mandatory parameter 'address' not given for command boot_read_data")
        try:
            self.length = command_options['length']
        except KeyError, e:
            raise SyntaxError("Mandatory parameter 'length' not given for command boot_read_data")
        self.data = []

    def _execute(self):
        def done_reading_byte(byte):
            self.data.append(byte[1])
            self.length = self.length - 1

            if self.length > 0:
                self.current_cmd = ReadByteCommand(self.reactor, self.serial_port)
                self.current_cmd.set_fail_handler(self._fail)
                self.current_cmd.set_success_handler(done_reading_byte)
                self.current_cmd.execute()
            else:
                self._success("".join(map(lambda x: chr(x), self.data)))

        def done_set_address(result):
            self.current_cmd = ReadByteCommand(self.reactor, self.serial_port, {'retries': 0, 'timeout': 0.1})
            self.current_cmd.set_fail_handler(self._fail)
            self.current_cmd.set_success_handler(done_reading_byte)
            self.current_cmd.execute()

        self.current_cmd = SetAddressPointerCommand(self.reactor, self.serial_port, {'address': self.address, 'retries': 10, 'timeout': 0.1})
        self.current_cmd.set_fail_handler(self._fail)
        self.current_cmd.set_success_handler(done_set_address)
        self.current_cmd.execute()


class RealignMenuCommand(Command):
    """Try to get the menu back in a known state"""

    REX_MENU_LINE = re.compile("Boot Cmds:")
    PARSE_SPEC = "boot_realign"

    def __init__(self, reactor, serial_port, command_options = {}):
        super(RealignMenuCommand, self).__init__(reactor, serial_port, command_options, 1)
        self.retries = 20

    def _execute(self):
        self.serial_port.write('?')

    def _handle_input(self, data):
        if self.REX_MENU_LINE.search(self.buffer):
            self._success()

class WriteDataCommand(CombinedCommand):
    """Write several bytes of data at a specified address in the disc's memory"""

    PARSE_SPEC =  "boot_write_data address[int] data[hexstring]"

    def __init__(self, reactor, serial_port, command_options = {}):
        super(WriteDataCommand, self).__init__(reactor, serial_port, command_options, 1)
        try:
            self.address = command_options['address']
        except KeyError, e:
            raise SyntaxError("Mandatory parameter 'address' not given for command boot_write_data")
        try:
            self.data = command_options['data']
        except KeyError, e:
            raise SyntaxError("Mandatory parameter 'data' not given for command boot_write_data")
        self.index = 0

    def _execute(self):
        def done_command(dummy):
            if self.index < self.data.__len__():
                self.current_cmd = WriteByteCommand(self.reactor, self.serial_port, {'byte': ord(self.data[self.index]), 'retries': 0, 'timeout': 0.1})
                self.index += 1
                self.current_cmd.set_fail_handler(self._fail)
                self.current_cmd.set_success_handler(done_command)
                self.current_cmd.execute()
            else:
                self._success()

        self.current_cmd = SetAddressPointerCommand(self.reactor, self.serial_port, {'address': self.address, 'retries': 10, 'timeout': 0.1})
        self.current_cmd.set_fail_handler(self._fail)
        self.current_cmd.set_success_handler(done_command)
        self.current_cmd.execute()

class WriteDataFromFileCommand(CombinedCommand):
    """Read data from a file and write it to the HDD's memory at the specified location"""

    PARSE_SPEC =  "boot_write_data_from_file address[int] file[string]"

    def __init__(self, reactor, serial_port, command_options = {}):
        super(WriteDataFromFileCommand, self).__init__(reactor, serial_port, command_options, 3600)
        try:
            self.address = command_options['address']
        except KeyError, e:
            raise SyntaxError("Mandatory parameter 'address' not given for command boot_write_data_from_file")
        try:
            self.file = command_options['file']
        except KeyError, e:
            raise SyntaxError("Mandatory parameter 'file' not given for command boot_write_data_from_file")

    def _execute(self):
        file = open(self.file, 'rb')
        data = file.read()
        file.close()

        self.current_cmd = BlockedWriteDataCommand(self.reactor, self.serial_port, {'address': self.address, 'data': data})
        self.current_cmd.set_fail_handler(self._fail)
        self.current_cmd.set_success_handler(self._success)
        self.current_cmd.execute()
        
class GoCommand(Command):
    """Instruct the bootloader to execute the code at the current address pointer"""

    REX_GO_REPLY = re.compile("Run: 0x([0-9A-F]{8})")
    PARSE_SPEC =  "boot_go"

    def __init__(self, reactor, serial_port, command_options = {}):
        super(GoCommand, self).__init__(reactor, serial_port, command_options, 1)

    def _execute(self):
        self.serial_port.write("GO\r")

    def _handle_input(self, data):
        if self.REX_GO_REPLY.search(self.buffer):
            self._success()

class WriteAndRunFileCommand(CombinedCommand):
    """Write data from a file into memory and then run the code at this location. 
       This function is very convenient to directly run binary programs (generate with objcopy) on the harddrive.
    """

    PARSE_SPEC = "boot_write_and_run_file address[int] file[string] is_thumb[bool]"

    def __init__(self, reactor, serial_port, command_options = {}):
        super(WriteAndRunFileCommand, self).__init__(reactor, serial_port, command_options, 3600)
        try:
            self.address = command_options['address']
        except KeyError, e:
            raise SyntaxError("Mandatory parameter 'address' not given for command boot_read_and_run_file")
        try:
            self.file = command_options['file']
        except KeyError, e:
            raise SyntaxError("Mandatory parameter 'file' not given for command boot_read_and_run_file")
        try:
            self.is_thumb = command_options['is_thumb']
        except KeyError, e:
            raise SyntaxError("Mandatory parameter 'is_thumb' not given for command boot_read_and_run_file")

    def _execute(self):
        def set_address_done(dummy):
            run_address = self.address
            if self.is_thumb:
                run_address |= 1

            self.current_cmd = RunFromAddressCommand(self.reactor, self.serial_port, {'address': run_address})
            self.current_cmd.set_fail_handler(self._fail)
            self.current_cmd.set_success_handler(self._success)
            self.current_cmd.execute()

        self.current_cmd = WriteDataFromFileCommand(self.reactor, self.serial_port, {'address': self.address, 'file': self.file})
        self.current_cmd.set_fail_handler(self._fail)
        self.current_cmd.set_success_handler(set_address_done)
        self.current_cmd.execute()

class RunFromAddressCommand(CombinedCommand):
    """Run a program at a memory address. Note that you need to add 1 if the code is THUMB code."""

    PARSE_SPEC = "boot_run address[int]"

    def __init__(self, reactor, serial_port, command_options = {}):
        super(RunFromAddressCommand, self).__init__(reactor, serial_port, command_options, 2)
        try:
            self.address = command_options['address']
        except KeyError, e:
            raise SyntaxError("Mandatory parameter 'address' not given for command boot_run")

    def _execute(self):
        def set_address_done(dummy):
            self.current_cmd = GoCommand(self.reactor, self.serial_port)
            self.current_cmd.set_fail_handler(self._fail)
            self.current_cmd.set_success_handler(self._success)
            self.current_cmd.execute()

        self.current_cmd = SetAddressPointerCommand(self.reactor, self.serial_port, {'address': self.address})
        self.current_cmd.set_fail_handler(self._fail)
        self.current_cmd.set_success_handler(set_address_done)
        self.current_cmd.execute()

class FwRebootCommand(Command):
    def __init__(self,reactor, serial_port, command_options = {}):
        super(FwRebootCommand, self).__init__(reactor, serial_port, command_options, 1)

    def _execute(self):
        self.serial_port.write('\x03')
        self._success()

class BatchCommand(CombinedCommand):
    """Run a list of commands, one after another. If a command fails, the whole batch command fails."""

    def __init__(self, reactor, serial_port, command_options = {}, timeout = 1000):
        super(BatchCommand, self).__init__(reactor, serial_port, command_options, timeout)
        self.commands = []

    def add_command(self, cmd):
        if not self.executing:
            self.commands.append(cmd)

    def _execute(self):
        def execute_next_command(result):
            if self.commands:
                self.current_cmd = self.commands.pop()
                print "BatchCommand: executing %s" % self.current_cmd.__class__.__name__
                self.current_cmd.set_success_handler(execute_next_command)
                self.current_cmd.set_fail_handler(self._fail)
                self.current_cmd.execute()
            else:
                self._success(result)
                

        self.commands.reverse()
        execute_next_command(None)

    def _abort(self):
        self.current_cmd.abort()

class ResetCommand(BatchCommand):
    """Do a reset of the HDD by toggling power, and then go through the menus until the boot menu."""

    PARSE_SPEC = "reset"

    def __init__(self, reactor, serial_port, command_options = {}):
        super(ResetCommand, self).__init__(reactor, serial_port, command_options, 60)
        self.add_command(CyclePowerCommand(self.reactor, self.serial_port))
        self.add_command(DelayCommand(self.reactor, self.serial_port, {'delay': 5}))
        self.add_command(GoIntoFirmwareMenuCommand(self.reactor, self.serial_port))
        self.add_command(FwRebootCommand(self.reactor, self.serial_port))
        self.add_command(GoIntoBootMenuCommand(self.reactor, self.serial_port))
        self.add_command(DelayCommand(self.reactor, self.serial_port, {'delay': 2}))
        self.add_command(SetTerminalEchoCommand(self.reactor, self.serial_port, {'state': True}))

class SoftResetCommand(BatchCommand):
    """Do a soft reset from the firmware menu, and then go through the menus until the boot menu."""

    PARSE_SPEC = "softreset"

    def __init__(self, reactor, serial_port, command_options = {}):
        super(SoftResetCommand, self).__init__(reactor, serial_port, command_options, 60)
        self.add_command(GoIntoFirmwareMenuCommand(self.reactor, self.serial_port))
        self.add_command(FwRebootCommand(self.reactor, self.serial_port))
        self.add_command(GoIntoBootMenuCommand(self.reactor, self.serial_port))
        self.add_command(DelayCommand(self.reactor, self.serial_port, {'delay': 2}))
        self.add_command(SetTerminalEchoCommand(self.reactor, self.serial_port, {'state': True}))


class ResetBootMenuCommand(BatchCommand):
    """Do a soft reset from the firmware menu, and then go through the menus until the boot menu."""

    PARSE_SPEC = "reset_bootmenu"

    def __init__(self, reactor, serial_port, command_options = {}):
        super(ResetBootMenuCommand, self).__init__(reactor, serial_port, command_options, 60)
        self.add_command(CyclePowerCommand(self.reactor, self.serial_port, command_options))
        self.add_command(GoIntoBootMenuCommand(self.reactor, self.serial_port))
        self.add_command(DelayCommand(self.reactor, self.serial_port, {'delay': 2}))
        self.add_command(SetTerminalEchoCommand(self.reactor, self.serial_port, {'state': True}))



class DelayCommand(CombinedCommand):
    """Complete command execution after _delay_ seconds. Useful in conjunction with the BatchCommand to insert waiting times."""

    PARSE_SPEC = "delay delay[int]"

    def __init__(self, reactor, serial_port, command_options):
        try:
            self.delay = command_options['delay']
        except KeyError, e:
            raise SyntaxError("Mandatory parameter 'delay' not given for command delay")

        super(DelayCommand, self).__init__(reactor, serial_port, command_options, self.delay + 10)

    def _execute(self):
        self.deferred = self.reactor.callLater(self.delay, self._success)

    def _cleanup(self):
        if self.deferred and self.deferred.active():
            self.deferred.cancel()

class BlockedWriteDataCommand(CombinedCommand):
    """Write data lieke the WriteDataCommand, but use blocks and only retry to write the block that has not been written successfully."""

    PARSE_SPEC = "boot_write_blocked_data address[int] data[hexstring] (blocksize[int]) (max_write_retries[int])"

    def __init__(self, reactor, serial_port, command_options):
        super(BlockedWriteDataCommand, self).__init__(reactor, serial_port, command_options, 3600, 0)
        try:
            self.address = command_options['address']
        except KeyError, e:
            raise SyntaxError("Mandatory parameter 'address' not given for command boot_write_blocked_data")
        try:
            self.data = command_options['data']
        except KeyError, e:
            raise SyntaxError("Mandatory parameter 'data' not given for command boot_write_blocked_data")
        try:
            self.blocksize = command_options['blocksize']
        except KeyError, e:
            self.blocksize = 16
        try:
            self.max_write_retries = command_options['max_write_retries']
        except KeyError, e:
            self.max_write_retries = 10

        self.index = 0

    def _execute(self):
        def write_failed(reason = ""):
                self._fail("Write of block at address 0x%x failed after %d retries with reason %s" % (self.address + self.index, self.max_write_retries, reason))

        def write_successful(dummy):
            self.index = self.index + self.blocksize

            if self.index >= self.data.__len__():
                self._success()
            else:
                next_write()

        def next_write(dummy = None):
            self.current_cmd = WriteDataCommand(self.reactor, self.serial_port, {'address': self.address + self.index, 'data': self.data[self.index:self.index + self.blocksize], 'retries': self.max_write_retries})
            self.current_cmd.set_fail_handler(write_failed)
            self.current_cmd.set_success_handler(write_successful)
            self.current_cmd.execute()

        next_write()

class BootCommand(Command):
    """Execute the normal disc firmware. This command does not seem very useful, as it resets the disc."""

    REX_BT_REPLY = re.compile("Booting from serial FLASH code")
    PARSE_SPEC = "boot_boot"

    def __init__(self, reactor, serial_port, command_options = {}):
        super(BootCommand, self).__init__(reactor, serial_port, command_options, 1)

    def _execute(self):
        self.serial_port.write("BT\r")

    def _handle_input(self, data):
        if self.REX_BT_REPLY.search(self.buffer):
            self._success()

class SetBaudrateCommand(Command):
    """Set another baudrate in the boot menu."""

    PARSE_SPEC = "boot_set_baudrate baudrate[int]"
    DIVISOR_TABLE = {9600   : 0x28b, 
                     19200  : 0x146,
                     38400  : 0xa3,
                     57600  : 0x6d,
                     115200 : 0x36,
                     230400 : 0x1b,
                     460800 : 0xe,
                     625000 : 0xa,
                     921000 : 7,
                     921600 : 7,
                     1228000: 5,
                     1250000: 5}

    def __init__(self, reactor, serial_port, command_options = {}):
        super(SetBaudrateCommand, self).__init__(reactor, serial_port, command_options, 5)
        try:
            self.baudrate = command_options['baudrate']
        except KeyError, e:
            raise SyntaxError("Mandatory parameter 'address' not given for command boot_run")
        try:
            self.divisor = self.DIVISOR_TABLE[self.baudrate]
        except KeyError, e:
            raise SyntaxError("Parameter 'baudrate' has unexpected value. Must be one of the baudrate constants.")

        if not self.baudrate in [50, 75, 110, 134, 150, 200, 300, 600, 1200, 1800, 2400, 4800, 9600, 19200, 38400, 57600, 115200, 230400, 460800, 500000, 576000, 921600, 1000000, 1152000, 1500000, 2000000, 2500000, 3000000, 3500000, 4000000]:
            raise SyntaxError("Parameter 'baudrate' found for HDD, but not for Python serial port.")

    def _execute(self):
        self.serial_port.write("BR %X\r" % self.divisor)
#        self.serial_port._serial.close()
#        self.serial_port._serial = serial.Serial('/dev/ttyUSB0', self.baudrate)
#        self.serial_port._serial.setRTS(True)
        self.serial_port.flush()
        self.serial_port._serial.baudrate = self.baudrate
#        self.serial_port.setBaudRate(self.baudrate)
        self.serial_port.setRTS(True)


    def _handle_input(self, data):
        print "Received data: '%s'" % data
        self._success()
        



COMMANDS = [GoIntoFirmwareMenuCommand, 
            GoIntoBootMenuCommand, 
            CyclePowerCommand, 
            SetTerminalEchoCommand, 
            SetAddressPointerCommand, 
            WriteByteCommand, 
            ReadByteCommand,
            GoCommand,
            RunFromAddressCommand,
            WriteDataCommand,
            WriteDataFromFileCommand,
            ReadDataCommand,
            WriteAndRunFileCommand,
            ResetCommand,
			SoftResetCommand,
            BootCommand,
            BlockedWriteDataCommand,
            RealignMenuCommand,
            ResetBootMenuCommand,
            SetBaudrateCommand]


            

                
def line_wrap(text, max_length = 80):
    """Split a long text line into multiple lines on whitespaces."""
    output = []
    while text.__len__() >= max_length:
        split = text.rfind(' ', 0, max_length - 1)
        output.append(text[:split])
        text = text[split + 1:]

    return output



class HddMonitor(twisted.internet.protocol.Protocol):
    DISCSTATE_BOOTED = 0
    DISCSTATE_FW_MENU = 1
    DISCSTATE_BOOT_MENU = 2
    DISCSTATE_GDB = 3


    def __init__(self, reactor, next_handler, onoff_serial_port, serial_port_path, baudrate = 9600, bytesize = EIGHTBITS, parity = PARITY_NONE, stopbits = STOPBITS_ONE, xonxoff = 0, rtscts = 0):
        self.log = logging.getLogger('gdbstubs.HddMonitor')
        self.reactor = reactor
        self.next_handler = next_handler

        def write(obj, data):
            logging.getLogger('gdbstubs.SerialPort').debug("Sending data to serial port: '%s'", data)
            f = open('/tmp/serial.log', 'a+')
            f.write(data)
            f.close()
            obj._write(data)
        self.serial_port = twisted.internet.serialport.SerialPort(self, serial_port_path, reactor, baudrate, bytesize, parity, stopbits, xonxoff, rtscts)
        self.serial_port._write = self.serial_port.write
        self.serial_port.write = types.MethodType(write, self.serial_port)
        self.onoff_serial_port = serial.Serial(onoff_serial_port)
        self.command_port = SerialPortMultiplexer.UDPPort(1234, twisted.internet.reactor, self.receive_command)
        self.current_command = None
        self.verbose_terminal = True
    #
    def dataReceived(self, data):
        self.log.debug("Received data from serial port: '%s'", data)

        if self.current_command and self.current_command.executing:
            for byte in data:
                self.current_command.handle_input(byte)

                if hasattr(self, 'verbose_terminal') and self.verbose_terminal:
                    self.next_handler(byte)
        else:
            self.next_handler(data)

    def write(self, data):
        self.log.debug("Sending data to serial port: '%s'", data)
        self.serial_port.write(data)

    def receive_command(self, data):
        def fail_handler(reason = ""):
            self.command_port.sendDatagram("FAILED: %s  > " % reason)

        def success_handler(result):
            if result is None:
                self.command_port.sendDatagram("OK     > ")
            elif isinstance(result, (int, long)):
                self.command_port.sendDatagram("OK, result = 0x%x > " % result)
            elif isinstance(result, basestring):
                hex_string = " ".join(map(lambda x: "%02X" % ord(x), result))
                self.command_port.sendDatagram("OK, result = %s > " % hex_string)
            elif isinstance(result, tuple):
                msg = "OK, result = ("
                for t in result:
                    if isinstance(t, (int, long)):
                        msg += "0x%x, " % t
                    else:
                        msg += "%s, " % t
                self.command_port(msg + ") > ")
            else:
                self.command_port.sendDatagram("OK, unknown result type > ")

        data_arr = data.split()

        if not data_arr:
            return
        cmd = data_arr[0]

        if cmd.strip() == "?":
            self.command_port.sendDatagram("Usage: \r\n")
            for command in COMMANDS:
                self.command_port.sendDatagram("\t+ " + command.PARSE_SPEC + "\r\n")
                self.command_port.sendDatagram("\r\n".join(map(lambda x: "\t\t" + x, line_wrap(command.__doc__.replace('\n', ' '), 60))) + "\r\n")

            self.command_port.sendDatagram("> ")
            return
        elif cmd.strip() == "cancel":
            
            self.command_port.sendDatagram("OK, canceling all pending commands > ")
            
            if self.current_command:
                self.current_command.abort()
            return
       
        try: 
            for command in COMMANDS:
                if command.PARSE_SPEC.split()[0] == cmd:
                    self.log.debug("Received command %s", cmd)
                    self.current_command = command(self.reactor, self.serial_port, dict(chain({"turn_on_off": lambda x: self.onoff_serial_port.setRTS(x)}.items(), CommandParser(command.PARSE_SPEC).parse(data).items())))
                    self.current_command.set_success_handler(success_handler)
                    self.current_command.set_fail_handler(fail_handler)
                    self.current_command.execute()
                    return
        except ValueError, e:
            print e
            self.command_port.sendDatagram("ERROR: Value error in command > ")
            return

        self.command_port.sendDatagram("ERROR: command not recognized > ")

class SerialPortMultiplexer:
    class UDPPort(twisted.internet.protocol.DatagramProtocol):
        def __init__(self, listen_port, reactor, received_packet_handler):
            self.log = logging.getLogger('gdbstubs.UDPPort')
            self.local_port = listen_port
            self.reactor = reactor
            self.received_packet_handler = received_packet_handler
            self.remote_address = None
            self.remote_socket = None
            self.log.info("Listening on local UDP port %d", listen_port)
            self.queue = []
            reactor.listenUDP(listen_port, self)

        def datagramReceived(self, data, (host, port)):
            if not self.remote_address:
                self.log.info("Remote machine connected to port %d from %s:%d", self.local_port, host, port)
                self.remote_address = (host, port)
                for item in self.queue:
                    self.log.debug("Sending queued packet from local UDP socket %d to %s:%d: '%s'", self.local_port, self.remote_address[0], self.remote_address[1], item)
                    self.transport.write(item, self.remote_address)
                self.queue = []

            elif self.remote_address != (host, port):
				self.log.info("Remote machine %s:%d connected to local UDP socket %d that was listening to %s:%d before; now listening to new machine", host, port, self.local_port, self.remote_address[0], self.remote_address[1])
				self.remote_address = (host, port)

            if data:
                self.log.debug('Received UDP datagram on port %d: \'%s\'', self.local_port, data)
                self.received_packet_handler(data)

        def sendDatagram(self, data):
            if not self.remote_address:
                self.log.debug("Queueing packet on local UDP socket %d: \'%s\'", self.local_port, data)
                self.queue.append(data)
            else:
                self.log.debug("Sending packet from local UDP socket %d to %s:%d: '%s'", self.local_port, self.remote_address[0], self.remote_address[1], data)
                self.transport.write(data, self.remote_address)

    def __init__(self, udp_ports, onoff_serial_port, serial_port, baudrate = 9600, bytesize = EIGHTBITS, parity = PARITY_NONE, stopbits = STOPBITS_ONE, xonxoff = 0, rtscts = 0):
        self.log = logging.getLogger('gdbstubs.SerialPortMultiplexer')
        print("Created onoff port")
        def forward_to_udp(data):
            for udp_port in self.output_protocols:
                udp_port.sendDatagram(data)
        self.monitor = HddMonitor(twisted.internet.reactor, forward_to_udp, onoff_serial_port, serial_port, baudrate, bytesize, parity, stopbits, xonxoff, rtscts)
        self.output_protocols = []
        for port in udp_ports:
            udp_port = SerialPortMultiplexer.UDPPort(port[0], twisted.internet.reactor, self.monitor.write)
            if port.__len__() > 1 and port[1]:
                udp_port._sendDatagram = udp_port.sendDatagram
                udp_port.sendDatagram = types.MethodType(functools.partial(lambda filter_func, self, data: filter_func(self._sendDatagram, data), port[1]), udp_port) 
            if port.__len__() > 2 and port[2]:
                udp_port._datagramReceived = udp_port.datagramReceived
                udp_port.datagramReceived = types.MethodType(functools.partial(lambda filter_func, self, data, address: filter_func(self._datagramReceived, data, address), port[2]), udp_port) 
            
#udp_port.sendDatagram = types.MethodType(functools.partial(port[1], lambda x, y, func:  sys.stdout.write("Writing %s with parameter %s\n" % ( func, y ))), udp_port) #func(y)), udp_port) #functools.partial(port[1], lambda x, y, z: functools.partial(z, udp_port._sendDatagram)(y)), udp_port)

            self.output_protocols.append(udp_port)

                    

