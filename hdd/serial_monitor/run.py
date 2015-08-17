# -*- coding: utf-8 -*-
import sys
sys.path.append("/home/zaddach/projects/aurelien-s2e/hdd-svn/scripts/")
sys.path.append("/home/zaddach/projects/aurelien-s2e/hdd-svn/gdbstubs/")
import logging
logging.basicConfig(level = logging.INFO)
logging.getLogger().setLevel(logging.INFO)
#logging.basicConfig(level = logging.DEBUG)
#logging.getLogger().setLevel(logging.DEBUG)
import multiplexer
import serial
import twisted
gdbfilter = multiplexer.GDBProtocolFilter()
not_gdb_filter = multiplexer.NotGDBProtocolFilter()
class TerminalInputFilter(object):
    def __init__(self):
        self.escaped = False
        self.hex_num = []

    def filter(self, next_handler, data, address):
        for c in data:
            if self.escaped and not self.hex_num is None:
                if not c in '0123456789ABCDEFabcdef':
                    self.hex_num = None
                    self.escaped = False
                    return
                self.hex_num.append(c)
                if self.hex_num.__len__() >= 2:
                    next_handler(chr(int("".join(self.hex_num), 16)), address)
                    self.escaped = False
                    self.hex_num = None
            elif self.escaped and c == 'r':
                next_handler('\r', address)
                self.escaped = False
            elif self.escaped and c == 'n':
                next_handler('\n', address)
                self.escaped = False
            elif self.escaped and c == '\\':
                next_handler('\\', address)
                self.escaped = False
            elif self.escaped and c == 'x':
                self.hex_num = []
            elif c == '\\':
                next_handler('', address)
                self.escaped = True
            elif c == '\n':
                next_handler('', address)
                self.escaped = False
            elif c == '\r':
                next_handler('', address)
                self.escaped = False
            else:
                next_handler(c, address)
                self.escaped = False
                

#mux = multiplexer.SerialPortMultiplexer([(2010, None, TerminalInputFilter().filter), (2011, gdbfilter.filter)], sys.argv[1], 38400)
mux = multiplexer.SerialPortMultiplexer([(2010, None, not_gdb_filter.filter), (2011, gdbfilter.filter)], sys.argv[2], sys.argv[1], 38400)
twisted.internet.reactor.run()
