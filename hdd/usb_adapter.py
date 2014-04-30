#!/usr/bin/env python

import logging
import usb
import argparse
import struct

USB_VENDOR_ID = 0x152d
USB_PRODUCT_ID = 0x2338

log = logging.getLogger(__name__)

class UsbAtaBridgeException(Exception):
    pass

class DeviceNotFoundException(UsbAtaBridgeException):
    pass

def find_device():
    dev = usb.core.find(idVendor = USB_VENDOR_ID, idProduct = USB_PRODUCT_ID)

    if dev is None:
        raise DeviceNotFoundException()

    return dev

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", dest = "verbosity", default = 1, action = "count", help = "Increase verbosity (specify multiple times to increase more)")

    args = parser.parse_args()

    if args.verbosity >= 3:
        logging.basicConfig(level = logging.DEBUG)
    elif args.verbosity >= 2:
        logging.basicConfig(level = logging.INFO)
    if args.verbosity >= 1:
        logging.basicConfig(level = logging.WARN)

    return args

#def send_mass_storage_command(


class DeviceNotFoundException(usb.core.USBError):
    pass

class UsbScsiDevice():
    DIRECTION_IN = 0x80
    DIRECTION_OUT = 0x00
    def __init__(self):
        self._dev = usb.core.find(idVendor = USB_VENDOR_ID, idProduct = USB_PRODUCT_ID)
        if self._dev is None:
            raise DeviceNotFoundException()

        cfg = self._dev.get_active_configuration()

        #First check if kernel driver is active and disable it
        if not cfg is None and self._dev.is_kernel_driver_active(cfg.index):
            self._dev.detach_kernel_driver(cfg.index)

#        self._dev.reset()
        self._dev.set_configuration()

        interface_number = cfg[(0, 0)].bInterfaceNumber
        alternate_setting = usb.control.get_interface(self._dev, interface_number)
        interface = usb.util.find_descriptor(cfg, bInterfaceNumber = interface_number, bAlternateSetting = alternate_setting)
        self._ep_out = usb.util.find_descriptor(interface, custom_match = lambda e: usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_OUT)
        self._ep_in = usb.util.find_descriptor(interface, custom_match = lambda e: usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_IN)
        self._tag = 1

        port = self.get_registers(0x720f, 1)
        if port[0] & 0x44 == 0x04:
            self._port = 0
        elif port[0] & 0x44 == 0x40:
            self._port = 1
        elif port[0] & 0x44 == 0x44:
            raise RuntimeError("Both ports of the controller are used, decide for one (How is up to you to figure out)")
        else:
            raise RuntimeError("No device connected, your bad")

    def get_max_lun(self):
        reply = self._dev.ctrl_transfer(0xa1, 0xfe, 0, 0, 256) #GET MAX LUN
        assert(len(reply) == 1)
        return reply[0]

    def send_mass_storage_command(self, lun, direction, data_length, cdb):
        request = struct.pack("<4sLLBBB", "USBC".encode(encoding = 'ascii'), self._tag, data_length, direction, lun, len(cdb)) + \
                  cdb + \
                  bytes([0] * (16 - len(cdb))) #Fill packet to 31 bytes with 0

        self._tag += 1

        log.debug("Sending Mass Storage command: %s", " ".join(["%02x" % x for x in request]))
        self._ep_out.write(request)

    def receive_mass_storage_response(self, size):

        data = self._ep_in.read(size)
        reply = self._ep_in.read(13)
        assert(len(reply) == 13)
        header = struct.unpack("<4sLLB", reply)
        log.debug("Requested %d bytes of response, received %d bytes: tag = 0x%08x, data_residue = %d, status = 0x%02x", 
                  size, len(data), header[1], header[2], header[3])

        assert(header[0] == "USBS".encode(encoding = 'ascii'))
        assert(header[1] == self._tag - 1)
        #TODO: Check return code and throw error

        return data

    def get_registers(self, addr, size):
        cdb = bytes([0xdf, 0x10, 0x00, (size >> 8) & 0xff, size & 0xff, 0x00, (addr >> 8) & 0xff, addr & 0xff, 0x00, 0x00, 0x00, 0xfd]) 
        self.send_mass_storage_command(0, UsbScsiDevice.DIRECTION_IN, size, cdb)
        return self.receive_mass_storage_response(size)


    def send_ata_command(self, command, is_direction_out, xfer_len, sector_count, features, lba, device):
        if is_direction_out:
            direction_byte = 0x00
            direction = UsbScsiDevice.DIRECTION_OUT
        else:
            direction_byte = 0x10 
            direction = UsbScsiDevice.DIRECTION_IN
        cdb = bytes([0xdf, direction_byte, 0x00, 
                    (xfer_len >> 8) & 0xff, xfer_len & 0xff, 
                    features, 
                    sector_count,
                    lba & 0xff, (lba >> 8) & 0xff, (lba >> 16) & 0xff,
                    device | (self._port == 0 and 0xa0 or 0xb0),
                    command])
        self.send_mass_storage_command(0, direction, xfer_len * 512, cdb)

    def identify_device(self):
        dev.send_ata_command(0xec, False, 512, 1, 0, 0, 0)
        return dev.receive_mass_storage_response(512)

    def read(self, lba, sector_count):
        pass
        

def main():
    args = parse_args()

    dev = UsbScsiDevice()
#    dev.send_ata_command(0xec, False, 512, 1, 0, 0, 0)
    dev.send_ata_command(0x25, True, 0, 0, 0, 0, 0)
    dev.send_ata_command(0x25, False, 512, 1, 0, 0, 0)
    dev.receive_mass_storage_response(512)


#    dev._ep_out.write([0x55, 0x53, 0x42, 0x43, #Signature
#                  0x01, 0x00, 0x00, 0x00, #TAG = 0x00000001
#                  0x24, 0x00, 0x00, 0x00, #data transfer length = 36
#                  0x80,                   #flags = 0x80
#                  0x00,                   #LUN = 0
#                  0x06,                   #CDB length = 6
#                  #========================================= CDB starts here
#                  0x12,                   #Opcode = 0x12 (Inquiry)
#                  0x00,                   #CMDT = 0, EVPD = 0
#                  0x00, 0x00,             #?
#                  0x24,                   #Allocation length
#                  0x00,                   #Control = 0x00
#                  0x00, 0x00, 0x00, 0x00, #?
#                  0x00, 0x00, 0x00, 0x00, #?
#                  0x00, 0x00])
                  


if __name__ == "__main__":
    main()
