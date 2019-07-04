# -------------------------------------------------------------------------------------------------------------------------------------------------------------
# Bluetooth scanning for BlueBorne attack
# @Authors:  Authors: Shir, Hodaya and Alexey
# @Version: 1.0
# @Date 07.2019
# -------------------------------------------------------------------------------------------------------------------------------------------------------------
from classes.deviceslist import devices
from prettytable import PrettyTable
from bluetooth import *
import argparse

# global variables
devicelookup = devices.get_devices()        # list of devices according to manufacturer

# function search manufacturer of device
def is_device_vulnerable(addr):
    manufacturers = devicelookup["ANDROIDS"]
    for manufacturer in manufacturers:
        # search manufacturer
        lookups = manufacturers[manufacturer]
        for address in lookups:
            if (address == addr[:8]):                       # first 4 bytes of bluetooth address
                return True, str(manufacturer)
    return False, 'Don\'t know'


# function that scans bluetooth devices
def FindDevices(_duration):
    # use table to display devices
    BTable = PrettyTable(['Index', 'Bluetooth Address', 'Bluetooth Name', 'Manufacturer', 'Vulnerable'])
    nearby_devices = discover_devices(duration = _duration)
    for (i, address) in enumerate(nearby_devices):
        vulnerable, company = is_device_vulnerable(address)
        if (vulnerable):
            BTable.add_row([str(i+1), address, lookup_name(address), company, 'Yes'])
        else:
            BTable.add_row([str(i+1), address, lookup_name(address), company, 'None'])
    print BTable


if __name__ == "__main__":
    # construct the argument and parse the arguments
    ap = argparse.ArgumentParser()
    ap.add_argument("-d", "--duration", type = int, default = 3,
                    help="duration for finding bluetooth devices command")
    args = vars(ap.parse_args())

    # scan devices
    FindDevices(args["duration"])
    print ("\n\x1b[1;35m                             ")
    print ("    _    (^)                             ")
    print ("   (_\   |_|                             ")
    print ("    \_\  |_|                             ")
    print ("    _\_\,/_|                             ")
    print ("   (`\(_|`\|                             ")
    print ("  (`\,)  \ \'                            ")
    print ("   \,)   | |                             ")
    print ("     \__(__|\x1b[0m                      ")
    print ("                                         ")
    print ("\x1b[1;35m        Peace brothers and sisters!       ")
    print ("\n                                       ")
