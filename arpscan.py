__copyright__ = "Copyright 2017 Tyler Jordan"
__version__ = "0.1.1"
__email__ = "tjordan@juniper.net"

import datetime
import platform
import os
import netaddr
import jxmlease
import getopt

from jnpr.junos import *
from jnpr.junos.exception import *
from utility import *

from ncclient import manager  # https://github.com/ncclient/ncclient
from ncclient.transport import errors
from prettytable import PrettyTable
from pprint import pprint
from os import path
from operator import itemgetter
from netaddr import IPAddress, IPNetwork

# Paths
dir_path = ''

# Params
mypwd = ''
myuser = ''

# Detect the system enviornment (Windows/Linux/MAC)
def detect_env():
    """ Purpose: Detect OS and create appropriate path variables
    :param: None
    :return: None
    """
    global dir_path
    dir_path = os.path.dirname(os.path.abspath(__file__))

# Handles arguments provided at the command line
def getargs(argv):
    # Global variables
    global ip1
    global ip2

    # Interprets and handles the command line arguments
    try:
        opts, args = getopt.getopt(argv, "ha:b:", ["ip1=", "ip2="])
    except getopt.GetoptError:
        print 'jscan.py -a <host1> -b <host2>'
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print 'SYNTAX: arpscan -a <host1> -b <host2>'
            print '  -a : (REQUIRED) First host IP'
            print '  -b : (REQUIRED) Second host IP'
            sys.exit()
        elif opt in ("-a", "--ip1"):
            ip1 = arg
        elif opt in ("-b", "--ip2"):
            ip2 = arg
            return arg

# A function to open a connection to devices and capture any exceptions
def connect(ip):
    """ Purpose: Attempt to connect to the device

    :param ip:          -   IP of the device
    :param indbase:     -   Boolean if this device is in the database or not, defaults to False if not specified
    :return dev:        -   Returns the device handle if its successfully opened.
    """
    dev = Device(host=ip, user=myuser, passwd=mypwd, auto_probe=True)
    # Try to open a connection to the device
    try:
        dev.open()
    # If there is an error when opening the connection, display error and exit upgrade process
    except ConnectRefusedError as err:
        message = "Host Reachable, but NETCONF not configured."
        stdout.write("Connect Fail - " + message + " |")
        return False
    except ConnectAuthError as err:
        message = "Unable to connect with credentials. User:" + username
        stdout.write("Connect Fail - " + message + " |")
        return False
    except ConnectTimeoutError as err:
        message = "Timeout error, possible IP reachability issues."
        stdout.write("Connect Fail - " + message + " |")
        return False
    except ProbeError as err:
        message = "Probe timeout, possible IP reachability issues."
        stdout.write("Connect Fail - " + message + " |")
        return False
    except ConnectError as err:
        message = "Unknown connection issue."
        stdout.write("Connect Fail - " + message + " |")
        return False
    except Exception as err:
        message = "Undefined exception."
        stdout.write("Connect Fail - " + message + " |")
        return False
    # If try arguments succeeded...
    else:
        return dev

# Function for collecting the ARP information from the Juniper devices
def get_arp_table(ip):
    # ARP list dictionary
    arp_mac_listdict = []
    # Open a connection to this IP
    dev = connect(ip)
    if dev:
        print "Connected to {0}".format(ip)
        # Capture ARP tables from both devices
        arpsw_response = jxmlease.parse_etree(dev.rpc.get_arp_table_information())
        for arptableentry in arpsw_response['arp-table-information']['arp-table-entry']:
            #print "MAC: {0} -> IP: {1}".format(arptableentry['mac-address'].encode('utf-8'), arptableentry['ip-address'].encode('utf-8'))
            arp_mac_listdict.append({'ip': arptableentry['ip-address'].encode('utf-8'), 'mac': arptableentry['mac-address'].encode('utf-8')})
    # Return the listdict
    return arp_mac_listdict

# A function to capture ARP tables and compare them
def arpscan():
    print "-"*22
    print "- Loading ARP Tables -"
    print "-"*22

    # CSV Testing Code
    router_a = 'arps-orig.csv'
    router_b = 'arps-mod.csv'
    # Loads the following CSV into a list dictionary
    arp_mac_listdict1 = csvListDict(os.path.join(dir_path, router_a))
    if arp_mac_listdict1:
        print "Successfully loaded Test ARP table from {0}".format(router_a)
        #print_listdict(arp_mac_listdict1)
        arp_mac_listdict2 = csvListDict(os.path.join(dir_path, 'arps-mod.csv'))
        if arp_mac_listdict2:
            print "Successfully loaded Test ARP table from {0}".format(router_b)
            #print_listdict(arp_mac_listdict2)
            compare_arp_tables(arp_mac_listdict1, arp_mac_listdict2, ip1, ip2)
        else:
            print "Issue populating ARP table from {0}".format(router_b)
    else:
        print "Issue populating ARP table for {0}".format(router_a)

    # Router Code
    '''
    if ip1:
        print "Retrieving ARP table from {0}".format(ip1)
        arp_mac_listdict1 = get_arp_table(ip1)
        print "Successfully captured ARP table from {0}".format(ip1)
        #print_listdict(arp_mac_listdict1)
        if ip2:
            print "Retrieving ARP table from {0}".format(ip2)
            arp_mac_listdict2 = get_arp_table(ip2)
            print "Successfully captured ARP table from {0}".format(ip2)
            #print_listdict(arp_mac_listdict2)
            compare_arp_tables(arp_mac_listdict1, arp_mac_listdict2, ip1, ip2)
        else:
            print "Issue populating ARP table for {0}".format(ip1)
    else:
        print "Issue populating ARP table for {0}".format(ip2)
    '''

# Custom function for comparing ARP tables
def compare_arp_tables(arptab1, arptab2, ip1, ip2):
    # Compare ARP Tables
    match_count = 0
    discrep_list = []
    missing_on_a_list = []
    missing_on_b_list = []
    # Compares A against B
    for arp1 in arptab1:
        no_match= True
        for arp2 in arptab2:
            # If these records have the same IP
            if arp1['ip'] == arp2['ip']:
                # If these records have the same MAC
                if arp1['mac'] == arp2['mac']:
                   # Exact Match
                   match_count += 1
                # If these records have different MACs
                else:
                    #print "MAC Discrepancy - IP: {0} | {1} MAC: {2} | {3} MAC: {4}".format(arp1['ip'], ip1, arp1['mac'], ip2, arp2['mac'])
                    discrep_list.append("IP: " + arp1['ip'] + " | MAC on A: " + arp1['mac'] + " | MAC on B: " + arp2['mac'])
                no_match = False
                break
            # If these records have different IPs
            else:
                # Move onto next IP...
                pass
        if no_match:
            #print "Missing ARP on {0} | ARP: {1}|{2}".format(ip2, arp1['ip'], arp1['mac'])
            missing_on_b_list.append("IP: " + arp1['ip'] + " | MAC: " + arp1['mac'])
    # Compares B against A
    for arp2 in arptab2:
        no_match = True
        for arp1 in arptab1:
            if arp2['ip'] == arp1['ip']:
                no_match = False
                break
            else:
                pass
        if no_match:
            #print "Missing ARP on {0} | ARP: {1}|{2}".format(ip1, arp2['ip'], arp2['mac'])
            missing_on_a_list.append("IP: " + arp2['ip'] + " | MAC: " + arp2['mac'])

    print "\n" + "-"*22
    print "- Comparison Results -"
    print "-"*22
    print "  - ARP Discrepancies -"
    for item in discrep_list:
        print "\t" + item
    print "-"*100
    print "  - ARPs on B, NOT on A -"
    for item in missing_on_a_list:
        print "\t" + item
    print "-"*100
    print "  - ARPs on A, NOT on B -"
    for item in missing_on_b_list:
        print "\t" + item
    print "-"*100
    print "-----------------------------"
    print "Total Matching ARPs: {0}".format(str(match_count))
    print "-----------------------------\n"

# A function to display a list dict in a "pretty" format
def print_listdict(list_dict):
    """ 
        Purpose: Display a table showing contents of the list dictionary.
        Returns: Nothing
    """
    t = PrettyTable(['IP', 'MAC'])
    for host_dict in list_dict:
        # print device
        t.add_row([host_dict['ip'], host_dict['mac']])
    print t
    print "Total Entries: {0}".format(len(list_dict))

# START OF SCRIPT #
if __name__ == '__main__':
    # Detect environment and capture arguments
    detect_env()
    getargs(sys.argv[1:])

    # Credentials
    myfile = os.path.join(dir_path, 'pass.csv')
    creds = csv_to_dict(myfile)
    myuser = creds['username']
    mypwd = creds['password']
    print "User: {0} | Pass: {1}".format(myuser, mypwd)

    # Main Program Loop
    my_options = ['ARP Scan', 'Quit']
    while True:
        answer = getOptionAnswerIndex('Select a task', my_options)
        print "\n" + "*" * 25
        if answer == "1":
            print "Run -> ARP Scan"
            arpscan()
        elif answer == "6":
            print "Goodbye!"
            quit()
        else:
            quit()