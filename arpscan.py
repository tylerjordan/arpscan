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
conf_path = ''

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
    global conf_path

    dir_path = os.path.dirname(os.path.abspath(__file__))
    if platform.system().lower() == "windows":
        #print "Environment Windows!"
        conf_path = os.path.join(dir_path, "conf")
    else:
        #print "Environment Linux/MAC!"
        conf_path = os.path.join(dir_path, "conf")

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
            #print "MAC: {0} -> IP: {1}".format(arptableentry['mac-address'].encode('utf-8'),
            #  arptableentry['ip-address'].encode('utf-8'))
            if 'permanent' in arptableentry['arp-table-entry-flags'] \
                    and 'remotely-learnt-address' in arptableentry['arp-table-entry-flags']:
                arpflag = 'perm_remote'
            elif 'none' in arptableentry['arp-table-entry-flags']:
                arpflag = 'none'
            else:
                arpflag = 'permanent'
            arp_mac_listdict.append({'ip': arptableentry['ip-address'].encode('utf-8'),
                                     'mac': arptableentry['mac-address'].encode('utf-8'),
                                     'flag': arpflag})
    # Return the listdict
    return arp_mac_listdict

# A function to capture ARP tables and compare them
def arpscan():
    print "-"*22
    print "- Loading ARP Tables -"
    print "-"*22

    # TESTING Code
    #'''
    router_a = 'ita_arp.csv'
    router_b = 'itb_arp.csv'
    # Loads the following CSV into a list dictionary
    arp_mac_listdict1 = csvListDict(os.path.join(dir_path, router_a))
    if arp_mac_listdict1:
        print "Successfully loaded Test ARP table from {0}".format(router_a)
        #print_listdict(arp_mac_listdict1)
        arp_mac_listdict2 = csvListDict(os.path.join(dir_path, router_b))
        if arp_mac_listdict2:
            print "Successfully loaded Test ARP table from {0}".format(router_b)
            #print_listdict(arp_mac_listdict2)
            compare_arp_tables(arp_mac_listdict1, arp_mac_listdict2, ip1, ip2)
        else:
            print "Issue populating ARP table from {0}".format(router_b)
    else:
        print "Issue populating ARP table for {0}".format(router_a)
    #'''
    # OPERATIONAL Code
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
    good_count = 0
    # Lists to hold the Juniper commands for removing ARPs
    clear_ether_list = []
    clear_arp_a_list = []
    clear_arp_b_list = []

    # Dictlists for holding content for outputs
    perm_remote_dictlist = []       # Format: 'ip', 'mac'
    discrep_dictlist = []           # Format: 'ip', 'mac_a', 'mac_b'
    miss_on_a_dictlist = []         # Format: 'ip', 'mac', 'flag'
    miss_on_b_dictlist = []         # Format: 'ip', 'mac', 'flag'
    # Compares A against B
    for arp1 in arptab1:
        no_match= True
        for arp2 in arptab2:
            # If these records have the same IP
            if arp1['ip'] == arp2['ip']:
                # If these records have the same MAC
                if arp1['mac'] == arp2['mac']:
                    # If these records have the same flag
                    if arp1['flag'] == 'perm_remote' and arp2['flag'] == 'perm_remote':
                        # If this is NOT a duplicate
                        if not any(d['mac'] == arp1['mac'] for d in perm_remote_dictlist):
                            clear_ether_list.append("clear ethernet-switching table mac " + arp1['mac'] + "\n")
                        # If it is a duplicate
                        else:
                           #print "Duplicate MAC: {0} on IP: {1}!".format(arp1['mac'], arp1['ip'])
                            pass
                        # Add record regardless
                        perm_remote_dictlist.append({'ip': arp1['ip'], 'mac': arp1['mac']})
                    else:
                        # Good Match
                        good_count += 1
                # If these records have different MACs
                else:
                    discrep_dictlist.append({'ip': arp1['ip'], 'mac_a': arp1['mac'], 'mac_b': arp2['mac']})
                no_match = False
                break
            # If these records have different IPs
            else:
                # Move onto next IP...
                pass
        # If no match was made, this ARP doesn't exist on B
        if no_match:
            # Checks that flag has a value
            if arp1['flag']:
                # If flag's value is 'none'
                if arp1['flag'] == 'none':
                    miss_on_b_dictlist.append(arp1)
                    clear_arp_a_list.append("clear arp hostname " + arp1['ip'] + "\n")
                else:
                    miss_on_b_dictlist.append(arp1)
                    pass
            # If flag value is missing
            else:
                print "ERROR: On {0} -> Missing Flag for IP: {1}".format(ip1, arp1['ip'])
    # Compares B against A
    for arp2 in arptab2:
        no_match = True
        for arp1 in arptab1:
            if arp2['ip'] == arp1['ip']:
                no_match = False
                break
            else:
                pass
        # If not match was made, this ARP deosn't exist on A
        if no_match:
            if arp2['flag']:
                # If flag's value is 'none'
                if arp2['flag'] == 'none':
                    miss_on_a_dictlist.append(arp2)
                    clear_arp_b_list.append("clear arp hostname " + arp2['ip'] + "\n")
                else:
                    miss_on_a_dictlist.append(arp2)
                    pass
            # If flag value is missing
            else:
                print "ERROR: On {0} -> Missing Flag for IP: {1}".format(ip2, arp2['ip'])

    # Create configuration file with clear commands if applicable
    if clear_ether_list or clear_arp_a_list or clear_arp_b_list:
        # Create config file
        now = get_now_time()
        clear_conf_name = "clear_comds_" + now + "_.conf"
        myconfile = os.path.join(conf_path, clear_conf_name)
        print_log("##\n## TOTALS:\n## Both Permanent|Remote: " + str(len(perm_remote_dictlist)) + "\n", myconfile)
        print_log("## 'none' Status on A: " + str(len(clear_arp_a_list)) + "\n", myconfile)
        print_log("## 'none' Status on B: " + str(len(clear_arp_b_list)) + "\n", myconfile)
        print_log("##\n", myconfile)

        if clear_ether_list:
            # Loop ether_list and add commands
            print_log("##\n## Both Permanent|Remote - Run these commands on both devices.\n##\n", myconfile)
            for command in clear_ether_list:
                print_log(command, myconfile)

        if clear_arp_a_list:
            # Loop arp_list and add commands
            print_log("##\n## None Status on A - Run these commands on " + ip1 + "\n##\n", myconfile)
            for command in clear_arp_a_list:
                print_log(command, myconfile)

        if clear_arp_a_list:
            # Loop arp_list and add commands
            print_log("##\n## None Status on B - Run these commands on " + ip2 + "\n##\n", myconfile)
            for command in clear_arp_b_list:
                print_log(command, myconfile)

    # Printing the results of the comparison
    print "\n" + "-"*22
    print "- Comparison Results -"
    print "-"*22
    print "  - Both Perm ARPs -"
    print "-"*100
    if perm_remote_dictlist:
        for item in perm_remote_dictlist:
            print "\t" + "IP: " + item['ip'] + " | MAC: " + item['mac']
    else:
        print "\tNo Matches Found"
    print "-"*100
    print "  - ARP Discrepancies -"
    print "-"*100
    if discrep_dictlist:
        for item in discrep_dictlist:
            print "\t" + "IP: " + item['ip'] + " | MAC on A: " + item['mac_a'] + " | MAC on B: " + item['mac_b']
    else:
        print "\tNo Matches Found"
    print "-"*100
    print "  - ARPs on B, NOT on A -"
    print "-"*100
    if miss_on_a_dictlist:
        sorted_list = list_dict_custom_sort(miss_on_a_dictlist, 'flag', ['none'])
        for item in sorted_list:
            print "\t" + "IP: " + item['ip'] + " | MAC: " + item['mac'] + " | FLAG: " + item['flag']
    else:
        print "\tNo Matches Found"
    print "-"*100
    print "  - ARPs on A, NOT on B -"
    print "-"*100
    if miss_on_b_dictlist:
        sorted_list = list_dict_custom_sort(miss_on_b_dictlist, 'flag', ['none'])
        for item in sorted_list:
            print "\t" + "IP: " + item['ip'] + " | MAC: " + item['mac'] + " | FLAG: " + item['flag']
    else:
        print "\tNo Matches Found"
    print "-"*100
    print "-----------------------------"
    print "Total Both Permanent: {0}".format(len(perm_remote_dictlist))
    print "Total ARP Discrepancies: {0}".format(len(discrep_dictlist))
    print "Total ARP on B, Not A: {0}".format(len(miss_on_a_dictlist))
    print "Total ARP on A, Not B: {0}".format(len(miss_on_b_dictlist))
    print "Total Matching ARPs: {0}".format(str(good_count))
    print "-----------------------------\n"

# A function to display a list dict in a "pretty" format
def print_listdict(list_dict):
    """ 
        Purpose: Display a table showing contents of the list dictionary.
        Returns: Nothing
    """
    t = PrettyTable(['IP', 'MAC', 'FLAG'])
    for host_dict in list_dict:
        # print device
        t.add_row([host_dict['ip'], host_dict['mac'], host_dict['flag']])
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