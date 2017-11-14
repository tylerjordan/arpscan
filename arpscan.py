__copyright__ = "Copyright 2017 Tyler Jordan"
__version__ = "0.1.1"
__email__ = "tjordan@juniper.net"

import datetime
import platform
import os
import netaddr
import jxmlease
import getopt
import time
import sys

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

# Capture the ARP table from the device
def get_arp_table(dev):
    arpsw_response = jxmlease.parse_etree(dev.rpc.get_arp_table_information(no_resolve=True))
    for arptableentry in arpsw_response['arp-table-information']['arp-table-entry']:
        # print "MAC: {0} -> IP: {1}".format(arptableentry['mac-address'].encode('utf-8'),
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

# Function for collecting the ARP information from the Juniper devices
def collect_data(ip):
    # ARP list dictionary
    arp_mac_listdict = []
    # Open a connection to this IP
    dev = connect(ip)
    if dev:
        print "Connected to {0}".format(ip)
        arp_mac_listdict = get_arp_table(dev)
        dev.close()
    # Return the listdict
    return arp_mac_listdict

# Remove uninteresting ARP entries
def filter_excluded_arps(arp_listdict):
    # New filtered listdict
    filtered_listdict = []

    # Load exclusion list
    ip_list = line_list(os.path.join(dir_path, 'exclusion_list.txt'))

    # Loop over the list and omit any that match from the exclusion list
    # Make sure the ip_list has entries
    if ip_list:
        # Loop over this ARP list of dictionaries
        for arpentry in arp_listdict:
            matched = False
            for excluded_ip in ip_list:
                # If the IP is matched, it is uninteresting
                if arpentry['ip'] == excluded_ip:
                    # ARP is excluded
                    #print "Excluded this IP: {0}".format(arpentry['ip'])
                    matched = True
                    break
            # If the IP was never matched, it isn't excluded
            if not matched:
                filtered_listdict.append(arpentry)
        return filtered_listdict
    # This executes if the ip_list is empty, return the listdict unchanged
    else:
        print "No IPs filtered using exclusion list."
        return arp_listdict


# A function to capture ARP tables and compare them
def arpscan():
    print "-"*22
    print "- Loading ARP Tables -"
    print "-"*22

    ####################
    # OPERATIONAL Code
    #'''
    both_perm_remote_dl_1, both_none_dl_1, misc_flag_dl_1, mac_discrep_dl_1, miss_on_a_dl_1, miss_on_b_dl_1, valid_count_1 = \
        oper_compare_capture()
    stdout.write("Pausing for 2 mins...")
    sys.stdout.flush()
    time.sleep(120)
    print "Done Waiting"
    both_perm_remote_dl_2, both_none_dl_2, misc_flag_dl_2, mac_discrep_dl_2, miss_on_a_dl_2, miss_on_b_dl_2, valid_count_2 = \
        oper_compare_capture()
    #'''

    # TESTING Code
    '''
    router_a_1 = 'itw-spn-a-all-arp-1200.csv'
    router_a_2 = 'itw-spn-a-all-arp-1202.csv'
    router_b_1 = 'itw-spn-b-all-arp-1159.csv'
    router_b_2 = 'itw-spn-b-all-arp-1201.csv'

    router_a_1_ld = csvListDict(os.path.join(dir_path, router_a_1))
    router_a_2_ld = csvListDict(os.path.join(dir_path, router_a_2))
    router_b_1_ld = csvListDict(os.path.join(dir_path, router_b_1))
    router_b_2_ld = csvListDict(os.path.join(dir_path, router_b_2))

    # Run comparisons
    both_perm_remote_dl_1, both_none_dl_1, misc_flag_dl_1, mac_discrep_dl_1, miss_on_a_dl_1, miss_on_b_dl_1, valid_count_1 = \
        test_compare_capture(router_a_1_ld, router_b_1_ld)
    stdout.write("Pausing for 2 mins...")
    sys.stdout.flush()
    time.sleep(120)
    print "Done Waiting"
    both_perm_remote_dl_2, both_none_dl_2, misc_flag_dl_2, mac_discrep_dl_2, miss_on_a_dl_2, miss_on_b_dl_2, valid_count_2 = \
        test_compare_capture(router_a_2_ld, router_b_2_ld)
    '''
    ########################

    '''
    # Print Results
    print "Print Results of the First Compare"
    print_results(both_perm_remote_dl_1, both_none_dl_1, misc_flag_dl_1, mac_discrep_dl_1, miss_on_a_dl_1, \
                  miss_on_b_dl_1, valid_count_1)
    print "Print Results of the Second Compare"
    print_results(both_perm_remote_dl_2, both_none_dl_2, misc_flag_dl_2, mac_discrep_dl_2, miss_on_a_dl_2, \
                  miss_on_b_dl_2, valid_count_2)
    '''

    # Compare All Results
    both_perm = compare_listdict(both_perm_remote_dl_1, both_perm_remote_dl_2)
    both_none = compare_listdict(both_none_dl_1, both_none_dl_2)
    misc_flag = compare_listdict(misc_flag_dl_1, misc_flag_dl_2)
    mac_discr = compare_listdict(mac_discrep_dl_1, mac_discrep_dl_2)
    miss_on_a = compare_listdict(miss_on_a_dl_1, miss_on_a_dl_2)
    miss_on_b = compare_listdict(miss_on_b_dl_1, miss_on_b_dl_2)

    # Create clear commands
    clear_ether_list = []
    clear_arp_a_list = []
    clear_arp_b_list = []

    for arp_entry in both_perm:
        clear_ether_list.append("clear ethernet-switching table " + arp_entry['mac'] + "\n")
    for arp_entry in both_none:
        clear_ether_list.append("clear ethernet-switching table " + arp_entry['mac'] + "\n")
    for arp_entry in miss_on_a:
        if arp_entry['flag'] == 'perm_remote':
            clear_ether_list.append("clear ethernet-switching table " + arp_entry['mac'] + "\n")
        elif arp_entry['flag'] == 'none':
            clear_arp_b_list.append("clear arp hostname " + arp_entry['ip'] + "\n")
    for arp_entry in miss_on_b:
        if arp_entry['flag'] == 'perm_remote':
            clear_ether_list.append("clear ethernet-switching table " + arp_entry['mac'] + "\n")
        elif arp_entry['flag'] == 'none':
            clear_arp_a_list.append("clear arp hostname " + arp_entry['ip'] + "\n")

    create_conf_file(clear_ether_list, clear_arp_a_list, clear_arp_b_list, both_perm)
    print "Completed creating clear configuration file."

    # Print Results
    print_results(both_perm, both_none, misc_flag, mac_discr, miss_on_a, miss_on_b, valid_count_1)

def compare_listdict(listdict1, listdict2):
    common_ld = []
    # Compare Results and Return Common Entries
    for arp1 in listdict1:
        for arp2 in listdict2:
            if arp1 == arp2:
                common_ld.append(arp1)
                break
    return common_ld

def test_compare_capture(router_a_ld, router_b_ld):
    blank_list = []
    # Loads the following CSV into a list dictionary
    if router_a_ld:
        # Filter out uninteresting IPs
        arp_mac_listdict1 = filter_excluded_arps(router_a_ld)
        print "Completed filtering ARPs for A."
        if router_b_ld:
            # Filter out uninteresting IPs
            arp_mac_listdict2 = filter_excluded_arps(router_b_ld)
            print "Completed filtering ARPs for B."
            # Run comparison function and print results and commands
            both_perm_remote_dl, both_none_dl, misc_flag_dl, mac_discrep_dl, miss_on_a_dl, miss_on_b_dl, valid_count = \
                compare_arp_tables(arp_mac_listdict1, arp_mac_listdict2, ip1, ip2)
            return both_perm_remote_dl, both_none_dl, misc_flag_dl, mac_discrep_dl, miss_on_a_dl, miss_on_b_dl, valid_count
        else:
            print "Invalid ARP table for B"
    else:
        print "Invalid ARP table for A"

    return blank_list

def oper_compare_capture():
    blank_list = []
    # Retrieve information from device A
    if ip1:
        print "Retrieving ARP table from {0}".format(ip1)
        arp_mac_listdict1 = collect_data(ip1)
        print "Successfully captured ARP table from {0}".format(ip1)
        arp_mac_listdict1 = filter_excluded_arps(arp_mac_listdict1)
        print "Completed filtering ARPs for {0}.".format(ip1)
        # Retrieve information from device B
        if ip2:
            print "Retrieving ARP table from {0}".format(ip2)
            arp_mac_listdict2 = collect_data(ip2)
            print "Successfully captured ARP table from {0}".format(ip2)
            arp_mac_listdict2 = filter_excluded_arps(arp_mac_listdict2)
            print "Completed filtering ARPs for {0}.".format(ip2)
            # Run comparison function and print results and commands
            both_perm_remote_dl, both_none_dl, misc_flag_dl, mac_discrep_dl, miss_on_a_dl, miss_on_b_dl, valid_count = \
                compare_arp_tables(arp_mac_listdict1, arp_mac_listdict2, ip1, ip2)
            return both_perm_remote_dl, both_none_dl, misc_flag_dl, mac_discrep_dl, miss_on_a_dl, miss_on_b_dl, valid_count
        else:
            print "Issue populating ARP table for {0}".format(ip1)
    else:
        print "Issue populating ARP table for {0}".format(ip2)

    return blank_list

# Custom function for comparing ARP tables
def compare_arp_tables(arptab1, arptab2, ip1, ip2):
    # Compare ARP Tables
    valid_count = 0

    # Dictlists for holding content for outputs
    both_perm_remote_dl = []        # Format: 'ip', 'mac'
    both_none_dl = []               # Format: 'ip', 'mac'
    misc_flag_dl = []               # Format: 'ip_a', 'mac_a', 'flag_a', 'ip_b', 'mac_b', 'flag_b'
    mac_discrep_dl = []             # Format: 'ip', 'mac_a', 'mac_b'

    miss_on_a_dl = []               # Format: 'ip', 'mac', 'flag'
    miss_on_b_dl = []               # Format: 'ip', 'mac', 'flag'

    # Compares A against B
    for arp1 in arptab1:
        no_match= True
        for arp2 in arptab2:
            # If these records have the same IP
            if arp1['ip'] == arp2['ip']:
                # If these records have the same MAC
                if arp1['mac'] == arp2['mac']:
                    # Check for various flag combinations
                    if arp1['flag'] == 'perm_remote' and arp2['flag'] == 'perm_remote':
                        both_perm_remote_dl.append({'ip': arp1['ip'], 'mac': arp1['mac']})
                    elif arp1['flag'] == 'none' and arp2['flag'] == 'none':
                        both_none_dl.append({'ip': arp1['ip'], 'mac': arp1['mac']})
                    elif (arp1['flag'] == 'perm_remote' and arp2['flag'] == 'none') or \
                            (arp1['flag'] == 'none' and arp2['flag'] == 'perm_remote'):
                        valid_count += 1
                    else:
                        misc_flag_dl.append({'ip_a': arp1['ip'], 'mac_a': arp1['mac'], 'flag_a': arp1['flag'],
                                             'ip_b': arp2['ip'], 'mac_b': arp2['mac'], 'flag_b': arp2['flag']})
                # If these records have different MACs
                else:
                    mac_discrep_dl.append({'ip': arp1['ip'], 'mac_a': arp1['mac'], 'mac_b': arp2['mac']})
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
                # A is 'permanent remote' and B has no entry
                if arp1['flag'] == 'perm_remote' or arp2['flag'] == 'none':
                    pass
                else:
                    print "Unmatched flag for IP: {0} MAC: {1} FLAG: {2}".format(arp1['ip'], arp1['mac'], arp1['flag'])
                miss_on_b_dl.append(arp1)
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
            # Checks that flag has a value
            if arp2['flag']:
                if arp2['flag'] == 'perm_remote' or arp2['flag'] == 'none':
                    pass
                else:
                    print "Unmatched flag for IP: {0} MAC: {1} FLAG: {2}".format(arp2['ip'], arp2['mac'], arp2['flag'])
                miss_on_a_dl.append(arp2)
            # If flag value is missing
            else:
                print "ERROR: On {0} -> Missing Flag for IP: {1}".format(ip2, arp2['ip'])

    # Return all lists of dictionaries as a list
    return both_perm_remote_dl, both_none_dl, misc_flag_dl, mac_discrep_dl, miss_on_a_dl, miss_on_b_dl, valid_count

def create_conf_file(clear_ether_list, clear_arp_a_list, clear_arp_b_list, both_perm):
    # Create configuration file with clear commands if applicable
    if clear_ether_list or clear_arp_a_list or clear_arp_b_list:
        # Create config file
        now = get_now_time()
        clear_conf_name = "clear_comds_" + now + "_.conf"
        myconfile = os.path.join(conf_path, clear_conf_name)
        print_log("##\n## TOTALS:\n## Both Permanent|Remote: " + str(len(both_perm)) + "\n", myconfile)
        print_log("## Exists on A, not B: " + str(len(clear_arp_a_list)) + "\n", myconfile)
        print_log("## Exists on B, not A: " + str(len(clear_arp_b_list)) + "\n", myconfile)
        print_log("##\n", myconfile)

        if clear_ether_list:
            # Loop ether_list and add commands
            print_log("##\n## Both Permanent|Remote - Run these commands on both devices.\n##\n", myconfile)
            for command in clear_ether_list:
                print_log(command, myconfile)

        if clear_arp_a_list:
            # Loop arp_list and add commands
            print_log("##\n## Exists on A, not B - Run these commands on " + ip1 + "\n##\n", myconfile)
            for command in clear_arp_a_list:
                print_log(command, myconfile)

        if clear_arp_a_list:
            # Loop arp_list and add commands
            print_log("##\n## Exists on B, not A - Run these commands on " + ip2 + "\n##\n", myconfile)
            for command in clear_arp_b_list:
                print_log(command, myconfile)

def print_results(both_perm_remote_dl, both_none_dl, misc_flag_dl, mac_discrep_dl, miss_on_a_dl, miss_on_b_dl, valid_count):
    # Printing the results of the comparison
    print "\n" + "-"*22
    print "- Comparison Results -"
    print "-"*22
    print "  - Both ARPs Permanent Remote -"
    print "-"*100
    if both_perm_remote_dl:
        for item in both_perm_remote_dl:
            print "\t" + "IP: " + item['ip'] + " | MAC: " + item['mac']
    else:
        print "\tNo Matches Found"
    print "-"*100
    print "  - Both ARPs None -"
    print "-"*100
    if both_none_dl:
        for item in both_none_dl:
            print "\t" + "IP: " + item['ip'] + " | MAC: " + item['mac']
    else:
        print "\tNo Matches Found"
    print "-"*100
    print "  - Unexpected ARPs -"
    print "-"*100
    if misc_flag_dl:
        for item in misc_flag_dl:
            print "\t" + "A - [IP: " + item['ip_a'] + " | MAC: " + item['mac_a'] + " | FLAG: " + item['flag_a'] + \
                  "] B - [IP: " + item['ip_b'] + " | MAC: " + item['mac_b'] + " | FLAG: " + item['flag_b'] + "]"
    else:
        print "\tNo Matches Found"
    print "-"*100
    print "  - ARP Discrepancies -"
    print "-"*100
    if mac_discrep_dl:
        for item in mac_discrep_dl:
            print "\t" + "IP: " + item['ip'] + " | MAC on A: " + item['mac_a'] + " | MAC on B: " + item['mac_b']
    else:
        print "\tNo Matches Found"
    print "-"*100
    print "  - ARPs on A, NOT on B -"
    print "-"*100
    if miss_on_b_dl:
        sorted_list = list_dict_custom_sort(miss_on_b_dl, 'flag', ['none'])
        for item in sorted_list:
            print "\t" + "IP: " + item['ip'] + " | MAC: " + item['mac'] + " | FLAG: " + item['flag']
    else:
        print "\tNo Matches Found"
    print "-"*100
    print "  - ARPs on B, NOT on A -"
    print "-"*100
    if miss_on_a_dl:
        sorted_list = list_dict_custom_sort(miss_on_a_dl, 'flag', ['none'])
        for item in sorted_list:
            print "\t" + "IP: " + item['ip'] + " | MAC: " + item['mac'] + " | FLAG: " + item['flag']
    else:
        print "\tNo Matches Found"
    print "-"*100
    print "-----------------------------"
    print "Total Both Permanent:.....{0}".format(len(both_perm_remote_dl))
    print "Total Both None:..........{0}".format(len(both_none_dl))
    print "Total Unexpected ARPs.....{0}".format(len(misc_flag_dl))
    print "Total ARP Discrepancies:..{0}".format(len(mac_discrep_dl))
    print "Total ARP on B, Not A:....{0}".format(len(miss_on_a_dl))
    print "Total ARP on A, Not B:....{0}".format(len(miss_on_b_dl))
    print "Total Valid ARPs:.........{0}".format(str(valid_count))
    print "-----------------------------\n"

# A function to display a list dict in a "pretty" format
def print_listdict(list_dict, header_show, header_keys):
    """ 
        Purpose: Display a table showing contents of the list dictionary.
        Returns: Nothing
    """
    t = PrettyTable(headers)
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