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
log_path = ''

# Params
mypwd = ''
myuser = ''

# Credentials Dictionary


# Router IP Hostname Mappings
host_ip_dict = {"10.159.0.105": "ITE_105", "10.159.0.106": "ITE_106", "10.159.0.107": "ITW_107",
                "10.159.0.108": "ITW_108", "10.8.0.51": "Boyers_51", "10.8.0.52": "Boyers_52", "10.10.40.70": "Test_1",
                "10.10.40.71": "Test_2"}


# Detect the system enviornment (Windows/Linux/MAC)
def detect_env():
    """ Purpose: Detect OS and create appropriate path variables
    :param: None
    :return: None
    """
    global dir_path
    global conf_path
    global log_path

    dir_path = os.path.dirname(os.path.abspath(__file__))
    if platform.system().lower() == "windows":
        #print "Environment Windows!"
        conf_path = os.path.join(dir_path, "conf")
        log_path = os.path.join(dir_path, "log")
    else:
        #print "Environment Linux/MAC!"
        conf_path = os.path.join(dir_path, "conf")
        log_path = os.path.join(dir_path, "log")

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
    ip1 = 'A'
    ip2 = 'B'
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

# A heading to spruce up the output
def heading(title):
    # Get the length of the title
    title_len = len(title)
    border_len = title_len + 4

    # Print heading
    print "-" * border_len
    print "- " + title + " -"
    print "-" * border_len

# A function to open a connection to devices and capture any exceptions
def connect(ip):
    """ Purpose: Attempt to connect to the device

    :param ip:          -   IP of the device
    :param indbase:     -   Boolean if this device is in the database or not, defaults to False if not specified
    :return dev:        -   Returns the device handle if its successfully opened.
    """
    dev = Device(host=ip, user=creds['sshkeyuser'], auto_probe=True)
    #dev = Device(host=ip, user=myuser, password=mypwd, auto_probe=True)
    # Try to open a connection to the device
    try:
        dev.open()
    # If there is an error when opening the connection, display error and exit upgrade process
    except ConnectRefusedError as err:
        message = "Host Reachable, but NETCONF not configured."
        print("Connect Fail - {0}").format(message)
        return False
    except ConnectAuthError as err:
        print("SSH Key Connect Failed using '{0}'").format(creds['sshkeyuser'])
        dev = backup_connect(ip)
        if dev:
            return dev
        else:
            return False
    except ConnectTimeoutError as err:
        message = "Timeout error, possible IP reachability issues."
        print("Connect Fail - {0}").format(message)
        return False
    except ProbeError as err:
        message = "Probe timeout, possible IP reachability issues."
        print("Connect Fail - {0}").format(message)
        return False
    except ConnectError as err:
        message = "Unknown connection issue."
        print("Connect Fail - {0}").format(message)
        return False
    except Exception as err:
        message = "Undefined exception."
        print("Connect Fail - {0}").format(message)
        return False
    # If try arguments succeeded...
    else:
        print("Connected to {0} using SSH Key.").format(ip)
        return dev

def backup_connect(ip):
    """ Purpose: Attempt to connect to the device

    :param ip:          -   IP of the device
    :param indbase:     -   Boolean if this device is in the database or not, defaults to False if not specified
    :return dev:        -   Returns the device handle if its successfully opened.
    """
    dev = Device(host=ip, user=creds['username'], password=creds['password'], auto_probe=True)
    # Try to open a connection to the device
    try:
        dev.open()
    # If there is an error when opening the connection, display error and exit upgrade process
    except ConnectRefusedError as err:
        message = "Host Reachable, but NETCONF not configured."
        print("Connect Fail - {0}").format(message)
        return False
    except ConnectAuthError as err:
        message = "Unable to connect using SSH Key. User:" + username
        print("Connect Fail - {0}").format(message)
        return False
    except ConnectTimeoutError as err:
        message = "Timeout error, possible IP reachability issues."
        print("Connect Fail - {0}").format(message)
        return False
    except ProbeError as err:
        message = "Probe timeout, possible IP reachability issues."
        print("Connect Fail - {0}").format(message)
        return False
    except ConnectError as err:
        message = "Unknown connection issue."
        print("Connect Fail - {0}").format(message)
        return False
    except Exception as err:
        message = "Undefined exception."
        print("Connect Fail - {0}").format(message)
        return False
    # If try arguments succeeded...
    else:
        print("Connected {0} using user/password.").format(ip)
        return dev


# Capture the ARP table from the device
def get_arp_table(ip):
    # Place to store ARP info
    arp_mac_listdict = []
    # Open a connection to this IP
    dev = connect(ip)
    if dev:
        # Request ARP table information from device
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
        dev.close()
    # Return the ARP table to requestor
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
    nameA = ''
    nameB = ''
    label = ''
    ####################
    # TESTING Code
    ####################
    if ip1 == 'A' and ip2 == 'B':
        # Set the hostnames
        nameA = "Host_A"
        nameB = "Host_B"

        router_a_1 = 'itw-spn-a-all-arp-1200.csv'
        router_a_2 = 'itw-spn-a-all-arp-1202.csv'
        router_b_1 = 'itw-spn-b-all-arp-1159.csv'
        router_b_2 = 'itw-spn-b-all-arp-1201.csv'

        router_a_1_ld = csvListDict(os.path.join(dir_path, router_a_1))
        router_a_2_ld = csvListDict(os.path.join(dir_path, router_a_2))
        router_b_1_ld = csvListDict(os.path.join(dir_path, router_b_1))
        router_b_2_ld = csvListDict(os.path.join(dir_path, router_b_2))

        # Run comparisons
        # First comparison
        both_perm_remote_dl_1, both_none_dl_1, misc_flag_dl_1, mac_discrep_dl_1, miss_on_a_dl_1, miss_on_b_dl_1, valid_count_1 = \
            test_compare_capture(router_a_1_ld, router_b_1_ld)
        # Second comparison
        both_perm_remote_dl_2, both_none_dl_2, misc_flag_dl_2, mac_discrep_dl_2, miss_on_a_dl_2, miss_on_b_dl_2, valid_count_2 = \
            test_compare_capture(router_a_2_ld, router_b_2_ld)
    ####################
    # OPERATIONAL Code
    ####################
    else:
        if netaddr.valid_ipv4(ip1) and netaddr.valid_ipv4(ip2):
            # Set the hostnames and labels
            if ip1 in host_ip_dict:
                nameA = host_ip_dict[ip1]
                if ip2 in host_ip_dict:
                    nameB = host_ip_dict[ip2]
                    label = nameA.split('_')[0]
                else:
                    nameA = ip1
                    nameB = ip2
                    label = ip1 + "_" + ip2
            else:
                nameA = ip1
                nameB = ip2
                label = ip1 + "_" + ip2

            #print "Label is {0}".format(label)

            heading("Running First Comparison")
            both_perm_remote_dl_1, both_none_dl_1, misc_flag_dl_1, mac_discrep_dl_1, miss_on_a_dl_1, miss_on_b_dl_1, valid_count_1 = \
                oper_compare_capture()
            print "-" * 30
            stdout.write("Pausing for 2 mins...")
            sys.stdout.flush()
            time.sleep(120)
            print "Done Waiting"
            print "-" * 30
            heading("Running Second Comparison")
            both_perm_remote_dl_2, both_none_dl_2, misc_flag_dl_2, mac_discrep_dl_2, miss_on_a_dl_2, miss_on_b_dl_2, valid_count_2 = \
                oper_compare_capture()
            print "-" * 30
        else:
            print "Detected Invalid IPv4 Formatted IPs ... exiting"
            exit()
    ####################
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

    heading("Creating Configuration and Results Files")

    # Print Configuration To File
    create_conf_file(clear_ether_list, clear_arp_a_list, clear_arp_b_list, both_perm, label, nameA, nameB)

    # Print Results To File
    print_results(both_perm, both_none, misc_flag, mac_discr, miss_on_a, miss_on_b, valid_count_1, label, nameA, nameB)
    print "-" * 30


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
    print "Retrieving ARP table ({0})".format(ip1)
    arp_mac_listdict1 = get_arp_table(ip1)
    # Make sure retrieval was successful
    if arp_mac_listdict1:
        print "--> Successfully captured ARP table"
        arp_mac_listdict1 = filter_excluded_arps(arp_mac_listdict1)
        print "--> Completed filtering ARP table"
        # Retrieve information from device B
        print "Retrieving ARP table ({0})".format(ip2)
        arp_mac_listdict2 = get_arp_table(ip2)
        # Make sure retrieval was successful
        if arp_mac_listdict2:
            print "--> Successfully captured ARP table"
            arp_mac_listdict2 = filter_excluded_arps(arp_mac_listdict2)
            print "--> Completed filtering ARP table"
            # Run comparison function and print results and commands
            both_perm_remote_dl, both_none_dl, misc_flag_dl, mac_discrep_dl, miss_on_a_dl, miss_on_b_dl, valid_count = \
                compare_arp_tables(arp_mac_listdict1, arp_mac_listdict2, ip1, ip2)
            return both_perm_remote_dl, both_none_dl, misc_flag_dl, mac_discrep_dl, miss_on_a_dl, miss_on_b_dl, valid_count
        else:
            print("Failed to retrieve ARP table on {0} ... exiting").format(ip2)
            exit()
    else:
        print("Failed to retrieve ARP table on {0} ... exiting").format(ip1)
        exit()

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
        # If no match was made, this ARP deosn't exist on A
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

def create_conf_file(clear_ether_list, clear_arp_a_list, clear_arp_b_list, both_perm, label, nameA, nameB):
    # Create configuration file with clear commands if applicable
    if clear_ether_list or clear_arp_a_list or clear_arp_b_list:
        # Create config file
        now = get_now_time()
        clear_conf_name = "clear_comds_" + label + "_" + now + ".conf"
        myconfile = os.path.join(conf_path, clear_conf_name)

        # Output for the config file
        print_log("## CLEAR CONFIGURATION COMMANDS", myconfile, True)
        print_log("## ****************************", myconfile, True)
        print_log("## Host A: " + nameA + " (" + ip1 + ")", myconfile, True)
        print_log("## Host B: " + nameB + " (" + ip2 + ")", myconfile, True)
        print_log("## ****************************", myconfile, True)
        print_log("## Both Permanent|Remote: " + str(len(both_perm)), myconfile, True)
        print_log("## Exists on A, not B: " + str(len(clear_arp_a_list)), myconfile, True)
        print_log("## Exists on B, not A: " + str(len(clear_arp_b_list)), myconfile, True)
        print_log("## ****************************", myconfile, True)

        if clear_ether_list:
            # Loop ether_list and add commands
            print_log("##\n## Both Permanent|Remote - Run these commands on both devices.\n##", myconfile, True)
            for command in clear_ether_list:
                print_log(command, myconfile)

        if clear_arp_a_list:
            # Loop arp_list and add commands
            print_log("##\n## Exists on A, not B - Run these commands on " + ip1 + "\n##", myconfile, True)
            for command in clear_arp_a_list:
                print_log(command, myconfile)

        if clear_arp_a_list:
            # Loop arp_list and add commands
            print_log("##\n## Exists on B, not A - Run these commands on " + ip2 + "\n##", myconfile, True)
            for command in clear_arp_b_list:
                print_log(command, myconfile)

        # Print file name
        print "Completed Config File: {0}".format(clear_conf_name)


def print_results(both_perm_remote_dl, both_none_dl, misc_flag_dl, mac_discrep_dl, miss_on_a_dl, miss_on_b_dl, valid_count, label, nameA, nameB):
    # Create log file
    now = get_now_time()
    log_name = "log_output_" + label + "_" + now + ".log"
    mylogfile = os.path.join(log_path, log_name)

    # Printing the results of the comparison to the file
    print_log("ARP COMPARISON RESULTS", mylogfile, True)
    print_log("****************************", mylogfile, True)
    print_log("Host A: " + nameA + " (" + ip1 + ")", mylogfile, True)
    print_log("Host B: " + nameB + " (" + ip2 + ")", mylogfile, True)
    print_log("****************************", mylogfile, True)
    print_log("-"*100, mylogfile, True)
    print_log("- Both ARPs Permanent Remote -", mylogfile, True)
    print_log("-"*100, mylogfile, True)
    if both_perm_remote_dl:
        for item in both_perm_remote_dl:
            print_log("\t" + "IP: " + item['ip'] + " | MAC: " + item['mac'], mylogfile, True)
    else:
        print_log("\tNo Matches Found", mylogfile, True)
    print_log("-"*100, mylogfile, True)
    print_log("- Both ARPs None -", mylogfile, True)
    print_log("-"*100, mylogfile, True)
    if both_none_dl:
        for item in both_none_dl:
            print_log("\t" + "IP: " + item['ip'] + " | MAC: " + item['mac'], mylogfile, True)
    else:
        print_log("\tNo Matches Found", mylogfile, True)
    print_log("-"*100, mylogfile, True)
    print_log("- Unexpected ARPs -", mylogfile, True)
    print_log("-"*100, mylogfile, True)
    if misc_flag_dl:
        for item in misc_flag_dl:
            print_log("\t" + "A - [IP: " + item['ip_a'] + " | MAC: " + item['mac_a'] + " | FLAG: " + item['flag_a'] + \
                  "] B - [IP: " + item['ip_b'] + " | MAC: " + item['mac_b'] + " | FLAG: " + item['flag_b'] + "]", mylogfile, True)
    else:
        print_log("\tNo Matches Found", mylogfile, True)
    print_log("-"*100, mylogfile, True)
    print_log("- ARP Discrepancies -", mylogfile, True)
    print_log("-"*100, mylogfile, True)
    if mac_discrep_dl:
        for item in mac_discrep_dl:
            print_log("\t" + "IP: " + item['ip'] + " | MAC on A: " + item['mac_a'] + " | MAC on B: " + item['mac_b'], mylogfile, True)
    else:
        print_log("\tNo Matches Found", mylogfile, True)
    print_log("-"*100, mylogfile, True)
    print_log("- ARPs on A, NOT on B -", mylogfile, True)
    print_log("-"*100, mylogfile, True)
    if miss_on_b_dl:
        sorted_list = list_dict_custom_sort(miss_on_b_dl, 'flag', ['none'])
        for item in sorted_list:
            print_log("\t" + "IP: " + item['ip'] + " | MAC: " + item['mac'] + " | FLAG: " + item['flag'], mylogfile, True)
    else:
        print_log("\tNo Matches Found", mylogfile, True)
    print_log("-"*100, mylogfile, True)
    print_log("- ARPs on B, NOT on A -", mylogfile, True)
    print_log("-"*100, mylogfile, True)
    if miss_on_a_dl:
        sorted_list = list_dict_custom_sort(miss_on_a_dl, 'flag', ['none'])
        for item in sorted_list:
            print_log("\t" + "IP: " + item['ip'] + " | MAC: " + item['mac'] + " | FLAG: " + item['flag'], mylogfile, True)
    else:
        print_log("\tNo Matches Found", mylogfile, True)
    print_log("-"*100, mylogfile, True)
    print_log("-----------------------------", mylogfile, True)
    print_log("Total Both Permanent:....." + str(len(both_perm_remote_dl)), mylogfile, True)
    print_log("Total Both None:.........." + str(len(both_none_dl)), mylogfile, True)
    print_log("Total Unexpected ARPs....." + str(len(misc_flag_dl)), mylogfile, True)
    print_log("Total ARP Discrepancies:.." + str(len(mac_discrep_dl)), mylogfile, True)
    print_log("Total ARP on B, Not A:...." + str(len(miss_on_a_dl)), mylogfile, True)
    print_log("Total ARP on A, Not B:...." + str(len(miss_on_b_dl)), mylogfile, True)
    print_log("Total Valid ARPs:........." + str(valid_count), mylogfile, True)
    print_log("-----------------------------\n", mylogfile, True)

    # Print file name
    print "Completed Results File: {0}".format(log_name)

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
    global creds
    creds = {'username': '', 'password': '', 'sshkeyuser': ''}
    creds_list = line_list(os.path.join(dir_path, 'pass.dat'))
    for cred in creds_list:
        elem = cred.split(':')
        #print('Key: {0} Value: {1}'.format(elem[0], elem[1]))
        creds[elem[0]] = elem[1]

    #print "User: {0} | Pass: {1}".format(myuser, mypwd)
    print "***** RUNNING ARPSCAN *****"

    # Main Program Loop
    arpscan()
    print "***** EXITING ARPSCAN *****"