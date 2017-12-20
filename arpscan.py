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
import types

from jnpr.junos import *
from jnpr.junos.exception import *
from netaddr import *
from utility import *
from random import *

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
emailfrom = 'arpscan_script@aquarius.uspto.gov'
emailto = 'gdnsnetworksupport@uspto.gov,nosengineers@uspto.gov,tim.murphy@uspto.gov'

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
    global pushChanges

    # Interprets and handles the command line arguments
    try:
        opts, args = getopt.getopt(argv, "hta:b:", ["ip1=", "ip2="])
    except getopt.GetoptError:
        print 'jscan.py -a <host1> -b <host2>'
        sys.exit(2)
    ip1 = 'A'
    ip2 = 'B'
    pushChanges = False
    for opt, arg in opts:
        if opt == '-h':
            print 'Usage: arpscan [-h] [-t] -a <host1> -b <host2>'
            print '  -a : (REQUIRED) First host IP'
            print '  -b : (REQUIRED) Second host IP'
            print '  -t : (OPTIONAL) Apply clear commands to the hosts'
            print '  -h : (OPTIONAL) Show this help information'
            sys.exit()
        elif opt in '-t':
            pushChanges = True
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
    expanded_list = []

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
                # Checks if IP is masked or not
                if "/" in excluded_ip:
                    # Checks if the provided IP is in the excluded network
                    if IPAddress(arpentry['ip']) in IPNetwork(excluded_ip):
                        #print "Excluding: {0} From: {1}".format(arpentry['ip'], excluded_ip)
                        matched = True
                        break
                elif arpentry['ip'] == excluded_ip:
                    # ARP is excluded
                    #print "Excluding: {0}".format(arpentry['ip'])
                    #print "Excluded this IP: {0}".format(arpentry['ip'])
                    matched = True
                    break
            # If the IP was never matched, it isn't excluded
            if not matched:
                filtered_listdict.append(arpentry)
        return filtered_listdict
    # This executes if the ip_list is empty, return the listdict unchanged
    else:
        print "No IPs in the exclusion list. Skipping."
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
        nameA = "HostA"
        nameB = "HostB"
        label = nameA + "_" + nameB

        router_a_1 = 'ite-spine-a-1.csv'
        router_a_2 = 'ite-spine-a-2.csv'
        router_b_1 = 'ite-spine-b-1.csv'
        router_b_2 = 'ite-spine-b-2.csv'

        #router_a_1 = 'itw-spn-a-all-arp-1200.csv'
        #router_a_2 = 'itw-spn-a-all-arp-1202.csv'
        #router_b_1 = 'itw-spn-b-all-arp-1159.csv'
        #router_b_2 = 'itw-spn-b-all-arp-1201.csv'

        print subHeading("Import Test Files", 5)
        router_a_1_ld = csvListDict(os.path.join(dir_path, router_a_1))
        router_a_2_ld = csvListDict(os.path.join(dir_path, router_a_2))
        router_b_1_ld = csvListDict(os.path.join(dir_path, router_b_1))
        router_b_2_ld = csvListDict(os.path.join(dir_path, router_b_2))

        # Run comparisons
        # First comparison
        both_perm_remote_dl_1, both_none_dl_1, mac_discrep_dl_1, remove_mac_on_a_dl_1, remove_mac_on_b_dl_1,\
        valid_count_1 = test_compare_capture(router_a_1_ld, router_b_1_ld)
        # Second comparison
        both_perm_remote_dl_2, both_none_dl_2, mac_discrep_dl_2, remove_mac_on_a_dl_2, remove_mac_on_b_dl_2,\
        valid_count_2 = test_compare_capture(router_a_2_ld, router_b_2_ld)
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

            print subHeading("Running First Comparison", 5)
            both_perm_remote_dl_1, both_none_dl_1, mac_discrep_dl_1, remove_mac_on_a_dl_1, remove_mac_on_b_dl_1,\
            valid_count_1 = oper_compare_capture()
            print "-" * 30
            stdout.write("Pausing for 2 mins...")
            sys.stdout.flush()
            time.sleep(120)
            print "Done Waiting"
            print "-" * 30
            print subHeading("Running Second Comparison", 5)
            both_perm_remote_dl_2, both_none_dl_2, mac_discrep_dl_2, remove_mac_on_a_dl_2, remove_mac_on_b_dl_2,\
            valid_count_2 = oper_compare_capture()
            print "-" * 30
        else:
            print "Detected Invalid IPv4 Formatted IPs ... exiting"
    ###############
    # COMMON Code #
    ###############

    # Compare All Results
    both_perm = compare_listdict(both_perm_remote_dl_1, both_perm_remote_dl_2)
    both_none = compare_listdict(both_none_dl_1, both_none_dl_2)
    mac_discr = compare_listdict(mac_discrep_dl_1, mac_discrep_dl_2)
    remove_mac_on_a = compare_listdict(remove_mac_on_a_dl_1, remove_mac_on_a_dl_2)
    remove_mac_on_b = compare_listdict(remove_mac_on_b_dl_1, remove_mac_on_b_dl_2)

    # Clear file parameter lists
    clear_ether_list_perm_remote = []
    clear_ether_list_none = []
    clear_ether_list_a = []
    clear_ether_list_b = []
    clear_arp_list_a = []
    clear_arp_list_b = []

    # Clear send parameter list of dictionaries
    clear_cmds_a = []
    clear_cmds_b = []

    # Add components to correct lists
    # Entries that have 'permanent remote' on both
    for arp_entry in both_perm:
        clear_ether_list_perm_remote.append("clear ethernet-switching table " + arp_entry['mac'] + "\n")
        # Don't have the system automatically remove entries with "perm_remote" on both
        #clear_cmds_a.append({'rpc': 'est', 'mac': arp_entry['mac']})
        #clear_cmds_b.append({'rpc': 'est', 'mac': arp_entry['mac']})
    # Entries that have 'none' on both
    for arp_entry in both_none:
        clear_ether_list_none.append("clear ethernet-switching table " + arp_entry['mac'] + "\n")
        clear_cmds_a.append({'rpc': 'est', 'mac': arp_entry['mac']})
        clear_cmds_b.append({'rpc': 'est', 'mac': arp_entry['mac']})
    # Entries that are missing an ARP on one side,
    for arp_entry in remove_mac_on_a:
        clear_ether_list_a.append("clear ethernet-switching table " + arp_entry['mac'] + "\n")
        clear_cmds_a.append({'rpc': 'est', 'mac': arp_entry['mac']})
    for arp_entry in remove_mac_on_b:
        clear_ether_list_b.append("clear ethernet-switching table " + arp_entry['mac'] + "\n")
        clear_cmds_b.append({'rpc': 'est', 'mac': arp_entry['mac']})
    # Entries that have inconsisent ARP entires (same IP, different MAC)
    for arp_entry in mac_discr:
        clear_arp_list_a.append("clear arp hostname " + arp_entry['ip'] + "\n")
        clear_arp_list_b.append("clear arp hostname " + arp_entry['ip'] + "\n")
        clear_cmds_a.append({'rpc': 'arp', 'ip': arp_entry['ip']})
        clear_cmds_b.append({'rpc': 'arp', 'ip': arp_entry['ip']})

    print subHeading("Creating Log, Configuration, and Results Files", 5)

    # Print Configuration To File
    conf_file = create_conf_file(clear_ether_list_perm_remote, clear_ether_list_none, clear_ether_list_a,
                                 clear_ether_list_b, clear_arp_list_a, clear_arp_list_b, label, nameA, nameB)
    # Email Configuration to Engineers
    email_attachment(conf_file, emailfrom, emailto, label + ' - Config')

    # Print Log Results To File
    log_file = print_results(both_perm, both_none, mac_discr, remove_mac_on_a, remove_mac_on_b, valid_count_1, label,
                             nameA, nameB)
    # Email Log to Engineers
    email_attachment(log_file, emailfrom, emailto, label + ' - Log')

    # Request clear commands on the appropriate device
    if pushChanges:
        print subHeading("Clearing Detected ARPs", 5)
        if getTFAnswer("Continue with clearing ARP and ETHERNET-SWITCHING entries?"):
            headings = ['RPC', 'Mac', 'IP', 'Result', 'Error']
            keys = ['rpc', 'mac', 'ip', 'result', 'error']
            # Make RPC requests to IP1 device
            #print_listdict(clear_cmds_a, headings, keys)
            cmd_results_a = push_changes(ip1, clear_cmds_a)
            '''
            cmd_results_a = [{'rpc': 'est', 'mac': '1c:6a:7a:61:06:49', 'success': True},
                             {'rpc': 'est', 'mac': '58:f3:9c:5a:9d:7b', 'success': True},
                             {'rpc': 'arp', 'ip': '10.112.192.63', 'success': True},
                             {'rpc': 'arp', 'ip': '10.117.18.99', 'success': True},
                             {'rpc': 'arp', 'ip': '10.112.101.20', 'success': True},
                             {'rpc': 'arp', 'ip': '10.112.101.22', 'success': True},
                             {'rpc': 'arp', 'ip': '10.112.151.60', 'success': True},
                             {'rpc': 'arp', 'ip': '10.112.133.22', 'success': True}]
            '''
            # Make RPC requests to IP2 device
            #print_listdict(clear_cmds_b, headings, keys)
            cmd_results_b = push_changes(ip2, clear_cmds_b)
            '''
            cmd_results_b = [{'rpc': 'est', 'mac': '1c:6a:7a:61:06:49', 'success': True},
                             {'rpc': 'est', 'mac': '58:f3:9c:5a:9d:7b', 'success': True},
                             {'rpc': 'arp', 'ip': '10.112.165.25', 'success': True},
                             {'rpc': 'arp', 'ip': '10.112.165.32', 'success': True},
                             {'rpc': 'arp', 'ip': '10.112.101.21', 'success': True},
                             {'rpc': 'arp', 'ip': '10.112.162.126', 'success': True}]
            '''
            results_file = create_results_file(cmd_results_a, cmd_results_b, label, nameA, nameB)
            # Email Results to Engineers
            email_attachment(results_file, emailfrom, emailto, label + ' - Log')

    print "-" * 30

# A function to run RPC commands against Junipers
def push_changes(host_ip, clear_cmds):
    loop_max = 5
    cmd_results = []
    fail_clear_cmds = []
    # Try to connect to the host
    stdout.write("-> Connecting to " + host_ip + " ... ")
    dev = connect(host_ip)
    #dev = True
    if dev:
        print "Connected!"
        # Loop over the dictionary list
        if clear_cmds:
            loop = 1
            # Do this loop if its the first or if its less than 5 and has items in the fail_clear_cmds list
            while loop == 1 or (loop < (loop_max + 1) and clear_cmds):
                # Loop over clear elements
                for entry in clear_cmds:
                    #print entry
                    try:
                        if entry['rpc'] == 'est':
                            if getTFAnswer("Continue clearing ethernet-switching table mac " + entry['mac']):
                                stdout.write("--> Attempting to clear EST " + entry['mac'] + " (" + str(loop) + ") ... ")
                                rsp = dev.rpc.clear_ethernet_switching_table(mac=entry['mac'])
                            else:
                                loop = loop_max + 1
                                break
                            '''
                            if randint(0, 1):
                                rsp = True
                            else:
                                rsp = "est: randomly chose false"
                            '''
                        else:
                            if getTFAnswer("Continue clearing arp table IP " + entry['ip']):
                                stdout.write("--> Attempting to clear ARP " + entry['ip'] + " (" + str(loop) + ") ... ")
                                rsp = dev.rpc.clear_arp_table(hostname=entry['ip'])
                            else:
                                loop = loop_max + 1
                                break
                            '''
                            if randint(0, 1):
                                rsp = True
                            else:
                                rsp = "arp: randomly chose false"
                            '''
                    except RpcError as err:
                        print "Failed: RPC Error: " + err
                        print "Try to print RSP output..."
                        rsp = jxmlease.parse_etree(rsp)
                        print "RSP Output: " + rsp
                        if loop == loop_max:
                            entry['success'] = False
                            entry['error'] = err
                            cmd_results.append(entry)
                            fail_clear_cmds.append(entry)
                    except RpcTimeoutError as err:
                        print "Failed: RPC Timeout Error"
                        if loop == loop_max:
                            entry['success'] = False
                            entry['error'] = err
                            cmd_results.append(entry)
                        else:
                            fail_clear_cmds.append(entry)
                    except Exception as err:
                        print "Failed: Unknown Error"
                        if loop == loop_max:
                            entry['success'] = False
                            entry['error'] = err
                            cmd_results.append(entry)
                        else:
                            fail_clear_cmds.append(entry)
                    else:
                        # If the response is a string, it's a failure
                        if type(rsp) != types.BooleanType:
                            print "Failed: Possible Clear Issue"
                            if loop == loop_max:
                                rsp = jxmlease.parse_etree(rsp)
                                entry['success'] = False
                                entry['error'] = rsp
                                cmd_results.append(entry)
                            else:
                                fail_clear_cmds.append(entry)
                        # Else the response should be "True"
                        else:
                            print "Successful"
                            entry['success'] = True
                            entry['loop'] = loop
                            cmd_results.append(entry)
                # Replace clear_cmds with the new list (old list minus successful clears)
                clear_cmds = fail_clear_cmds
                fail_clear_cmds = []
                # Increase loop by 1
                #print "\nIncrease Loop Value\n"
                loop += 1
        else:
            print "No commands in list!"
    # Return the entries with the results of the clear attempts
    return cmd_results


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
            both_perm_remote_dl, both_none_dl, mac_discrep_dl, remove_mac_on_a_dl, remove_mac_on_b_dl,\
            valid_count = compare_arp_tables(arp_mac_listdict1, arp_mac_listdict2, ip1, ip2)
            return both_perm_remote_dl, both_none_dl, mac_discrep_dl, remove_mac_on_a_dl, remove_mac_on_b_dl, valid_count
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
            both_perm_remote_dl, both_none_dl, mac_discrep_dl, remove_mac_on_a_dl, remove_mac_on_b_dl,\
            valid_count = compare_arp_tables(arp_mac_listdict1, arp_mac_listdict2, ip1, ip2)
            return both_perm_remote_dl, both_none_dl, mac_discrep_dl, remove_mac_on_a_dl, remove_mac_on_b_dl, valid_count
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
    mac_discrep_dl = []             # Format: 'ip', 'mac_a', 'mac_b'

    remove_mac_on_a_dl = []         # Format: 'ip', 'mac', 'flag'
    remove_mac_on_b_dl = []         # Format: 'ip', 'mac', 'flag'

    # Compares A against B
    for arp1 in arptab1:
        no_ip_match = True
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
                    # Catches anything else, for troubleshooting only
                    else:
                        pass
                # If these records have different MACs
                else:
                    #print "Diff MACs - IP: {0} MAC A: {1} MAC B: {2} FLAG A: {3} FLAG B: {4}".format(arp1['ip'],
                    #                                                                                arp1['mac'],
                    #                                                                                arp2['mac'],
                    #                                                                                arp1['flag'],
                    #                                                                                arp2['flag'])
                    mac_discrep_dl.append({'ip': arp1['ip'], 'mac_a': arp1['mac'], 'mac_b': arp2['mac']})
                no_ip_match = False
                break
            # If these records have different IPs
            else:
                # Move onto next IP...
                pass
        # If no match was made, this ARP doesn't exist on B
        if no_ip_match:
            #print "On A, Not B: {0} MAC: {1} FLAG: {2}".format(arp1['ip'], arp1['mac'], arp1['flag'])
            # Checks that flag has a value
            if arp1['flag']:
                # We don't care about permanent flagged ARPs
                if arp1['flag'] == 'permanent':
                    pass
                # Capture all other entries with a missing ARP on side B
                else:
                    remove_mac_on_b_dl.append(arp1)
            # If flag value is missing
            else:
                print "ERROR: On {0} -> Missing Flag for IP: {1}".format(ip1, arp1['ip'])
                remove_mac_on_b_dl.append(arp1)
    # Compares B against A
    for arp2 in arptab2:
        no_ip_match = True
        for arp1 in arptab1:
            if arp2['ip'] == arp1['ip']:
                no_ip_match = False
                break
            else:
                pass
        # If no match was made, this ARP deosn't exist on A
        if no_ip_match:
            #print "On B, Not A: {0} MAC: {1} FLAG: {2}".format(arp2['ip'], arp2['mac'], arp2['flag'])
            # Checks that flag has a value
            if arp2['flag']:
                # We don't care about permanent flagged ARPs
                if arp2['flag'] == 'permanent':
                    pass
                # Capture all other entries with a missing ARP on side A
                else:
                    remove_mac_on_a_dl.append(arp2)
            # If flag value is missing
            else:
                print "ERROR: On {0} -> Missing Flag for IP: {1}".format(ip2, arp2['ip'])
                remove_mac_on_a_dl.append(arp2)
    # Return all lists of dictionaries as a list
    return both_perm_remote_dl, both_none_dl, mac_discrep_dl, remove_mac_on_a_dl, remove_mac_on_b_dl, valid_count

def create_results_file(cmd_results_a, cmd_results_b, label, nameA, nameB):
    # Storage Variables
    a_est_success = []
    a_arp_success = []
    a_est_fail = []
    a_arp_fail = []

    b_est_success = []
    b_arp_success = []
    b_est_fail = []
    b_arp_fail = []

    # Process results
    for entry in cmd_results_a:
        if entry['success']:
            if entry['rpc'] == 'est':
                a_est_success.append({'address': entry['mac'], 'loop': entry['loop']})
            else:
                a_arp_success.append({'address': entry['ip'], 'loop': entry['loop']})
        else:
            if entry['rpc'] == 'est':
                a_est_fail.append({'address': entry['mac'], 'reason': entry['error']})
            else:
                a_arp_fail.append({'address': entry['ip'], 'reason': entry['error']})

    for entry in cmd_results_b:
        if entry['success']:
            if entry['rpc'] == 'est':
                b_est_success.append({'address': entry['mac'], 'loop': entry['loop']})
            else:
                b_arp_success.append({'address': entry['ip'], 'loop': entry['loop']})
        else:
            if entry['rpc'] == 'est':
                b_est_fail.append({'address': entry['mac'], 'reason': entry['error']})
            else:
                b_arp_fail.append({'address': entry['ip'], 'reason': entry['error']})

    # Create config file
    now = get_now_time()
    clear_results = "clear_results_" + label + "_" + now + ".conf"
    myresfile = os.path.join(conf_path, clear_results)

    # Output for the config file
    print_log("## ****************************", myresfile, True)
    print_log("## CLEAR COMMAND RESULTS", myresfile, True)
    print_log("## ****************************", myresfile, True)
    print_log("## Host A: " + nameA + " (" + ip1 + ")", myresfile, True)
    print_log("## Host B: " + nameB + " (" + ip2 + ")", myresfile, True)
    print_log("## ****************************", myresfile, True)
    print_log("## SUMMARY", myresfile, True)
    print_log("## ***********************************", myresfile, True)
    print_log("## Host A ETHER-SWITCHING Table Clears", myresfile, True)
    print_log("## -- Successful .... " + str(len(a_est_success)), myresfile, True)
    print_log("## -- Failed ........ " + str(len(a_est_fail)), myresfile, True)
    print_log("## Host A ARP Table Clears", myresfile, True)
    print_log("## -- Successful .... " + str(len(a_arp_success)), myresfile, True)
    print_log("## -- Failed ........ " + str(len(a_arp_fail)), myresfile, True)
    print_log("## Host B ETHER-SWITCHING Table Clears", myresfile, True)
    print_log("## -- Successful .... " + str(len(b_est_success)), myresfile, True)
    print_log("## -- Failed ........ " + str(len(b_est_fail)), myresfile, True)
    print_log("## Host B ARP Table Clears", myresfile, True)
    print_log("## -- Successful .... " + str(len(b_arp_success)), myresfile, True)
    print_log("## -- Failed ........ " + str(len(b_arp_fail)), myresfile, True)
    print_log("## ***********************************", myresfile, True)

    # Print out the details of the failed clears, if any
    if a_est_fail or b_est_fail:
        print_log("##\n## FAILED ETHER-SWITCHING TABLE CLEARS", myresfile, True)
        if a_est_fail:
            print_log("## Host A:", myresfile, True)
            for entry in a_est_fail:
                print_log("##\t" + entry['address'] + " Reason: " + entry['reason'], myresfile, True)
        if b_est_fail:
            print_log("## Host B:", myresfile, True)
            for entry in b_est_fail:
                print_log("##\t" + entry['address'] + " Reason: " + entry['reason'], myresfile, True)
    if a_arp_fail or b_arp_fail:
        print_log("##\n## FAILED ARP TABLE CLEARS", myresfile, True)
        if a_arp_fail:
            print_log("## Host A:", myresfile, True)
            for entry in a_arp_fail:
                print_log("##\t" + entry['address'] + " Reason: " + entry['reason'], myresfile, True)
        if b_arp_fail:
            print_log("## Host B:", myresfile, True)
            for entry in b_arp_fail:
                print_log("##\t" + entry['address'] + " Reason: " + entry['reason'], myresfile, True)

    # Print out the details of the successful clears, if any
    if a_est_success or b_est_success:
        print_log("##\n## SUCCESSFUL ETHER-SWITCHING TABLE CLEARS", myresfile, True)
        if a_est_success:
            print_log("## Host A:", myresfile, True)
            for entry in a_est_success:
                print_log("##\t" + entry['address'] + " (" + str(entry['loop']) + ")", myresfile, True)
        if b_est_success:
            print_log("## Host B:", myresfile, True)
            for entry in b_est_success:
                print_log("##\t" + entry['address'] + " (" + str(entry['loop']) + ")", myresfile, True)
    if a_arp_success or b_arp_success:
        print_log("##\n## SUCCESSFUL ARP TABLE CLEARS", myresfile, True)
        if a_arp_success:
            print_log("## Host A:", myresfile, True)
            for entry in a_arp_success:
                print_log("##\t" + entry['address'] + " (" + str(entry['loop']) + ")", myresfile, True)
        if b_arp_success:
            print_log("## Host B:", myresfile, True)
            for entry in b_arp_success:
                print_log("##\t" + entry['address'] + " (" + str(entry['loop']) + ")", myresfile, True)
    print_log("##", myresfile, True)

    # Print file name
    print "-"*50
    print "Completed Clear Results File: {0}".format(clear_results)

    return myresfile


def create_conf_file(clear_ether_list_perm_remote, clear_ether_list_none, clear_ether_list_a, clear_ether_list_b,
                     clear_arp_list_a, clear_arp_list_b, label, nameA, nameB):
    # Create config file
    now = get_now_time()
    clear_conf_name = "clear_comds_" + label + "_" + now + ".conf"
    myconfile = os.path.join(conf_path, clear_conf_name)

    # Output for the config file
    print_log("## CLEAR CONFIGURATION COMMANDS", myconfile, True)
    print_log("## ****************************", myconfile, True)
    print_log("## Host A: " + nameA + " (" + ip1 + ")", myconfile, True)
    print_log("## Host B: " + nameB + " (" + ip2 + ")", myconfile, True)
    print_log("## ***********************************************", myconfile, True)
    print_log("## Both entries 'PERMANENT REMOTE' .......... " + str(len(clear_ether_list_perm_remote)), myconfile, True)
    print_log("## Both entries 'NONE' ...................... " + str(len(clear_ether_list_none)), myconfile, True)
    print_log("## Entries in ETHER-SWITCHING on A, not B ... " + str(len(clear_ether_list_a)), myconfile, True)
    print_log("## Entries in ETHER-SWITCHING on B, not A ... " + str(len(clear_ether_list_b)), myconfile, True)
    print_log("## Entries in ARP on A, not B ............... " + str(len(clear_arp_list_a)), myconfile, True)
    print_log("## Entries in ARP on B, not A ............... " + str(len(clear_arp_list_b)), myconfile, True)
    print_log("## ***********************************************", myconfile, True)

    # Create configuration file with clear commands if applicable
    if clear_ether_list_perm_remote:
        # Loop ether_list and add commands
        print_log("##\n## Both entries 'Permanent Remote' - Check and Run these commands on both devices.\n##", myconfile, True)
        for command in clear_ether_list_perm_remote:
            print_log(command, myconfile)

    if clear_ether_list_none:
        # Loop ether_list and add commands
        print_log("##\n## Both entries 'None' - Run these commands on both devices.\n##", myconfile, True)
        for command in clear_ether_list_none:
            print_log(command, myconfile)

    if clear_ether_list_a:
        # Loop ether_list and add commands
        print_log("##\n## Exists in ethernet-switching table as permanent|remote on A, not B - Run these commands on " + ip1 + "\n##", myconfile, True)
        for command in clear_ether_list_a:
            print_log(command, myconfile)

    if clear_ether_list_b:
        # Loop ether_list and add commands
        print_log("##\n## Exists in ethernet-switching table as permanent|remote on B, not A - Run these commands on " + ip2 + "\n##", myconfile, True)
        for command in clear_ether_list_b:
            print_log(command, myconfile)

    if clear_arp_list_a:
        # Loop arp_list and add commands
        print_log("##\n## Exists in arp table on A, not B - Run these commands on " + ip1 + "\n##", myconfile, True)
        for command in clear_arp_list_a:
            print_log(command, myconfile)

    if clear_arp_list_b:
        # Loop arp_list and add commands
        print_log("##\n## Exists in arp table on B, not A - Run these commands on " + ip2 + "\n##", myconfile, True)
        for command in clear_arp_list_b:
            print_log(command, myconfile)
    print_log("##", myconfile, False)

    # Print file name
    print "-" * 50
    print "Completed Config File: {0}".format(clear_conf_name)

    return myconfile

# Function for running operational commands to multiple devices
def arp_commands(arp_clear=None, ethsw_clear=None):
    print "*" * 50 + "\n" + " " * 10 + "ARP CLEAR COMMANDS\n" + "*" * 50
    # Provide selection for sending a single command or multiple commands from a file
    if arp_clear:
        rpc_command = clear_arp_table

    if my_ips:
        command_list = []
        print "\n" + "*" * 110 + "\n"
        command_list = getMultiInputAnswer("Enter a command to run")

        if getTFAnswer("Continue with operational requests?"):
            output_log = create_timestamped_log("oper_output_", "log")
            err_log = create_timestamped_log("oper_err_", "log")
            # Header of operational command output
            screen_and_log(starHeading("OPERATIONAL COMMANDS OUTPUT", 110), output_log)
            screen_and_log(('User: {0}\n').format(username), output_log)
            screen_and_log(('Performed: {0}\n').format(get_now_time()), output_log)
            screen_and_log(('Output Log: {0}\n').format(output_log), output_log)
            screen_and_log(('Error Log: {0}\n').format(err_log), output_log)
            screen_and_log(starHeading("COMMANDS EXECUTED", 110), output_log)
            for command in command_list:
                screen_and_log(' -> {0}\n'.format(command), output_log)
            screen_and_log('*' * 110 + '\n', output_log)

            # Loop over commands and devices
            devs_unreachable = []
            devs_no_output = []
            devs_with_output = []
            loop = 0
            try:
                screen_and_log("-" * 110 + "\n", output_log)
                for ip in my_ips:
                    command_output = ""
                    loop += 1
                    stdout.write("-> Connecting to " + ip + " ... ")
                    dev = connect(ip)
                    if dev:
                        print "Connected!"
                        hostname = dev.facts['hostname']
                        if not hostname:
                            hostname = "Unknown"
                        got_output = False
                        # Loop over the commands provided
                        if command_list:
                            stdout.write(hostname + ": Executing commands ")
                            for command in command_list:
                                command_output += "\n" + hostname + ": Executing -> {0}\n".format(command)
                                #com = dev.cli_to_rpc_string(command)
                                #print "Command: {0}\nRPC: {1}\n".format(command, com)
                                #if com is None:
                                try:
                                    results = dev.cli(command, warning=False)
                                except Exception as err:
                                    stdout.write("\n")
                                    screen_and_log("{0}: Error executing '{1}'. ERROR: {2}\n".format(ip, command, err), err_log)
                                    stdout.write("\n")
                                else:
                                    if results:
                                        command_output += results
                                        got_output = True
                                    stdout.write(".")
                                    stdout.flush()
                            if got_output:
                                devs_with_output.append(ip)
                                screen_and_log(command_output, output_log)
                                stdout.write("\n")
                            else:
                                devs_no_output.append(ip)
                                stdout.write(" No Output!\n")
                        # If no commands are provided, run the get_chassis_inventory on devices
                        else:
                            get_chassis_inventory(dev, hostname)
                        # Close connection to device
                        try:
                            dev.close()
                        except TimeoutExpiredError as err:
                            print "Error: {0}".format(err)
                            break
                    else:
                        screen_and_log("{0}: Unable to connect\n".format(ip), err_log)
                        devs_unreachable.append(ip)
                screen_and_log("-" * 110 + "\n", output_log)
                screen_and_log(starHeading("COMMANDS COMPLETED", 110), output_log)
                # Results of commands
                screen_and_log(starHeading("PROCESS SUMMARY", 110), output_log)
                screen_and_log("Devices With Output:  {0}\n".format(len(devs_with_output)), output_log)
                screen_and_log("Devices No Output:    {0}\n".format(len(devs_no_output)), output_log)
                screen_and_log("Devices Unreachable:  {0}\n".format(len(devs_unreachable)), output_log)
                screen_and_log("Total Devices:        {0}\n".format(len(my_ips)), output_log)
                screen_and_log("*" * 110 + "\n", output_log)
            except KeyboardInterrupt:
                print "Exiting Procedure..."
        else:
            print "\n!!! Configuration deployment aborted... No changes made !!!\n"
    else:
        print "\n!! Configuration deployment aborted... No IPs defined !!!\n"

def print_results(both_perm_remote_dl, both_none_dl, mac_discrep_dl, remove_mac_on_a_dl,
                  remove_mac_on_b_dl, valid_count, label, nameA, nameB):
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
    # Show entries that are both 'Permanent Remote'
    print_log("-"*100, mylogfile, True)
    print_log("- Both ARPs Permanent Remote -", mylogfile, True)
    print_log("-"*100, mylogfile, True)
    if both_perm_remote_dl:
        for item in both_perm_remote_dl:
            print_log("\t" + "IP: " + item['ip'] + " | MAC: " + item['mac'], mylogfile, True)
    else:
        print_log("\tNo Matches Found", mylogfile, True)
    # Show entries that are both 'None'
    print_log("-"*100, mylogfile, True)
    print_log("- Both ARPs None -", mylogfile, True)
    print_log("-"*100, mylogfile, True)
    if both_none_dl:
        for item in both_none_dl:
            print_log("\t" + "IP: " + item['ip'] + " | MAC: " + item['mac'], mylogfile, True)
    else:
        print_log("\tNo Matches Found", mylogfile, True)
    # Show the ARP/MAC Discrepancies
    print_log("-"*100, mylogfile, True)
    print_log("- ARP Discrepancies -", mylogfile, True)
    print_log("-"*100, mylogfile, True)
    if mac_discrep_dl:
        for item in mac_discrep_dl:
            print_log("\t" + "IP: " + item['ip'] + " | MAC on A: " + item['mac_a'] + " | MAC on B: " + item['mac_b'], mylogfile, True)
    else:
        print_log("\tNo Matches Found", mylogfile, True)
    # Show ARPS that are on A, but not on B
    complete_b_dl = remove_mac_on_b_dl
    print_log("-"*100, mylogfile, True)
    print_log("- ARPs on A, NOT on B -", mylogfile, True)
    print_log("-"*100, mylogfile, True)
    if complete_b_dl:
        sorted_list = list_dict_custom_sort(complete_b_dl, 'flag', ['none'])
        for item in sorted_list:
            print_log("\t" + "IP: " + item['ip'] + " | MAC: " + item['mac'] + " | FLAG: " + item['flag'], mylogfile, True)
    else:
        print_log("\tNo Matches Found", mylogfile, True)
    # Show ARPS that are on B, but not on A
    complete_a_dl = remove_mac_on_a_dl
    print_log("-"*100, mylogfile, True)
    print_log("- ARPs on B, NOT on A -", mylogfile, True)
    print_log("-"*100, mylogfile, True)
    if complete_a_dl:
        sorted_list = list_dict_custom_sort(complete_a_dl, 'flag', ['none'])
        for item in sorted_list:
            print_log("\t" + "IP: " + item['ip'] + " | MAC: " + item['mac'] + " | FLAG: " + item['flag'], mylogfile, True)
    else:
        print_log("\tNo Matches Found", mylogfile, True)
    print_log("-"*100, mylogfile, True)
    print_log("-----------------------------", mylogfile, True)
    print_log("Total Both Permanent:....." + str(len(both_perm_remote_dl)), mylogfile, True)
    print_log("Total Both None:.........." + str(len(both_none_dl)), mylogfile, True)
    print_log("Total ARP Discrepancies:.." + str(len(mac_discrep_dl)), mylogfile, True)
    print_log("Total ARP on B, Not A:...." + str(len(complete_a_dl)), mylogfile, True)
    print_log("Total ARP on A, Not B:...." + str(len(complete_b_dl)), mylogfile, True)
    print_log("Total Valid ARPs:........." + str(valid_count), mylogfile, True)
    print_log("-----------------------------\n", mylogfile, True)

    # Print file name
    print "-" * 50
    print "Completed Results File: {0}".format(log_name)

    return mylogfile

# Print a list dictionary using PrettyTable
def print_listdict(list_dict, headings, keys):
    """ 
        Purpose: Display a table showing contents of the list dictionary.
        Returns: Nothing
    """
    t = PrettyTable(headings)
    for host_dict in list_dict:
        # print device
        mylist = []
        for key in keys:
            if key in host_dict.keys():
                mylist.append(host_dict[key])
            else:
                mylist.append("")
        t.add_row(mylist)
    print t
    print "Total Items: {0}".format(len(list_dict))

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