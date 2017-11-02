# File: utility.py
# Author: Tyler Jordan
# Modified: 11/2/2017
# Purpose: Assist CBP engineers with Juniper configuration tasks

import csv
import datetime
import difflib
import fileinput
import glob
import json
import operator
import os
from os import listdir
from os.path import isfile, join
from sys import stdout

#--------------------------------------
# ANSWER METHODS
#--------------------------------------
# Method for asking a question that has a single answer, returns answer
def getOptionAnswer(question, options):
    answer = ""
    loop = 0
    while not answer:
        for option in options:
            loop += 1
            print '[' + str(loop) + '] -> ' + option
        answer = raw_input(question + ': ')
        try:
            if answer == "":
                return answer
            if int(answer) >= 1 and int(answer) <= loop:
                index = int(answer) - 1
                return options[index]
        except Exception as err:
            print "Invalid Entry - ERROR: {0}".format(err)
        else:
            print "Bad Selection"
        answer = ""
        loop = 0

# Method for asking a question that can have multiple answers, returns list of answers
def getOptionMultiAnswer(question, options):
    answer_str = ""
    loop = 0
    while not answer_str and options:
        for option in options:
            loop += 1
            print '[' + str(loop) + '] -> ' + option
        answer_str = raw_input(question + ': ')
        try:
            answer_list = []
            index_list = answer_str.split(",")
            for answer in index_list:
                index = int(answer) - 1
                answer_list.append(options[index])
            return answer_list
        except Exception as err:
            print "Invalid Entry - ERROR: {0}".format(err)
        else:
            print "Bad Selection"
        answer_str = ""
        loop = 0

# Method for asking a question that has a single answer, returns answer index
def getOptionAnswerIndex(question, options):
    answer = ""
    loop = 0
    while not answer:
        for option in options:
            loop += 1
            print '[' + str(loop) + '] -> ' + option
        answer = raw_input(question + ': ')
        try:
            if int(answer) >= 1 and int(answer) <= loop:
                return answer
        except Exception as err:
            print "Invalid Entry - ERROR: {0}".format(err)
        else:
            print "Bad Selection"
        answer = ""
        loop = 0

# Method for asking a user input question
def getInputAnswer(question):
    answer = ""
    while not answer:
        answer = raw_input(question + ': ')
    return answer

# Method for asking a user input question that can have multiple answers
def getMultiInputAnswer(question):
    answer_list = []
    answer = "placeholder"
    while answer:
        answer = raw_input(question + ': ')
        if answer:
            answer_list.append(answer)
    return answer_list

# Method for asking a Y/N question
def getYNAnswer(question):
    answer = ""
    while not answer:
        answer = raw_input(question + '(y/n): ')
        if answer == 'Y' or answer == 'y':
            answer = 'y'
        elif answer == 'N' or answer == 'n':
            answer = 'n'
        else:
            print "Bad Selection"
            answer = ""
    return answer

# Method for asking a Y/N question, return True or False
def getTFAnswer(question):
    answer = False
    while not answer:
        ynanswer = raw_input(question + '(y/n): ')
        if ynanswer == 'Y' or ynanswer == 'y':
            answer = True
            return answer
        elif ynanswer == 'N' or ynanswer == 'n':
            answer = False
            return answer
        else:
            print "Bad Selection"

# Method for creating a log file
def createLogFile(path_and_file, columns, delimiter=","):
    try:
        with open(path_and_file, 'w+') as fh:
            header_line = ''
            # Loops over all column headers in list, except for the last one
            for column in columns[:-1]:
                header_line += column + delimiter
            # Add the last header without a delimiter
            header_line += columns[-1]
            # Write header to file
            fh.write(header_line)
    except Exception as err:
        print "Error opening/writing to file -> ERROR: {0}".format(err)
        return False
    else:
        return True

# Return list of files from a directory
def getFileList(mypath):
    fileList = []
    try:
        for afile in listdir(mypath):
            if isfile(join(mypath,afile)):
                fileList.append(afile)
    except:
        print "Error accessing directory: " + mypath

    return fileList

# Method for requesting IP address target
def getTarget():
    print 64*"="
    print "= Scan Menu                                                    ="
    print 64*"="
    # Loop through the IPs from the file "ipsitelist.txt"
    loop = 0
    list = {};
    for line in fileinput.input('ipsitelist.txt'):
        # Print out all the IPs/SITEs
        loop += 1
        ip,site = line.split(",")
        list[str(loop)] = ip;
        print '[' + str(loop) + '] ' + ip + ' -> ' + site.strip('\n')

    print "[c] Custom IP"
    print "[x] Exit"
    print "\n"

    response = ""
    while not response:
        response = raw_input("Please select an option: ")
        if response >= "1" and response <= str(loop):
            return list[response]
        elif response == "c":
            capturedIp = ""
            while not capturedIp:
                capturedIp = raw_input("Please enter an IP: ")
                return capturedIp
        elif response == "x":
            response = "exit"
            return response
        else:
            print "Bad Selection"

# Takes a text string and creates a top level heading
def topHeading(rawtext, margin):
    head_length = len(rawtext)
    equal_length = head_length + 6

    heading = " " * margin + "+" + "=" * equal_length + "+\n" +\
              " " * margin + "|   " + rawtext + "   |\n" +\
              " " * margin + "+" + "=" * equal_length + "+\n"

    return heading

# Takes a string and creates a sub heading
def subHeading(rawtext, margin):
    head_length = len(rawtext)
    dash_length = head_length + 2

    heading = " " * margin + "o" + "-" * dash_length + "o\n" +\
              " " * margin + "| " + rawtext + " |\n" +\
              " " * margin + "o" + "-" * dash_length + "o\n"

    return heading

# Common method for accessing multiple routers
def chooseDevices():
    # Define the routers to deploy the config to (file/range/custom)
    print "**** Configuration Deployment ****"
    method_resp = getOptionAnswer('How would you like to define the devices', ['file', 'range', 'custom'])
    ip_list = []
    # Choose a file from a list of options
    if method_resp == "file":
        print "Defining a file..."
        path = '.\ips\*.ips'
        files=glob.glob(path)
        file_resp = getOptionAnswer('Choose a file to use', files)

        # Print out all the IPs/SITEs
        for line in fileinput.input(file_resp):
            ip_list.append(line)

    # Define a certain range of IPs
    elif method_resp == "range":
        print "Defining a range..."

    # Define one or more IPs individually
    elif method_resp == "custom":
        print 'Define using /32 IP Addresses'
        answer = ""
        while( answer != 'x' ):
            answer = getInputAnswer('Enter an ip address (x) to exit')
            if( answer != 'x'):
                ip_list.append(answer)

    # Print the IPs that will be used
    loop = 1;
    for my_ip in ip_list:
        print 'IP' + str(loop) + '-> ' + my_ip
        loop=loop + 1

    return ip_list

# Creates a new CSV based on contents of listDict
def listdict_to_csv(aListDict, csvPathName, myDelimiter, columnNames=[]):
    # If columnNames is empty, get the column names from the list dict
    if not columnNames:
        for mydict in aListDict:
            for key in mydict:
                columnNames.append(key)
            break

    # Attempt to open the file and write entries to csv
    if not os.path.exists(csvPathName):
        os.mknod(csvPathName)
    try:
        with open(csvPathName, 'w') as csvfile:
            writer = csv.DictWriter(csvfile, delimiter=myDelimiter, fieldnames=columnNames)
            writer.writeheader()
            writer.writerows(aListDict)
        return True
    except Exception as err:
        print "ERROR: Problem writing to file {0} : {1}".format(csvPathName, err)
        return False

# Converts CSV file to listDict. First line is considered column headers.
def csvListDict(fileName, keys=''):
    myListDict = []
    try:
        with open(fileName) as myfile:
            firstline = True
            for line in myfile:
                if firstline:
                    if not keys:
                        keys = "".join(line.split()).split(',')
                    firstline = False
                else:
                    values = "".join(line.split()).split(',')
                    myListDict.append({keys[n]:values[n] for n in range(0,len(keys))})
    except Exception as err:
        print "Failure converting CSV to listDict - ERROR: {0}".format(err)
    else:
        print "File Import Complete!"
    return myListDict

# Converts CSV file to Dictionary
def csv_to_dict(filePathName, mydelim=","):
    input_file = csv.DictReader(open(filePathName), delimiter=mydelim)
    for row in input_file:
        return row

# Converts a two term CSV file into a dicionary of key, value pairs
def csv_to_dict_twoterm(filePathName, mydelim=","):
    try:
        with open(filePathName) as f:
            d = dict(filter(None, csv.reader(f, delimiter=mydelim)))
    except Exception as err:
        print "Error converting file to dictionary: ERROR: {0}".format(err)
    else:
        return d

# Removes a record from the specified list of dictionaries
def remove_record(listDict, key, value):
    """ Purpose: Remove a record from the provided list of dictionaries. 
    NOTE: Removes only the first record found with the specified value.

    :param key:         -   The key to search for
    :param value:       -   The value to search for
    :return:            -   Returns True/False
    """
    was_changed = False
    for record in listDict:
        #print "Provided: {0} -> Comparing to Key: {1} | Value: {2} --> ".format(listDict[i][key], key, value)
        if record[key] == value:
            #print "Removing: {0}".format(listDict[i])
            listDict.remove(record)
            print "| Device Removed!"
            was_changed = True
    if was_changed:
        return listDict
    else:
        return False

# Gets a record
def get_record(listDict, ip='', hostname='', sn='', code=''):
    """ Purpose: Returns a record from the listDict containing hostname, ip, model, version, serial number. Providing
                three different methods to return the data.

        :param ip:          -   String of the IP of the device
        :param hostname:    -   String of the device hostname
        :parma sn:          -   String of the device chassis serial number
        :param code:        -   String of the JunOS code version
        :returns:           -   Dictionary of device attributes
    """
    has_record = False
    # Make sure listDict has contents
    if listDict:
        if ip:
            for record in listDict:
                # Make sure this info exists, it may have failed
                if 'inet_intf' in record:
                    for inet_intf in record['inet_intf']:
                        if inet_intf['ipaddr'] == ip:
                            return record
                # If it did, just search the 'ip" attribute
                else:
                    if record['ip'] == ip:
                        return record
        elif hostname:
            for record in listDict:
                if record['hostname'] == hostname:
                    return record
        elif sn:
            for record in listDict:
                if record['serialnumber'] == sn:
                    return record
        elif code:
            for record in listDict:
                if record['version'] == code:
                    return record
        else:
            return has_record
    else:
        return has_record

# Write database to JSON
def write_to_json(list_dict, main_list_dict):
    try:
        with open(main_list_dict, 'w') as fout:
            json.dump(list_dict, fout)
    except Exception as err:
        print "Problem opening or writing to JSON file from database -> ERROR: {0}".format(err)
        return False
    else:
        return True

def json_to_listdict(json_file):
    list_data = []
    if not os.path.exists(json_file):
        return list_data
    else:
        try:
            with open(json_file) as fin:
                list_data = json.load(fin)
        except Exception as err:
            print "Problem opening or reading from JSON to database -> ERROR: {0}".format(err)
            return False
        else:
            return list_data

# Write new entries from list_dict to csv file, then sort the csv file
def csv_write_sort(list_dict, csv_file, sort_column, reverse_sort=False, column_names=[], my_delimiter=","):
    '''
    :param myListDict: List - the list dictionary with the entries to add to the csv
    :param csv_file: String - the csv file to save the new entries to
    :param sort_column: Integer - the column number to sort by
    :param field_names: List - use if you want the CSV columns in a specific order 
    :param sort_order: Boolean - sets the "reverse" value for the "sorted" function. Default: "False"
        - Sorting Dates: True = newest date to oldest date
        - Sorting Alphas: True = Z to A (NOTE: lowercase is preferred to uppercase)
        - Sorting Numbers: True = high to low
    :param my_delimiter: String - contains the delimiter for csv file . Default: ","
    :return: NONE
    '''
    # Write new entries to csv file
    if listdict_to_csv(list_dict, csv_file, my_delimiter, column_names):
        # Opens the file for reading only, places pointer at beginning
        with open(csv_file, "r") as f:
            reader = csv.reader(f, delimiter=my_delimiter)
            # Skip the first line
            headers = reader.next()
            try:
                # Attempt to sort the contents, sorting by the third column values, from newest to oldest
                sortedlist = sorted(reader, key=operator.itemgetter(sort_column), reverse=reverse_sort)
            except Exception as err:
                print "Issue sorting file -> ERROR: {0}".format(err)
                return False
            else:
                try:
                    # Opens the file and overwrites if it already exists
                    with open(csv_file, "w") as f:
                        # This writes the newly sorted data to the file
                        fileWriter = csv.writer(f, delimiter=my_delimiter)
                        # Write the headers first
                        fileWriter.writerow(headers)
                        for row in sortedlist:
                            fileWriter.writerow(row)
                except Exception as err:
                    print "Issue writing to file -> ERROR: {0}".format(err)
                    return False
                else:
                    return True
    else:
        print "ERROR: Unable to perform sort.".format(csv_file)
        return False

# Sorts a list of dictionaries based on supplied key/value pair
def list_dict_custom_sort(list_dict, sort_attrib, sort_list, exclusion_attrib, exclustion_list):
    #print "Intf List:"
    #print list_dict
    # Sort the dictionary list
    mylist = []

    # Loop over list to get primary interfaces
    for sort_val in sort_list:
        for intf_rec in list_dict:
            #print "Compare [{0}] to [{1}]".format(item, intf_rec[sort_attrib])
            #print "Sort Val: {0} | Attrib Val: {1}".format(sort_val, intf_rec[sort_attrib])
            if intf_rec[sort_attrib] == sort_val:
                if intf_rec[exclusion_attrib] not in exclustion_list:
                    #print "Selected {0}".format(sort_val)
                    mylist = sorted(list_dict, key=lambda x: x[sort_attrib] != sort_val)
                    return mylist
                #else:
                #    print "Excluded {0} due to {1}".format(sort_val, intf_rec[exclusion_attrib])
    return mylist

# Accetps a masked or unmasked IP and returns the IP and mask in a list
def get_ip_mask(masked_ip):

    ip_mask_list = []
    if "/" in masked_ip:
        ip_mask_list = masked_ip.split("/")
    else:
        ip_mask_list.append(masked_ip)
        ip_mask_list.append('32')

    return ip_mask_list

# Analyze listDict and create statistics (Upgrade)
def tabulateUpgradeResults(listDict):
    statusDict = {'success_rebooted': [],'success_not_rebooted': [], 'connect_fails': [], 'software_install_fails': [], 'total_devices': 0}

    for mydict in listDict:
        if mydict['Connected'] == 'Y' and mydict['OS_installed'] == 'Y':
            if mydict['Rebooted'] == 'Y':
                statusDict['success_rebooted'].append(mydict['IP'])
            else:
                statusDict['success_not_rebooted'].append(mydict['IP'])
        elif mydict['Connected'] == 'Y' and mydict['OS_installed'] == 'N':
            statusDict['software_install_fails'].append(mydict['IP'])
        elif mydict['Connected'] == 'N':
            statusDict['connect_fails'].append(mydict['IP'])
        else:
            print("Error: Uncaptured Result")
        # Every device increments this total
        statusDict['total_devices'] += 1

    return statusDict

# Analyze listDict and create statistics (Reboot)
def tabulateRebootResults(listDict):
    statusDict = {'rebooted': [], 'not_rebooted': [], 'connect_fails': [], 'total_devices': 0}

    for mydict in listDict:
        if mydict['Connected'] == 'Y':
            if mydict['Rebooted'] == 'Y':
                statusDict['rebooted'].append(mydict['IP'])
            else:
                statusDict['not_rebooted'].append(mydict['IP'])
        elif mydict['Connected'] == 'N':
            statusDict['connect_fails'].append(mydict['IP'])
        else:
            print("Error: Uncaptured Result")
        # Every device increments this total
        statusDict['total_devices'] += 1

    return statusDict

def compare_configs(config1, config2):
    """ Purpose: To compare two configs and get the changes.
        Returns: True means there are differences, false means they are the same.
    """
    change_list = []
    if config1 and config2:
        config1_lines = config1.splitlines(1)
        config2_lines = config2.splitlines(1)

        diffInstance = difflib.Differ()
        diffList = list(diffInstance.compare(config1_lines, config2_lines))

        #print '-'*50
        #print "Lines different in config1 from config2:"
        for line in diffList:
            if line[0] == '-':
                change_list.append(line)
                #print line,
            elif line[0] == '+':
                change_list.append(line)
                #print line,
        #print '-'*50
    else:
        print "ERROR with compare configs, check configs."
    return change_list

# Print output to the screen and a log file (either a list or string)
def print_sl(statement, file_list):
    # Print to screen
    stdout.write(statement)
    # Print to log
    if type(file_list) is list:
        for log in file_list:
            print_log(statement, log)
    else:
        print_log(statement, file_list)

# Append output to log file only
def print_log(statement, logfile):
    # Print to log
    #print "Log File: {0}".format(logfile)
    try:
        logobj = open(logfile, 'a')
    except Exception as err:
        print "Error opening log file {0}".format(err)
    else:
        logobj.write(statement)
        logobj.close()

# Write text to a file. Overwrite existing contents.
def print_file(statement, myfile):
    # Print to log
    #print "Log File: {0}".format(logfile)
    try:
        myobj = open(myfile, 'w')
    except Exception as err:
        print "Error opening log file {0}".format(err)
    else:
        myobj.write(statement)
        myobj.close()

# Return a specifically formatted timestamp
def get_now_time():
    """ Purpose: Create a formatted timestamp

    :return:            -   String of the timestamp in "YYYY-MM-DD_HHMM" format
    """
    now = datetime.datetime.now()
    return now.strftime("%Y-%m-%d_%H%M")

# Convert "XML" formatted file to "set" formatted file
def xml_to_set(xml_output):
    # Regular Expressions
    config_regex = r'<\/?configuration.*>'
    term_value_regex = r'<.+>.+<\/.+>'         # Matches <term>value</term>
    value_regex = r'>[^\/]+<'
    term_regex = r'<.+>'
    term_noslash_regex = r'^<[^\/]+>'

    close_regex = r'\/.+'
    val_regex = r'.+\/'

    # Lists
    quote_list = ['secret', 'authentication-key', 'privacy-key', "encrypted-password", "full-name"]
    multi_line_list = ['announcement', 'message']
    level_list = []
    set_list = []

    my_file_list = line_list(xml_output)
    if my_file_list:
        multi_line = False
        set_line = ""
        prev_name = False
        prev_name_val = ""
        prev_name_parent = ""
        prev_open = ""

        # Start looping of lines of the XML configuration
        for line in my_file_list:
            # Remove all preceeding whitespace
            raw_line = line.lstrip()
            print "\n" + "-" * 50
            #print "Raw Line: {0}".format(line)
            line = line.lstrip().rstrip()
            print "Stripped Line: {0}".format(line)

            # Match string with a term and value
            if re.match(term_value_regex, line):
                t = re.search(term_noslash_regex, line)
                term = t.group(0).lstrip('<').rstrip('>')
                v = re.search(value_regex, line)
                value = v.group(0).lstrip('>').rstrip('<')
                # Check if prev_name is set to True, if it is, we need to add a level
                if prev_name:
                    level_list.append(prev_name_val)
                    prev_name = False
                # If term/value is term "name", we might need to treat "value" as the level
                if term == "name":
                    prev_name_val = value
                    prev_name_parent = level_list[-1]
                    prev_name = True
                else:
                    set_line = "set"
                    for a_level in level_list:
                        set_line += ' ' + a_level
                    if term in quote_list:
                        set_line += ' ' + term + ' "' + value + '"'
                    else:
                        set_line += ' ' + term + ' ' + value
                    print "SET: {0}".format(set_line)
                    set_list.append(set_line)
                prev_open = ""
            # Match string against config term regex
            elif re.match(config_regex, line):              # Matches </configuration and <configuration
                if line.startswith( "</configuration"):
                    print "--- END OF CONFIGURATION ---"
                    break
                else:
                    print "--- START OF CONFIGURATION ---"
                prev_open = ""
            # Match string with a term
            elif re.match(term_regex, line):                # Matches <*>
                t = re.search(term_regex, line)
                term = t.group(0).lstrip('<').rstrip('>')
                # Match a close term
                if re.match(close_regex, term):             # Matches /term
                    term = term.lstrip("/")
                    if term == "contents":
                        pass
                    # If prev_name is True and this term is the "close" of the parent, print term and remove this level
                    elif prev_name and term == prev_name_parent:
                        set_line = "set"
                        for a_level in level_list:
                            set_line += ' ' + a_level
                        set_line += ' ' + prev_name_val
                        print "SET: {0}".format(set_line)
                        set_list.append(set_line)
                        prev_name = False
                        print "Removing Level: {0}".format(level_list[-1])
                        del level_list[-1]
                    # If this close term is a multi_line term
                    elif multi_line and term in multi_line_list:
                        # Add current line to the list
                        set_line += '"'
                        print "SET: {0}".format(set_line)
                        set_list.append(set_line)
                        multi_line = False
                    # If the previous term was an open of the same term
                    elif prev_open == term:
                        set_line = "set"
                        for a_level in level_list:
                            set_line += ' ' + a_level
                        print "SET: {0}".format(set_line)
                        set_list.append(set_line)
                        del level_list[-1]
                    # Otherwise this is a standard close term
                    else:
                        while level_list[-1] != term:
                            print "Removing Level: {0}".format(level_list[-1])
                            del level_list[-1]
                        else:
                            if level_list[-1] == term:
                                print "Removing Final Level: {0}".format(level_list[-1])
                                del level_list[-1]
                            else:
                                print "Unexpected value in level list!"
                                print "Current Term: '{0}'".format(term)
                                print "List Level: '{0}'".format(level_list[-1])
                    prev_open = ""
                # Match a value term
                elif re.match(val_regex, term):             # Matches term/
                    term = term.rstrip("/")
                    # If the previous term was a "name" term
                    if prev_name:
                        level_list.append(prev_name_val)
                        prev_name = False
                    set_line = "set"
                    for a_level in level_list:
                        set_line += ' ' + a_level
                    set_line += ' ' + term
                    print "SET: {0}".format(set_line)
                    set_list.append(set_line)
                    prev_open = ""
                # Matches an open term
                else:                                       # Matches term
                    # If the previous term as "name", we need to add name value as a level
                    if prev_name:
                        level_list.append(prev_name_val)
                        prev_name = False
                    # If current term is "contents", ignore it
                    if term == "contents":
                        pass
                    # If current term is a "multi-line" term, create a set for it
                    elif term in multi_line_list:
                        value = ""
                        set_line = "set"
                        if raw_line.startswith( '<' + term + '>'):
                            value = raw_line.split('>', 1)
                        for a_level in level_list:
                            set_line += ' ' + a_level
                        set_line += ' ' + term + ' "' + value[1]
                        multi_line = True
                    else:
                        # Add a term to the level list
                        level_list.append(term)
                    prev_open = term
            # Match all other formats, which should only be multi-line content
            else:
                if multi_line:
                    set_line += raw_line
                else:
                    print "Content not captured!"
                    print "Content: '{0}'".format(raw_line)
                prev_open = ""

        print "### SET LIST ###"
        print set_list