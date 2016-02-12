'''			VMware Log Insight EPS Calculator
This simple python script is run against your vCD Cells and will give you an estimate on 
your Events Per Second as well as the bandwidth consumed by syslog events.

REQUIRED scp to be installed if you connect to remote hosts. Install it with 
"pip install scp" from the command line

This script will automatically add host keys to your known host list which can potentially be a security risk

Currently supports VMware Cloud Director (vcd)
Future support of VMware vSphere5 and vSphere6

Future support for inspecting multiple files for a broader sample
'''
import re
import datetime
import os
import argparse
import getpass
import paramiko
import sys
import atexit
import shutil
from paramiko import SSHClient
from scp import SCPClient

global tmp_dir
global default_vcd 
global default_vsphere5
global default_vsphere6

tmp_dir = '/tmp/vmw_eps_calc'
default_vcd = '/opt/vmware/vcloud-director/logs/vcloud-container-debug.log.1'
default_vsphere5 = ''
default_vsphere6 = ''

def main():
    atexit.register(clean_up)
    # Parse command line arguments to fine device class and specific log if requested
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--device', required=True, action='store', help='The type of VMware device (vcd, vsphere5, vsphere6)')
    parser.add_argument('-l', '--log', required=False, action='store', help='Specific log file to inspect')
    parser.add_argument('-r', '--host', required=False, action='store', help='Remote host to connect to over SSH. Localhost is implied if not used')
    parser.add_argument('-u', '--user', required=False, action='store', help='SSH user for remote hosts. Not required unless you specified a remote host')
    parser.add_argument('-p', '--password', required=False, action='store', help='SSH password for scripting. Recommened that you IGNORE and will be securely prompted instead')
    #parser.add_argument('-r', '--recursive', required=False, action='store', help='Set to number of older log files you want to parse older copies and not just the last full log')
    args = parser.parse_args()
    col_type = str(args.device)
    col_log = str(args.log)
    col_host = str(args.host)
    col_user = str(args.user)
    col_pass = str(args.password)
  
    print '\n ---- Events Per Second (EPS) Calculator for VMware Products ---- \n'
    
    # Operations for collecting from a remote host
    if col_host != 'None':
        if col_user == 'None':
            sys.exit('Please specify the user with the -u flag\n')
        print 'Caution - Continuing to run this can potentially add unknown SSH host keys to the machine running this script\n'
        if col_pass == 'None':
            col_pass = getpass.getpass()
        # Connect to remote host
        scp_connect(col_host, col_user, col_pass, col_log, col_type)
    
    # Operations for a local collection
    if col_host == 'None' and col_log == 'None':
        file_list(None, col_type)
    else:
        if col_host == 'None':
            print 'Using custom log specified at command line\n'
            file_list(col_log, col_type)
            
    


def scp_connect(server, username, password, col_log, col_type):
    print 'Connecting to remote host ' + server
    ssh = SSHClient()
    #ssh.load_system_host_keys()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(server, 22, username, password)
    scp = SCPClient(ssh.get_transport())
    
    # Copy files to localdir
    if col_log == 'None' and col_type == 'vcd':
        col_log = default_vcd
    if col_log == 'None' and col_type == 'vsphere5':
        col_log = default_vsphere5
    if col_log == 'None' and col_type == 'vsphere6':
        col_log = default_vsphere6

    # Create local directory to hold log files
    print tmp_dir
    try:
        os.stat(tmp_dir)
        print 'Local temp folder exists'
    except:
        
        os.mkdir(tmp_dir)
        print 'Creating local temp folder'
        
    print 'Connected, attempting to copy ' + col_log + ' to localhost. This can take a a bit depending on your connection....'
    file_path = '/tmp/vmw_eps_calc/'
    scp.get(col_log, file_path)

    # Pass file location to file_list() after parsing it a bit to extract the actual file name
    file_name_index = col_log.rfind('/')
    file_name = col_log[file_name_index:]
    file_path = tmp_dir + file_name
    file_list(file_path, col_type)
    scp.close()    


def file_list(file_location, device_type):
    # Check file exists and get size at same time
    if file_location != None:
        try:
            file_size_kb = int((os.path.getsize(file_location) / 1024))
            if file_size_kb:
                # Pass file to parser
                parse_vcd_log(file_location, file_size_kb)
        except:
            print 'File does not exist or is empty'
    else:
        if device_type == 'vcd':
            print 'Grabbing last full debug log for vCD in default location (' + default_vcd + ')\n'
            try:
                file_size_kb = int((os.path.getsize(default_vcd) / 1024))
            except:
                print 'File does not exist or is empty'
            if file_size_kb:
                # Pass file to parser
                parse_vcd_log(default_vcd, file_size_kb)
        if device_type == 'vsphere5':
            print 'Grabbing last full debug log for vsphere5 in default location (' + default_vsphere5 + ')\n'
            try:
                file_size_kb = int((os.path.getsize(default_vsphere5) / 1024))
            except:
                print 'File does not exist or is empty'
            if file_size_kb:
                # Pass file to parser
                parse_vcd_log(default_vsphere5, file_size_kb)
        if device_type == 'vsphere6':
            print 'Grabbing last full debug log for vsphere6 in default location (' + default_vsphere6 + ')\n'           
            try:
                file_size_kb = int((os.path.getsize(default_vsphere6) / 1024))
            except:
                print 'File does not exist or is empty'
            if file_size_kb:
                # Pass file to parser
                parse_vcd_log(default_vsphere6, file_size_kb)


def parse_vcd_log(file_location, file_size_kb):
    # Create list of timestamps in file
    timestamps = []
    
    # Pattern to match beginning of event
    pattern = re.compile("^\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d")
    
    # Open and iterate through file
    for i, line in enumerate(open(file_location)):
        timestamps.append(re.findall(pattern, line))

    # Remove empty values from list
    timestamps = filter(None, timestamps)
    
    # Time of first event
    start_time_str = str(timestamps[0])
    # Time of last event
    end_time_str = str(timestamps[-1])
    
    # Convert timestamps to actual python timestamps
    st_yr = start_time_str[2:6]
    st_mo = start_time_str[7:9]
    st_da = start_time_str[10:12]
    st_hr = start_time_str[13:15]
    st_mn = start_time_str[16:18]
    st_sc = start_time_str[19:21]
    
    et_yr = end_time_str[2:6]
    et_mo = end_time_str[7:9]
    et_da = end_time_str[10:12]
    et_hr = end_time_str[13:15]
    et_mn = end_time_str[16:18]
    et_sc = end_time_str[19:21]
    
    start_time = datetime.datetime(int(st_yr),int(st_mo),int(st_da),int(st_hr),int(st_mn),int(st_sc))
    print 'First Recorded Event: ' + str(start_time)
    end_time = datetime.datetime(int(et_yr),int(et_mo),int(et_da),int(et_hr),int(et_mn),int(et_sc))
    print 'Last Recorded Event: ' + str(end_time) + '\n'
    
    # Find time span of logs in file
    elasped_time_sec = (end_time - start_time).seconds
    total_event_count = int(len(timestamps))
    display_results(elasped_time_sec, file_size_kb, total_event_count)


def display_results(elasped_time_sec, file_size_kb, total_event_count):
    # Show user all calculated information
    print 'Time Recorded in Log (Seconds): ' + str(elasped_time_sec)
    print 'Log File Size (KB): ' + str(file_size_kb)
    print 'Count of Events: ' + str(total_event_count) + '\n'
    print 'Based on your log file you are cuurently experiencing the below usage:'
    print 'Average Events Per Second (EPS): ' + str((total_event_count / elasped_time_sec))
    print 'Average Size Per Second (KBps): ' + str((file_size_kb / elasped_time_sec)) + '\n'

def clean_up():
    # Clean up temporary directory if it exists
    try:
        shutil.rmtree(tmp_dir)
        print 'Deleted temporary directory'
    except:
        print 'No temporary directory to remove'

if __name__ == '__main__':
    main()
