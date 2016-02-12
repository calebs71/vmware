'''			VMware Log Insight EPS Calculator
This simple python script is run against your vCD Cells and will give you an estimate on 
your Events Per Second as well as the bandwidth consumed by syslog events.

Currently supports VMware Cloud Director (vcd)
Future support of VMware vSphere5 and vSphere6

Future support for inspecting multiple files for a broader sample
'''
import re
import datetime
import os
import argparse
#import paramiko
#import getpass


def main():
    # Parse command line arguments to fine device class and specific log if requested
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--device', required=True, action='store', help='The type of VMware device (vcd, vsphere5, vsphere6)')
    parser.add_argument('-l', '--log', required=False, action='store', help='Specific log file to inspect')
    #parser.add_argument('-r', '--host', required=False, action='store', help='Remote host to connect to over SSH. Localhost is implied if not used')
    #parser.add_argument('-u', '--user', required=False, action='store', help='SSH user for remote hosts. Not required unless you specified a remote host')
    #parser.add_argument('-p', '--password', required=False, action='store', help='SSH password for scripting. Recommened that you IGNORE and will be securely prompted instead')
    #parser.add_argument('-r', '--recursive', required=False, action='store', help='Set to number of older log files you want to parse older copies and not just the last full log')
    args = parser.parse_args()
    col_type = str(args.device)
    col_log = str(args.log)
    #col_host = str(args.host)
    #col_user = str(args.user)
    #col_pass = str(args.password)
  

    print '\n ---- Events Per Second (EPS) Calculator for VMware Products ---- \n'
    
    # Coneect to remote host and grab log file
    
    #if col_host != 'None':
        #if col_pass == 'None':
            #print 'Please enter your password'
            #col_pass = getpass.getpass()
            
        
          
        
        
    
    if col_log == 'None':
        file_list(None, col_type)
    else:
        print 'Using custom log specified at command line\n'
        file_list(col_log, col_type)


def file_list(file_location, device_type):
    default_vcd = '/opt/vmware/vcloud-director/logs/vcloud-container-debug.log.1'
    default_vsphere5 = ''
    default_vsphere6 = ''
    
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

if __name__ == '__main__':
    main()
