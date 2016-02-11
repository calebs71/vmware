'''			VMware Log Insight EPS Calculator
This simple python script is run against your vCD Cells and will give you an estimate on 
your Events Per Second as well as the bandwidth consumed by syslog events.
'''
import re
import datetime
import os
from sys import argv

print '\n ---- VMware Log Insight Events Per Second (EPS) Calculator for vCloud Director ---- \n'

try:
    if  argv[1]:
        print 'Using vCD log file specified in arguments\n'
        file_path = argv[1]
except:
    print 'No vCD log file specified. Using default vCD Debug Log\n'
    file_path = '/opt/vmware/vcloud-director/logs/vcloud-container-debug.log'

# Create list of timestamps in file
timestamps = []

# Pattern to match beginning of event
pattern = re.compile("^\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d")

# Open and iterate through file
for i, line in enumerate(open(file_path)):
    timestamps.append(re.findall(pattern, line))

# Get log file size and convert from bytes to kb
file_size_kb = (os.path.getsize(file_path) / 1024)

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

# Show user all calculated information
print 'Time Recorded in Log (Seconds): ' + str(elasped_time_sec)
print 'Log File Size (KB): ' + str(file_size_kb)
print 'Count of Events: ' + str(total_event_count) + '\n'
print 'Based on your log file you are cuurently experiencing the below usage:'
print 'Average Events Per Second (EPS): ' + str((total_event_count / elasped_time_sec))
print 'Average Size Per Second (KBps): ' + str((file_size_kb / elasped_time_sec)) + '\n'
