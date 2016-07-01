'''
************************* Log Insight Configuration Automation Tool *************************
**********                                                                         **********
This python program is built to reference values in a JSON configuration file for an individual Log 
Insight Server with the option to enforce configuration compliance with the gold master being defined
in the JSON file. All this takes place over https using the Log Insight Configuration APIs. Keep in
mind that Log Insight 3.3 is the minimum version requirement as that is the version where these APIs
are available. Both Python 2 and 3 are fully supported to prevent as many headaches as possible.

Example of a JSON configuration file is below. Note - JSON DOES NOT support inline comments so the 
comments beginning with # must be removed before use but are included to show you what each entry 
in the configuration file is doing or defining. If you don't want to go the JSON route just yet
then feel free to try out the "-b" or build wizard option to interactivly generate a simplified
JSON file.

-------------------------------------
{
# FQDN or IP of the Log Insight Server to manage
  "fqdn":"li-server1.sub.domain.com",
# Desired version of Log Insight - Warns only, no remediation available yet
  "version":"3.3.0-3571626",
# User to connect as
  "user":"admin",
  "password":"<PASSWORD!!!!>",
# Local for local user, domain for domain
  "auth_provider":"Local",
# This Log Insight server's license key
  "license":"XXXXX-XXXXX-XXXXX-XXXXX-XXXXX",
# Email notification settings
  "email_sender":"li-server1@domain.com",
  "email_server":"smtp-server.domain.com",
  "email_port":25,
  "email_sslAuth":"false",
  "email_tls":"false",
  "email_user":"",
  "email_password":"",
# Event Forwarder Configuration
  "forward_name":"Forward All",
# Forwarder destination
  "forward_fqdn":"master-li-cluster.domain.com",
  "forward_protocol":"cfapi",
  "forward_tags":{"tenant":"onecloud","environment":"production"},
  "forward_sslEnabled":"false",
  "forward_port":9000,
  "forward_diskCacheSize":2097152000,
  "forward_workerCount":32,
# Example of complex filtering to get you covered no matter how complex your filter needs to be
  "forward_filter":"not (((text=~\"*Applied change to temp map*\") or (text=~\"*Failed to get vsi stat set*\")) or (text=~\"*Is FT primary? false*\"))",
# Desired Content Packs to be installed and their version
  "content_packs":{"com.linux":"1.0","com.vmware.vsphere":"3.1","com.vmware.vcd":"8.0"},
# Active Directory Integration
  "ad_enable":"true",
  "ad_domain":"domain.com",
  "ad_username":"cstephenson",
  "ad_password":"MY Super Secret Password 1234!!$",
  "ad_connType":"STANDARD",
  "ad_port":"389",
  "ad_sslOnly":"false",
# Active Directory group to grant admin privileges on Log Insight
  "ac_ad_group":"global_li_admins",
# Leave this alone unless you are absolutely positive you know what you are doing. Even then, you probably shouldn't :)
  "ac_role_uuid":"00000000-0000-0000-0000-000000000001"
# NTP Servers to use
  "ntp_servers":["time.vmware.com", "0.vmware.pool.ntp.org", "1.vmware.pool.ntp.org"]
}
-------------------------------------

Once your JSON file has been defined the you can launch the tool using:
python3 li-json-api.py -f my-json-gold-template.json

or tell it to enforce your gold master by throwing on the -r (remediate) flag
python3 li-json-api.py -f my-json-gold-template.json -r

Author: Caleb Stephenson - cstephenson@vmware.com / calebs71@gmail.com
Date: 3-24-16

This code is not supported, released or related to VMware in any way and comes with absolutely no guarentees.
'''

import sys
import requests
import json
import time
import argparse
import getpass

# Suppresses Insecure connection messages
# Thanks - http://stackoverflow.com/questions/27981545/suppress-insecurerequestwarning-unverified-https-request-is-being-made-in-pytho
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

parser = argparse.ArgumentParser()
parser.add_argument('-f', '--file', required=False, action='store', help='Path to JSON configuration file containing the desired state')
parser.add_argument('-r', '--remediate', required=False, action='count', help='If set to true or yes then script will automatically remediate issues')
parser.add_argument('-d', '--doc', required=False, action='count',  help='Imbeded documentation')
parser.add_argument('-b', '--build', required=False, action='count', help='Wizard to help build JSON configuration file')

args = parser.parse_args()


def userQuery(varText):
    # Figures out which version of Python is being used to call correct method of user interaction
    if sys.version_info[0] > 2:
        userText = input(varText)
        return userText
    else:
        userText = raw_input(varText)
        return userText


def jsonWizard():
    print("\nWelcome to the interactive configuration file builder; built for us mere mortals who don't dream in JSON.")
    print("This wizard will guide you through building your first, simplified, JSON based configuration file.")
    print("Trust me though, you're going to want to build more complicated JSON files later on down the road using")
    print("the template in the help since it's much more robust!\n")

    wz_fqdn = userQuery('Please enter the FQDN or IP of your Log Insight Server: ')
    wz_password = getpass.getpass(prompt="Enter the Log Insight Server's Admin password: ")
    wz_license = userQuery('Enter the vRLI license key: ')
    wz_emailSender = userQuery('Enter sending email address for this LI server to use: ')
    wz_emailServer = userQuery('Enter the SMTP mail server to use: ')
    wz_emailAuth = userQuery('Does you SMTP Server require authentication (y/n): ')
    while wz_emailAuth.lower() != 'y' and wz_emailAuth.lower() != 'n':
        print('Please choose "y" or "n"')
        wz_emailAuth = userQuery('Does you SMTP Server require authentication (y/n): ')
    if wz_emailAuth.lower() == 'n':
        print('Skipping that then...')
    elif wz_emailAuth.lower() == 'y':
        wz_emailUser = userQuery('Enter your SMTP username: ')
        wz_emailPassword = getpass.getpass(prompt="Enter your SMTP password: ")
    wz_adEnable = userQuery('Do you wish to enable Active Directory authentication? (y/n): ')
    while wz_adEnable.lower() != 'y' and wz_adEnable.lower() != 'n':
        print('Please choose "y" or "n"')
        wz_adEnable = userQuery('Do you wish to enable Active Directory authentication? (y/n): ')
    if wz_adEnable.lower() == 'n':
        print('Skipping AD integration as requested')
    elif wz_adEnable.lower() == 'y':
        wz_adDomain = userQuery('Enter the domain to use: ')
        wz_adUsername = userQuery('Enter the Active Directory user to use for directory lookups: ')
        wz_adPassword = getpass.getpass(prompt="Enter the AD User's password: ")
        wz_adAddGroup = userQuery('Enter the name of an Active Directory Group to make Admins on the Log Insight Server: ')
    wz_ntp_raw = userQuery('Enter an NTP Server to use: ')
    wz_ntp = []
    wz_ntp.append(wz_ntp_raw)
    wz_location = userQuery('Please enter the location/filename to save this configuration as: ')

    # Time to put it in a list and make it all JSON
    wz_data = {}
    wz_data['fqdn'] = wz_fqdn
    wz_data['version'] = ''
    wz_data['user'] = 'admin'
    wz_data['password'] = wz_password
    wz_data['auth_provider'] = 'Local'
    wz_data['license'] = wz_license
    wz_data['email_sender'] = wz_emailSender
    wz_data['email_server'] = wz_emailServer
    wz_data['email_port'] = '25'
    if 'wz_emailUser' in locals():
        wz_data['email_sslAuth'] = 'false'
        wz_data['email_tls'] = 'false'
        wz_data['email_user'] = wz_emailUser
        wz_data['email_password'] = wz_emailPassword
    else:
        wz_data['email_sslAuth'] = 'false'
        wz_data['email_tls'] = 'false'
        wz_data['email_user'] = ''
        wz_data['email_password'] = ''
    wz_data['forward_name'] = ''
    wz_data['forward_fqdn'] = ''
    wz_data['forward_protocol'] = ''
    wz_data['forward_tags'] = ''
    wz_data['forward_sslEnabled'] = ''
    wz_data['forward_port'] = ''
    wz_data['forward_diskCacheSize'] = ''
    wz_data['forward_workerCount'] = ''
    wz_data['forward_filter'] = ''
    wz_data['content_packs'] = ''
    if wz_adEnable.lower() == 'y':
        wz_data['ad_enable'] = 'true'
        wz_data['ad_domain'] = wz_adDomain
        wz_data['ad_username'] = wz_adUsername
        wz_data['ad_password'] = wz_adPassword
        wz_data['ad_connType'] = 'STANDARD'
        wz_data['ad_port'] = 389
        wz_data['ad_sslOnly'] = 'false'
        wz_data['ac_ad_group'] = wz_adAddGroup
        wz_data['ac_role_uuid'] = '00000000-0000-0000-0000-000000000001'
    else:
        wz_data['ad_enable'] = ''
        wz_data['ad_domain'] = ''
        wz_data['ad_username'] = ''
        wz_data['ad_password'] = ''
        wz_data['ad_connType'] = ''
        wz_data['ad_port'] = ''
        wz_data['ad_sslOnly'] = ''
        wz_data['ac_ad_group'] = ''
        wz_data['ac_role_uuid'] = ''
    wz_data['ntp_servers'] = wz_ntp

    wz_json = json.dumps(wz_data)

    # Need to save to a file
    try:
        saveFile = open(wz_location,'w')
        saveFile.write(wz_json)
        print('\nYour JSON file has been saved to ' + wz_location + '\n')
    except:
        print('Unable to save file')


# Print documentation if requested
if args.doc:
    print(__doc__)
    sys.exit()
# Execute JSON builder if requested
if args.build:
    if (int(args.build) > 0):
        jsonWizard()
        sys.exit()
# If documentation or wizard is not requested check the rest...
else:
    try:
        if args.file == None:
            sys.exit()
        if args.remediate:
            if (int(args.remediate) > 0):
                remediateFlag = int(args.remediate)
        else:
            remediateFlag = 0
    except:
        print('Did you forget to specify an argument? Maybe try -h for help, -b for the configuration build wizard, or -d for more robust documentation.')
        sys.exit()

configFile = str(args.file)

try:
    configDataStr = open(configFile).read()
except:
    print('ERROR - Failed to open the specified file')
    sys.exit()
    
configData = json.loads(configDataStr)

baseUrl = 'https://' + configData['fqdn']
# Only used for the initial connection
unAuthHeaders = {"Content-Type":"application/json"}

def main():
    print('\n-- Welcome to the Log Insight Configuration API Audit and Standalone Remediation Tool --')
    print('        This code is not released, supported by or related to VMware in any way.\n')


    if remediateFlag > 0:
        print('*Remediation flag detected* - Will automatically remediate issues\n')
    else:
        print('No remediation selected, set the -r flag if you wish to automatically remediate issues.\n')

    # Connect to the LI Server and get a Bearer Token
    sessionAuth = connectToServer()
    # Build new headers with token
    authHeadersJson = {"Content-Type":"application/json", "Authorization":str(sessionAuth)}
    # Get Version
    getVersion(authHeadersJson)
    # Check License
    getLicense(authHeadersJson)
    # Check NTP
    getNtp(authHeadersJson)
    # Check SMTP 
    getEmail(authHeadersJson)
    # Check Forwarder
    getForwarder(authHeadersJson)
    # Check AD
    getAd(authHeadersJson)
    # Check Content Packs
    #   Currently does not remediate
    getReqContentPacks(authHeadersJson)
    # Check for the existance of a SINGLE Active Directory group and it's association with a SINGLE Log Insight role
    getAccessControls(authHeadersJson)
    print('All checks have completed successfully\n')

# Should define function for error message and remediation to reduce code

def connectToServer():
    # Sanity check to make sure all data is present
    if len(configData['auth_provider']) > 0 and \
       len(configData['user']) > 0 and \
       len(configData['password']) > 0:
           print('Connecting to Log Insight')
    else:
        print('ERROR - Needed information is missing! Please check your username, password and auth_provider')
        sys.exit()
    
    authUrl = str(baseUrl) + '/api/v1/sessions'
    buildJson = '{' + \
                 '"provider":"' + configData['auth_provider'] + '",' + \
                '"username":"' + configData['user'] + '",' + \
                '"password":"' + configData['password'] + '"' \
                '}'
    conn = requests.post(str(authUrl),headers = unAuthHeaders, verify = False, data = str(buildJson))
    connResponse = conn.json()
    try:
        authSession = connResponse['sessionId']
        if len(authSession) > 10:
            print('Successfully connected to Log Insight')
            authSessionKey = 'Bearer ' + authSession
            return authSessionKey
    except:
            print('-!!ERROR!!- Unable to connect to the Log Insight Server. Please check your credentials.\n')
            sys.exit()


def getVersion(authHeadersJson):
    # Sanity check to make sure all data is present
    if len(configData['version']) == 0:
        print('Desired version NOT specified in JSON template - Skipping Test')
        return
    
    try:
        versionUrl = str(baseUrl) + '/api/v1/version'
        version = requests.get(str(versionUrl), headers = authHeadersJson, verify = False).json()
        liReleaseName = str(version['releaseName'])
        liVersion = str(version['version'])
    
        print('Log Insight Server at ' + str(configData['fqdn']) + ' running version ' + liVersion + ' ' + liReleaseName + '\n')

        if str(liVersion).lower() == str(configData['version']).lower():
            print('Version matches desired state')
        else:
            print('-!!WARN!! - Version DOES NOT match desired state. No Automatic remediation available')
    except:
        print('-!!ERROR!! - Unable to get Log Insight version')
        
    # Build in some logic to allow at 3.3+ only since the APIs don't exist earlier
    majorRelease = liVersion.split('.')[0]
    minorRelease = liVersion.split('.')[1]
    if int(majorRelease) <= 3 and int(minorRelease) < 3:
        print('I\'m sorry but this Log Insight Server is not running version 3.3 or newer so the API\'s aren\'t available. Please upgrade your LI server\n')
        sys.exit()

def getLicense(authHeadersJson):
    # Sanity check to make sure all data is present
    if len(configData['license']) == 0:
        print('Desired license NOT specified in JSON template - Skipping Test')
        return
    
    try:
        licenseUrl = str(baseUrl) + '/api/v1/licenses'
        license = requests.get(str(licenseUrl), headers = authHeadersJson, verify = False)
        licenseDetails = license.json()
        if str(configData['license']).lower() in str(licenseDetails).lower():
            print('License information matches desired state')
        else:
            print('-!!WARN!!- License information DOES NOT match desired state')
            if remediateFlag > 0:
                setLicense(authHeadersJson)
    except:
        print('-!!ERROR!! - Unable to get License information')


def setLicense(authHeadersJson):
    # Sanity check to make sure all data is present
    if len(configData['license']) == 0:
        print('Desired license NOT specified in JSON template - Skipping Remediation')
        return
    
    print('Executing license remediation')
    licenseUrl = str(baseUrl) + '/api/v1/licenses'
    buildJson = '{' + \
                '"key":"' + configData['license'] + '"' + \
                '}'
    configLicense = requests.post(str(licenseUrl), headers = authHeadersJson, verify = False, data = str(buildJson))
    if configLicense.status_code >= 400:
        print('-!!ERROR!! - Unable to remediate License Configuration - See error details below ')
        print(' - Status Code: ' + str(configLicense.status_code))
        print(' - Error Details: ' + str(configLicense.text))
    else:
        time.sleep(3)
        getLicense(authHeadersJson)


def getEmail(authHeadersJson):
    # Sanity check to make sure all data is present
    if len(configData['email_sender']) == 0 or \
       len(configData['email_server']) == 0 or \
       configData['email_port'] is None or \
       len(configData['email_sslAuth']) == 0 or \
       len(configData['email_tls']) == 0:
        print('Desired email configuration NOT specified in JSON template - Skipping Test')
        return
    
    try:
        notificationUrl = str(baseUrl) + '/api/v1/notifications'
        notification = requests.get(str(notificationUrl), headers = authHeadersJson, verify=False).json()
        emailDetails = notification['channels'][0]['config']
        if str(emailDetails['defaultSender']).lower() == str(configData['email_sender']).lower() and \
           str(emailDetails['server']).lower() == str(configData['email_server']).lower() and \
           str(emailDetails['port']).lower() == str(configData['email_port']).lower() and \
           str(emailDetails['sslAuth']).lower() == str(configData['email_sslAuth']).lower() and \
           str(emailDetails['tls']).lower() == str(configData['email_tls']).lower() and \
           str(emailDetails['login']).lower() == str(configData['email_user']).lower():
            print('Email configuration matches desired state')
        else:
            print('-!!WARN!!- Email configuration DOES NOT match desired state')
            if remediateFlag > 0: 
                setEmail(authHeadersJson)
    except:
        print('-!!ERROR!! - Unable to get Email information')


def setEmail(authHeadersJson):
    # Sanity check to make sure all data is present
    if len(configData['email_sender']) == 0 or \
       len(configData['email_server']) == 0 or \
       configData['email_port'] is None or \
       len(configData['email_sslAuth']) == 0 or \
       len(configData['email_tls']) == 0:
        print('Desired email configuration NOT specified in JSON template - Skipping Remediation')
        return
    
    print('Executing email remediation')
    notificationUrl = str(baseUrl) + '/api/v1/notifications'
    buildJson = '{' + \
                '"channels":[{"type":"email","config":{' + \
                '"server":"' + configData['email_server'] + '",' + \
                '"port":' + str(configData['email_port']) + ',' + \
                '"sslAuth":"' + configData['email_sslAuth'] + '",' + \
                '"tls":"' + configData['email_tls'] + '",' + \
                '"defaultSender":"' + configData['email_sender'] + '",' + \
                '"login":"' + configData['email_user'] + '",' + \
                '"password":"' + configData['email_password'] + '"' + \
                '}}]}'
    configEmail = requests.put(notificationUrl, headers = authHeadersJson, verify = False, data = str(buildJson))
    if configEmail.status_code >= 400:
        print('-!!ERROR!! - Unable to remediate Email Configuration - See error details below ')
        print(' - Status Code: ' + str(configEmail.status_code))
        print(' - Error Details: ' + str(configEmail.text))
    else:
        time.sleep(3)
        getEmail(authHeadersJson)


def getForwarder(authHeadersJson):
    # Sanity check to make sure all data is present
    if len(configData['forward_name']) == 0 or \
       len(configData['forward_protocol']) == 0 or \
       len(configData['forward_tags']) == 0 or \
       len(configData['forward_sslEnabled']) == 0 or \
       configData['forward_port'] is None or \
       len(configData['forward_filter']) == 0 or \
       configData['forward_diskCacheSize'] is None or \
       len(configData['forward_fqdn']) == 0 or \
       configData['forward_workerCount'] is None:
        print('Desired Forwader configuration NOT specified in JSON template - Skipping Test')
        return
    
    try:
        forwarderUrl = str(baseUrl) + '/api/v1/forwarding'
        forwarder = requests.get(str(forwarderUrl), headers = authHeadersJson, verify = False).json()
        forwarderList = forwarder['forwarders']
        try:
            # Create a count of number of forwarders to iterate through to look for a match
            forwarderLen = len(forwarderList)
            for forwarderDetails in forwarderList :
                # First simple check
                if str(forwarderDetails['id']).lower() == str(configData['forward_name']).lower():
                    # If the simple check passes then do a through check to see if we need to update the record
                    #print('Forwarder ' + str(forwarderDetails['id']) + ' configuration exists, requires deeper inspection...')
                    if str(forwarderDetails['protocol']).lower() == str(configData['forward_protocol']).lower() and \
                       str(forwarderDetails['tags']).lower() == str(configData['forward_tags']).lower() and \
                       str(forwarderDetails['sslEnabled']).lower() == str(configData['forward_sslEnabled']).lower() and \
                       str(forwarderDetails['port']).lower() == str(configData['forward_port']).lower() and \
                       str(forwarderDetails['filter']).lower() == str(configData['forward_filter']).lower() and \
                       str(forwarderDetails['diskCacheSize']).lower() == str(configData['forward_diskCacheSize']).lower() and \
                       str(forwarderDetails['host']).lower() == str(configData['forward_fqdn']).lower() and \
                       str(forwarderDetails['workerCount']).lower() == str(configData['forward_workerCount']).lower():
                        print('Forwarder configuration matches desired state')
                    else:
                        print('-!!WARN!!- Forwader configuration DOES NOT match desired state')
                        if remediateFlag > 0:
                            updateForwarder(authHeadersJson)
                else:
                    # If the checks do not pass then it is not a match, decrease the counter and continue the loop
                    #print 'Forwarder ' + str(forwarderDetails['id']) + ' configuration DOES NOT match desired state'
                    forwarderLen = forwarderLen - 1
        except:
            # Try will fail if no forwarder is configured
            print('-!!WARN!!- No Forwarder configuration exists')
            if remediateFlag > 0:
                setForwarder(authHeadersJson)
        if forwarderLen != 1:
            # If no match has been found the counter will not equal 1 and we can add our forwarder
            print('-!!WARN!!- Forwader configuration DOES NOT match desired state')
            if remediateFlag > 0:
                setForwarder(authHeadersJson)
    except:
        print('-!!ERROR!! - Unable to get Forwarder information')

def updateForwarder(authHeadersJson):
    # Sanity check to make sure all data is present
    if len(configData['forward_name']) == 0 or \
       len(configData['forward_protocol']) == 0 or \
       len(configData['forward_tags']) == 0 or \
       len(configData['forward_sslEnabled']) == 0 or \
       configData['forward_port'] is None or \
       len(configData['forward_filter']) == 0 or \
       configData['forward_diskCacheSize'] is None or \
       len(configData['forward_fqdn']) == 0 or \
       configData['forward_workerCount'] is None:
        print('Desired Forwader configuration NOT specified in JSON template - Skipping Remediation')
        return
    
    print('Executing forwarder remediation - updating existing')
    forwarderUrl = str(baseUrl) + '/api/v1/forwarding'
    
    #Odd looking replace statement below is required to comment out double quotes in extended syntax and remove the u for unicode.
    buildJson = '{' + \
                '"id":"' + configData['forward_name'] + '",' + \
                '"protocol":"' + configData['forward_protocol'] + '",' + \
                '"tags":' + str(configData['forward_tags']).replace('\'','"').replace('u"','"') + ',' + \
                '"sslEnabled":"' + configData['forward_sslEnabled'] + '",' + \
                '"port":' + str(configData['forward_port']) + ',' + \
                '"diskCacheSize":' + str(configData['forward_diskCacheSize']) + ',' + \
                '"host":"' + configData['forward_fqdn'] + '",' + \
                '"workerCount":' + str(configData['forward_workerCount']) + ',' + \
                '"filter":"' + str(configData['forward_filter']).replace('"','\\"') + '"' + \
                '}'
    configForwarder = requests.put(str(forwarderUrl), headers = authHeadersJson, verify = False, data = str(buildJson))
    if configForwarder.status_code >= 400:
        print('-!!ERROR!! - Unable to remediate Forwarder Configuration - See error details below ')
        print(' - Status Code: ' + str(configForwarder.status_code))
        print(' - Error Details: ' + str(configForwarder.text))
    else:
        time.sleep(3)
        getForwarder(authHeadersJson)


def setForwarder(authHeadersJson):
    # Sanity check to make sure all data is present
    if len(configData['forward_protocol']) == 0 or \
       len(configData['forward_tags']) == 0 or \
       len(configData['forward_sslEnabled']) == 0 or \
       configData['forward_port'] is None or \
       len(configData['forward_filter']) == 0 or \
       configData['forward_diskCacheSize'] is None or \
       len(configData['forward_fqdn']) == 0 or \
       configData['forward_workerCount'] is None:
        print('Desired Forwader configuration NOT specified in JSON template - Skipping Remediation')
        return
    
    print('Executing forwarder remediation - creating new')
    forwarderUrl = str(baseUrl) + '/api/v1/forwarding'
    
    #Odd looking replace statement below is required to comment out double quotes in extended syntax and remove the u for unicode.
    buildJson = '{' + \
                '"id":"' + configData['forward_name'] + '",' + \
                '"protocol":"' + configData['forward_protocol'] + '",' + \
                '"tags":' + str(configData['forward_tags']).replace('\'','"').replace('u"','"') + ',' + \
                '"sslEnabled":"' + configData['forward_sslEnabled'] + '",' + \
                '"port":' + str(configData['forward_port']) + ',' + \
                '"diskCacheSize":' + str(configData['forward_diskCacheSize']) + ',' + \
                '"host":"' + configData['forward_fqdn'] + '",' + \
                '"workerCount":' + str(configData['forward_workerCount']) + ',' + \
                '"filter":"' + str(configData['forward_filter']).replace('"','\\"') + '"' + \
                '}'
    configForwarder = requests.post(str(forwarderUrl), headers = authHeadersJson, verify = False, data = str(buildJson))
    if configForwarder.status_code >= 400:
        print('-!!ERROR!! - Unable to remediate Forwarder Configuration - See error details below ')
        print(' - Status Code: ' + str(configForwarder.status_code))
        print(' - Error Details: ' + str(configForwarder.text))
    else:
        time.sleep(3)
        getForwarder(authHeadersJson)


def getAd(authHeadersJson):
    # Sanity check to make sure all data is present
    if len(configData['ad_domain']) == 0 or \
       len(configData['ad_username']) == 0 or \
       len(configData['ad_connType']) == 0 or \
       len(configData['ad_sslOnly']) == 0 or \
       len(configData['ad_enable']) == 0 or \
       configData['ad_port'] is None:
        print('Desired Active Directory configuration NOT specified in JSON template - Skipping Test')
        return
    
    try:
        # This operates under the asssumption that you WANT AD and don't intend to disable it via API.....
        adUrl = str(baseUrl) + '/api/v1/ad/config'
        ad = requests.get(str(adUrl), headers = authHeadersJson, verify = False).json()
        if str(ad['enableAD']).lower() == 'false':
             print('-!!WARN!!- AD Configuration DOES NOT match desired state')
             if remediateFlag > 0:
                 setAd(authHeadersJson)
        if str(ad['enableAD']).lower() == 'true':
            #print('AD Authentication enabled, verifying settings')
            if str(ad['domain']).lower() == str(configData['ad_domain']).lower() and \
               str(ad['username']).lower() == str(configData['ad_username']).lower() and \
               str(ad['connType']).lower() == str(configData['ad_connType']).lower() and \
               str(ad['sslOnly']).lower() == str(configData['ad_sslOnly']).lower():
                if str(ad['connType']).lower() == 'custom':
                    if str(ad['port']).lower() == str(configData['ad_port']).lower():
                        print('AD Configuration matches desired state')
                    else:
                        print('-!!WARN!!- AD Configuration DOES NOT match desired state')
                        if remediateFlag > 0:
                            setAd(authHeadersJson)
                else:
                    print('AD Configuration matches desired state')
            else:
                print('-!!WARN!!- AD Configuration DOES NOT match desired state')
                if remediateFlag > 0:
                    setAd(authHeadersJson)
    except:
        print('-!!ERROR!! - Unable to get Active Directory information')

def setAd(authHeadersJson):
    # Sanity check to make sure all data is present
    if len(configData['ad_domain']) == 0 or \
       len(configData['ad_username']) == 0 or \
       len(configData['ad_password']) == 0 or \
       len(configData['ad_connType']) == 0 or \
       len(configData['ad_sslOnly']) == 0 or \
       len(configData['ad_enable']) == 0 or \
       configData['ad_port'] is None:
        print('Desired Active Directory configuration NOT specified in JSON template - Skipping Remediation')
        return
    
    print('Executing AD authentication remediation')
    adUrl = str(baseUrl) + '/api/v1/ad/config'
    buildJson = '{' + \
                '"enableAD":"' + configData['ad_enable'] + '",' + \
                '"domain":"' + configData['ad_domain'] + '",' + \
                '"username":"' + configData['ad_username'] + '",' + \
                '"password":"' + configData['ad_password'] + '",' + \
                '"connType":"' + configData['ad_connType'] + '",' + \
                '"port":"' + configData['ad_port'] + '",' + \
                '"sslOnly":"' + configData['ad_sslOnly'] + '"' + \
                '}'
    configAd = requests.post(str(adUrl), headers = authHeadersJson, verify = False, data = str(buildJson))
    if configAd.status_code >= 400:
        print('-!!ERROR!! - Unable to remediate AD Configuration - See error details below ')
        print(' - Status Code: ' + str(configAd.status_code))
        print(' - Error Details: ' + str(configAd.text))
    else:
        time.sleep(3)
        getAd(authHeadersJson)


def getReqContentPacks(authHeadersJson):
    # Sanity check to make sure all data is present
    if len(configData['content_packs']) == 0:
        print('Desired Content Packs configuration NOT specified in JSON template - Skipping Test')
        return
    
    try:
        contentPacksUrl = str(baseUrl) + '/api/v1/contentpacks'
        inContentPacks = requests.get(str(contentPacksUrl), headers = authHeadersJson, verify = False).json()
        inContentPacks =  inContentPacks['contentPackMetadataList']
        
        for reqContentPack in configData['content_packs']:
            reqContentPackVer = configData['content_packs'][str(reqContentPack)]
            inContentPackLen = len(inContentPacks)

            #print '\n\nRequired:' +  reqContentPack + ' ' +  reqContentPackVer
            for inContentPack in inContentPacks:
                #print str(inContentPackLen)
                inContentPackName = str(inContentPack['namespace'])
                inContentPackVer = str(inContentPack['contentVersion'])
                #print 'Installed: ' +inContentPackName + ' ' + inContentPackVer
                if str(inContentPackName).lower() == str(reqContentPack).lower():
                    print('Required Content Pack ' + str(reqContentPack) + ' installed, checking version...')
                    # We should make this only alert if version is less than specified version
                    # Slightly nmore complicated than decimal operation due to x.y.z versioning and may include letters in the future. Putting this off for now
                    if str(inContentPackVer).lower() == str(reqContentPackVer).lower():
                        print('Version matches, check successful')
                    else:
                        print('-!!WARN!!- Content Pack ' + reqContentPack + ' installed but at incorrent version')
                        print('-- Automatic remediation not available in this version --')
                else:
                    #print 'Content Pack does not match'
                    inContentPackLen = inContentPackLen - 1
                    #print str(inContentPackLen)

            if inContentPackLen != 1:
                #print str(inContentPackLen)
                print('-!!WARN!!- No match installed for Content Pack ' + str(reqContentPack))
                print('-- Automatic remediation not available in this version --')
    except:
        print('-!!ERROR!! - Unable to get Content Pack information')


# Placeholder for remediation function. Want to be able to call simple operation, not ship whole CP but that may be unaviodable
def setContentPackVcd(authHeadersJson):
    print('')


def getAccessControls(authHeadersJson):
    # Sanity check to make sure all data is present
    if len(configData['ac_ad_group']) == 0 or \
       len(configData['ac_role_uuid']) == 0:
        print('Desired Active Directory configuration NOT specified in JSON template - Skipping Test')
        return
    
    try:
        accessControlsUrl = str(baseUrl) + '/api/v1/adgroups'
        inAccessControls = requests.get(str(accessControlsUrl), headers = authHeadersJson, verify = False).json()
        inAccessControls = inAccessControls['adGroups']
        inAccessControlsLen = len(inAccessControls)
        
        for accessControl in inAccessControls:
            #print(str(accessControl['name']))
            if str(accessControl['name'].lower()) == configData['ac_ad_group'].lower():
                #print('Access Control group membership matches desired state')
                groupIds = accessControl['groupIds']
                groupIdsLen = len(groupIds)
                for groupId in groupIds:
                    #print(groupId)
                    if str(groupId).lower() == str(configData['ac_role_uuid']).lower():
                        print('Access Control Group matches desired state')
                    else:
                        groupIdsLen = groupIdsLen -1
                if groupIdsLen != 1:
                    # Need to fix this once I have more API information
                    print('-!!WARN!!- Access Control Group DOES NOT match desired state - AD member added to incorrect Log Insight Role')
                    if remediateFlag > 0:
                        editAccessControl(authHeadersJson)
            else:
                inAccessControlsLen = inAccessControlsLen - 1

        if inAccessControlsLen != 1:
            print('-!!WARN!!- Access Control group membership DOES NOT match desired state')
            if remediateFlag > 0:
                addAccessControl(authHeadersJson)
    except:
        print('-!!ERROR!! - Unable to get Access Control information')


#This is used by 2 different functions so making it a function, because DRY....
def buildAccessControlJson():
    buildJson = '{' + \
                '"type":"ad",' + \
                '"domain":"' + configData['ad_domain'] + '",' + \
                '"name":"' + configData['ac_ad_group'] + '",' + \
                '"groupIds":["' + configData['ac_role_uuid'] + '"]' + \
                '}'
    return str(buildJson)


def addAccessControl(authHeadersJson):
    # Sanity check to make sure all data is present
    if len(configData['ac_ad_group']) == 0 or \
       len(configData['ac_role_uuid']) == 0:
        print('Desired Active Directory configuration NOT specified in JSON template - Skipping Test')
        return
    
    # Technical debt, only single group supported
    print('Executing Access Contorl Group addition remediation')
    accessControlsUrl = str(baseUrl) + '/api/v1/adgroups'
    buildJson = buildAccessControlJson()
    configAccessControl = requests.post(str(accessControlsUrl), headers = authHeadersJson, verify = False, data = str(buildJson))
    if configAccessControl.status_code >= 400:
        print('-!!ERROR!! - Unable to remediate Access Control Configuration - See error details below ')
        print(' - Status Code: ' + str(configAccessControl.status_code))
        print(' - Error Details: ' + str(configAccessControl.text))
    else:
        time.sleep(3)
        getAccessControls(authHeadersJson)


def editAccessControl(authHeadersJson):
    # Sanity check to make sure all data is present
    if len(configData['ac_ad_group']) == 0 or \
       len(configData['ac_role_uuid']) == 0:
        print('Desired Active Directory configuration NOT specified in JSON template - Skipping Test')
        return
    
    print('Executing Access Contorl Group modification remediation')
    accessControlsUrl = str(baseUrl) + '/api/v1/adgroups/ad/' + str(configData['ad_domain']) + '/' + str(configData['ac_ad_group'])
    buildJson = buildAccessControlJson()
    configAccessControl = requests.post(str(accessControlsUrl), headers = authHeadersJson, verify = False, data = str(buildJson))
    if configAccessControl.status_code >= 400:
        print('-!!ERROR!! - Unable to remediate Access Control Configuration - See error details below ')
        print(' - Status Code: ' + str(configAccessControl.status_code))
        print(' - Error Details: ' + str(configAccessControl.text))
    else:
        time.sleep(3)
        getAccessControls(authHeadersJson)



def getNtp(authHeadersJson):
    # Sanity check to make sure all data is present
    if len(configData['ntp_servers']) == 0:
        print('Desired NTP configuration NOT specified in JSON template - Skipping Test')
        return
    
    try:
        ntpUrl = str(baseUrl) + '/api/v1/time/config'
        inNtp = requests.get(str(ntpUrl), headers = authHeadersJson, verify = False).json()
        # Necessary for ESX Host sync configured devices
        try:
            inNtp = inNtp['ntpConfig']
            inNtpServers = inNtp['ntpServers']
            # Instead of iterating through each one to make sure they are present this is faster/cheaper
            if str(inNtpServers).lower() == str(configData['ntp_servers']).lower():
                print('NTP Servers match desired state')
            else:
                print('-!!WARN!!- NTP Server configuration DOES NOT match desired state')
                if remediateFlag > 0:
                    setNtp(authHeadersJson)
        except:
            print('-!!WARN!!- - NTP Server configuration DOES NOT MATCH desired state')
            if remediateFlag > 0:
                setNtp(authHeadersJson)
    except:
        print('-!!ERROR!! - Unable to get NTP information')


def setNtp(authHeadersJson):
    # Sanity check to make sure all data is present
    if len(configData['ntp_servers']) == 0:
        print('Desired NTP configuration NOT specified in JSON template - Skipping Remediation')
        return
    
    #Have list of NTP Servers that need iterated through
    #Potential Technical debt, not allowing ESXi host sync since it's not recommended anyway
    print('Executing NTP remediation')
    ntpUrl = str(baseUrl) + '/api/v1/time/config'
    buildJson = '{' + \
                '"timeReference":"NTP_SERVER",' + \
                '"ntpServers":' + str(configData['ntp_servers']).replace("'",'"').replace('u"','"') + \
                '}'
    configNtp =  requests.post(str(ntpUrl), headers = authHeadersJson, verify = False, data = str(buildJson))
    if configNtp.status_code >= 400:
        print('-!!ERROR!! - Unable to remediate NTP Configuration - See error details below ')
        print(' - Status Code: ' + str(configNtp.status_code))
        print(' - Error Details: ' + str(configNtp.text))
    else:
        time.sleep(3)
        getNtp(authHeadersJson)


if __name__ == '__main__':
    main()
