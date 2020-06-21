#!/usr/bin/env python3

# Copyright (c) 2020 Stewart Loving-Gibbard

'''
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
'''

# Version 1.0 - Initial release
# Version 1.1 - Loopback mode added

import argparse
import json
import sys
import string
import urllib3
import requests
import logging
# This is from the Pyst2 library (see https://pyst2.readthedocs.io/en/latest/manager.html#example)
import asterisk.manager
import time
import threading


class AsteriskChecker(object):

    def __init__(self, hostname, port, user, password, timeoutInSeconds, sipHost, debugLogging):
        self._debug_logging = debugLogging
        self.SetupLogging()
        logging.debug('Initializing AsteriskChecker')
    
        self._hostname = hostname
        self._port = port
        self._user = user
        self._password = password
        self._timeoutInSeconds = timeoutInSeconds;

        self._sip_host_name = sipHost

        self._ok_messages = []
        self._warning_messages = []
        self._critical_messages = []

        self.LogStartupInformation()

        # We trigger this event to indicate when all processing is complete
        # and we can exit.
        self._processing_complete_event = threading.Event()

    def SetupLogging(self):
        logger = logging.getLogger()
        
        if (self._debug_logging):
            #print('Trying to set logging level debug')
            logger.setLevel(logging.DEBUG)
        else:
            #print('Should be setting no logging level at all')
            logger.setLevel(logging.CRITICAL)

    def WaitForProcessingToBeComplete(self):
        logging.debug('WaitForProcessingToBeComplete')    
        self._processing_complete_event.wait(self._timeoutInSeconds);
        
    def SetProcessingIsComplete(self):
        logging.debug('SetProcessingIsComplete')
        # Caution - this may be the last thing the calling thread ever does!
        self._processing_complete_event.set();

    def LogStartupInformation(self):
        logging.debug('')
        logging.debug(f'hostname: {self._hostname}')
        logging.debug(f'port: {self._port}')
        logging.debug(f'Timeout: {self._timeoutInSeconds } seconds')
        logging.debug('')

    def DumpEventInfo(self, event):
        logging.debug(f"event.name: {event.name}");
        logging.debug(f"event.message: {event.message}");
        logging.debug(f"event.data: {event.data}");
        logging.debug(f"event.headers: {event.headers}");

    def HandleRequestedCheck(self, checkType):
        logging.debug(f"HandleRequestedCheck: {checkType}")
        if checkType == 'sippeer':
            self.CheckSipPeer();
        elif checkType == 'sipregistry':
            self.CheckSipRegistry()
        elif checkType == 'loopback':
            self.CheckLoopback()
        else:
            print ("Unknown Check type: " + checkType)
            sys.exit(3)

    # SIP Peer Stuff
    #################
    
    def CheckSipPeer(self):
        logging.debug(f"CheckSipPeer: {self._sip_host_name}");

        # List of peers we will build up during event callbacks
        self._sipPeerList = [];

        # This is how we receive results from this command, via events
        # coming to us in callbacks
        self._asteriskManager.register_event('PeerEntry', self.HandleSipPeerEvent)
        self._asteriskManager.register_event('PeerlistComplete', self.HandleSipPeerListComplete)

        sipPeerResult = self._asteriskManager.sippeers()
        # Check for "Success"?

    def HandleSipPeerEvent(self, event, manager):
       logging.debug(f"Receieved SipPeer event ({event.name})");
       
       self.DumpEventInfo(event);
       self._sipPeerList.append(event);

    def HandleSipPeerListComplete(self, event, manager):
        logging.debug(f"Receieved SipPeerlistComplete event ({event.name})");
        self.DumpEventInfo(event);

        # If we aren't looking for a specific Peer, process them all.
        if (self._sip_host_name is None):
            for peerEvent in self._sipPeerList:
                self.ProcessSipPeerEvent(peerEvent);
        # Otherwise, we are looking for just a particular Peer. 
        else:
            allHostnamesForDebugging = ''
            specificSipPeerFound = False;
            for peerEvent in self._sipPeerList:
                currentHostname = peerEvent.headers['ObjectName'];
                allHostnamesForDebugging += allHostnamesForDebugging + ' ' + currentHostname;
                if (currentHostname == self._sip_host_name):
                    self.ProcessSipPeerEvent(peerEvent);
                    specificSipPeerFound = True;
            if (specificSipPeerFound == False):
                self._critical_messages.append(f'Could not find Peer {self._sip_host_name}. All hostnames found: {allHostnamesForDebugging}')
        
        self.SetProcessingIsComplete();

    def HandleSipPeerEvent(self, event, manager):
       logging.debug(f"Receieved SipPeer event ({event.name})");
       
       self.DumpEventInfo(event);
       self._sipPeerList.append(event);
        
    def ProcessSipPeerEvent(self, sipPeerEvent):
        # Info about this Peer
        peerName = sipPeerEvent.headers['ObjectName']
        peerIPAddress = sipPeerEvent.headers['IPaddress']
        peerStatus = sipPeerEvent.headers['Status']
        peerChannelType = sipPeerEvent.headers['Channeltype']
        
        # Standardized message
        peerMessage = f'Peer {peerName} Status {peerStatus} - {peerIPAddress} {peerChannelType}'
        
        # Put the message in the appropriate list
        if (peerStatus.startswith('OK')):
            self._ok_messages.append(peerMessage)
        else:
            # Anything except "OK" treated as error. Not even sure what we might see.
            self._critical_messages.append(peerMessage)

    # SIP Registry Stuff
    ####################

    def CheckSipRegistry(self):
        logging.debug(f"CheckSipRegistry");

        # List of RegistryEntry we will build up during event callbacks
        self._sipRegistryEntryList = [];

        # This is how we receive results from this command, via events
        # coming to us in callbacks
        self._asteriskManager.register_event('RegistryEntry', self.HandleRegistryEntryEvent)
        self._asteriskManager.register_event('RegistrationsComplete', self.HandleRegistrationsComplete)

        sipRegistryResult = self._asteriskManager.sipshowregistry()
        # Check for "Success"?
        
    def HandleRegistryEntryEvent(self, event, manager):
       logging.debug(f"HandleRegistryEntryEvent()");
       logging.debug(f"Receieved SIP Registry event ({event.name})");
       
       self.DumpEventInfo(event);
       self._sipRegistryEntryList.append(event);

    # I think it's likely this Registration code will be close to working fine for IAX2 and
    # maybe more, but I lack the ability/patience to test it. 
    def HandleRegistrationsComplete(self, event, manager):
        logging.debug(f"HandleRegistrationsComplete()");
        logging.debug(f"Receieved RegistrationsComplete event ({event.name})");
        
        self.DumpEventInfo(event);

        # If we aren't looking for a specific SIP Host, process them all.
        if (self._sip_host_name is None):
            for sipRegistryEntry in self._sipRegistryEntryList:
                self.ProcessRegistryEntry(sipRegistryEntry);

        # Otherwise, we are looking for just a particular Registration.
        else:
            allHostnamesForDebugging = '';
            specificSipRegistrationFound = False;
            for sipRegistryEntry in self._sipRegistryEntryList:
                currentHostname = sipRegistryEntry.headers['Host']
                allHostnamesForDebugging += allHostnamesForDebugging + ' ' + currentHostname;
                if (currentHostname == self._sip_host_name):
                    self.ProcessRegistryEntry(sipRegistryEntry);
                    specificSipRegistrationFound = True;
            if (specificSipRegistrationFound == False):
                self._critical_messages.append(f'Could not find SIP Registration for hostname {self._sip_host_name}. All hostnames found: {allHostnamesForDebugging}')

        self.SetProcessingIsComplete();

    def ProcessRegistryEntry(self, sipRegistryEntry):
        logging.debug(f"ProcessRegistryEntry()");
        
        # Info about this Registration
        hostName = sipRegistryEntry.headers['Host']
        registryState = sipRegistryEntry.headers['State']

        # Standardized message
        registryMessage = f'Registered Host: {hostName} State: {registryState}'

        # Put the message in the appropriate list
        if (registryState.startswith('Registered')):
            self._ok_messages.append(registryMessage)
        else:
            # Anything except "Registered" treated as error. Not even sure what we might see.
            self._critical_messages.append(registryMessage)


    ### Loopback
    ############
    
    def CheckLoopback(self):
        logging.debug(f"CheckLoopback");
        
        self.InitiateLoopbackCall('SIP/2125551212voipms', '2125551212', '111222333')

        # List of RegistryEntry we will build up during event callbacks
        #self._sipRegistryEntryList = [];

        # This is how we receive results from this command, via events
        # coming to us in callbacks
        #self._asteriskManager.register_event('RegistryEntry', self.HandleRegistryEntryEvent)
        #self._asteriskManager.register_event('RegistrationsComplete', self.HandleRegistrationsComplete)

        #sipRegistryResult = self._asteriskManager.sipshowregistry()
        # Check for "Success"?    
    
        #             def InitiateLoopbackCall(self, channelName, numberToCall, outgoingCID):
    
    def InitiateLoopbackCall(self, channelName, numberToCall, outgoingCID):
       logging.debug(f"InitiateLoopbackCall on Channel Name: {channelName} Outgoing CID: {outgoingCID}")
       originateResponse = self._asteriskManager.originate(channelName, numberToCall, '', '', '', '', '', outgoingCID)
       print(f'originateResponse: {originateResponse}')


    ### More Connection Stuff
    ##########################

    def HandleGenericEvent(self, event, manager):
       # For now, just debugging information.
       logging.debug(f"Receieved event: {event.name}")

    def ConnectToAsteriskManager(self):
        logging.debug('ConnectToAsteriskManager')

        try:
            manager = asterisk.manager.Manager()
        
            logging.debug('In ConnectToAsteriskManager try...')
            manager.connect(self._hostname, self._port)
            manager.login(self._user, self._password)

            # Catch all events with Callbacks
            manager.register_event('*', self.HandleGenericEvent)

            #return manager;
            self._asteriskManager = manager;
        except asterisk.manager.ManagerSocketException as e:
            print (f"CRITICAL - Error connecting to the Asterisk Manager Interface (AMI) at {self._hostname} port {self._port}: {e}")
            sys.exit(2)
        except asterisk.manager.ManagerAuthException as e:
            print (f"CRITICAL - Error logging in to the Asterisk Manager Interface (AMI) at {self._hostname} port {self._port} using username {self._user}: {e}")
            sys.exit(2)
        except asterisk.manager.ManagerException as e:
            print (f"CRITICAL - Error: {e}")
            sys.exit(2)

    # Exit and Cleanup
    ##################

    def CleanUpAsteriskManager(self):
        logging.debug('CleanUpAsteriskManager - Logging out of Asterisk Manager Interface (AMI)')
        
        self._asteriskManager.logoff();

    def ExitAndShowResultStatus(self):
        logging.debug('ExitAndShowResultStatus')
    
        criticalCount = len(self._critical_messages)
        warningCount = len(self._warning_messages)
        okCount = len(self._ok_messages)

        criticalMessagesConcat = ", ".join(self._critical_messages);
        warningMessagesConcat = ", ".join(self._warning_messages);
        okMessagesConcat = ", ".join(self._ok_messages);
        
        if (criticalCount > 0):
            # Show critical errors before any warnings
            print (f'CRITICAL - {criticalMessagesConcat} {warningMessagesConcat} {okMessagesConcat}')
            sys.exit(2)
        elif (warningCount > 0): 
            print (f'WARNING - {warningMessagesConcat} {okMessagesConcat}')
            sys.exit(1)
        elif (okCount > 0):
            print (f'OK - {okMessagesConcat}')
            sys.exit(0)
        # If we get no messages of any kind it's more than likely we crashed.
        else:
            print (f'CRITICAL - No messages; unknown exception or other error? Try running with --debug for more information.')
            sys.exit(2)

### Static Routines

def SetupParser():
    DEFAULT_TIMEOUT_IN_SECONDS = 10;
    DEFAULT_AMI_PORT = 5038;

    # Build parser for arguments
    parser = argparse.ArgumentParser(description='Checks an Asterisk server using the AMI interface')
    parser.add_argument('-H', '--hostname', required=True, type=str, help='Hostname or IP address')
    parser.add_argument('-pt', '--port', nargs='?', const=DEFAULT_AMI_PORT, type=int, default=DEFAULT_AMI_PORT, help=f'AMI port. Defaults to {DEFAULT_AMI_PORT}')
    parser.add_argument('-u', '--user', required=True, type=str, help='Any valid user for Asterisk Manager')
    parser.add_argument('-p', '--passwd', required=True, type=str, help='Password')
    parser.add_argument('-ct', '--checktype', required=True, type=str, help='Type of check: siphost, sipregistry, loopback')
    parser.add_argument('-sh', '--siphost', required=False, type=str, help='name of specific SIP host to check')
    parser.add_argument('-tm', '--timeout', nargs='?', const=DEFAULT_TIMEOUT_IN_SECONDS, type=int, default=DEFAULT_TIMEOUT_IN_SECONDS, help=f'Timeout in number of seconds. Defaults to {DEFAULT_TIMEOUT_IN_SECONDS}.')
    parser.add_argument('-d', '--debug', required=False, action='store_true', help='Display debugging information; run script this way and record result when asking for help.')
    return parser;

def ExitIfNoArguments(parser):
    # if no arguments, print out help
    if len(sys.argv)==1:
        logging.debug('No arguments, printing help')
        parser.print_help(sys.stderr)
        sys.exit(1)

def main():
    # Build parser for arguments
    parser = SetupParser();
 
    # Exit and show help if no arguments
    ExitIfNoArguments(parser);
 
    # Parse the arguments
    args = parser.parse_args(sys.argv[1:])

    # Setup the checker
    asteriskChecker = AsteriskChecker(args.hostname, args.port, args.user, args.passwd, args.timeout, args.siphost, args.debug) 

    # Use the checker
    asteriskChecker.ConnectToAsteriskManager();
    asteriskChecker.HandleRequestedCheck(args.checktype.lower())

    # Wait on our event so we know processing is complete
    asteriskChecker.WaitForProcessingToBeComplete();

    # Cleanup and exit, showing our status
    asteriskChecker.CleanUpAsteriskManager();
    asteriskChecker.ExitAndShowResultStatus();

if __name__ == '__main__':
    main()
    
