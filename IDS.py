# Intrusion Detection System

"""
This program would read two files:
1) one file includes intrusion detection rules (like rules used in Snort) and 
2) the other file is the .pcap file that contains all the packets that your 
   program would go through to check if any or some of them violates the rules.

Both files will be passed into your Python program (IDS.py) through the 
Command-Line Argument.

The start of IDS.py would be:
$python3 IDS.py <path_to_the_pcap_file> <path_to_the_IDS_rules>
Both paths need to be absolute paths.
"""

import sys
from scapy.all import *
from scapy.all import IP, ICMP, TCP, UDP
from datetime import datetime


class Rule:
    """
    Models a single rule in an IDS rule file.
    """
    def __init__(self, ruleStr: str):
        """
        Initializes a Rule object.
        """
        self.rule = ruleStr.split() # Split the ruleStr into a list of strings.
    
    def extract_rule_fields(self) -> None:
        """
        Extracts fields from the rule.
        """
        self.action = self.rule[0]
        self.protocol = self.rule[1]
        self.sourceIP = self.rule[2]
        self.sourcePort = self.rule[3]
        self.destinationIP = self.rule[5] # Skip the "->" symbol.
        self.destinationPort = self.rule[6]
        self.additionalOptions = self.extract_additional_options(self.rule[7:])
    
    def extract_additional_options(self, additionalOptions) -> None:
        # From "alert tcp any any -> any any (msg: "receive a tcp packet";)",
        # Example additional options:
        # (msg: "TCP syn scan detected"; flags: S; detection_filter: count 10, seconds 2;)
        # the message should be "receive a tcp packet".
        self.msg = None
        self.flag = None
        self.detectionFilter = None

        optionsStr = " ".join(additionalOptions)

        if "content" in additionalOptions:
            # Find first occurrence of '"' and ';' after "content".
            firstQuotationMarkAfterContentIndex = optionsStr.find('"', optionsStr.find("content"))
            firstSemicolonAfterContentIndex = optionsStr.find(';', firstQuotationMarkAfterContentIndex)
            # Add one to the index of the first quotation mark to skip it.
            # Subtract one from the index of the first semicolon to skip the quotation mark.
            self.content = optionsStr[(firstQuotationMarkAfterContentIndex + 1) : (firstSemicolonAfterContentIndex - 1)]

        if "msg" in additionalOptions:
            # Find first occurrence of '"' and ';' after "msg".
            firstQuotationMarkAfterMsgIndex = optionsStr.find('"', optionsStr.find("msg"))
            firstSemicolonAfterMsgIndex = optionsStr.find(';', firstQuotationMarkAfterMsgIndex)
            # Add one to the index of the first quotation mark to skip it.
            # Subtract one from the index of the first semicolon to skip the quotation mark.
            self.msg = optionsStr[(firstQuotationMarkAfterMsgIndex + 1) : (firstSemicolonAfterMsgIndex - 1)]

        if "flags" in additionalOptions:
            # Find first occurrence of ';' after "flags".
            firstSemicolonAfterFlagsIndex = optionsStr.find(';', optionsStr.find("flags"))
            # Should be the character before the semicolon.
            self.flag = optionsStr[firstSemicolonAfterFlagsIndex - 1]

        ### IMPLEMENT DETECTION FILTER EXTRACTION ###

    def check_fields(self) -> None:
        """
        Checks if the fields are valid.
        """
        # Check if the action is valid.
        if self.action != "alert":
            print("Invalid/unimplemented action.")
            return False
        
        # Check if the protocol is valid.
        if self.protocol not in ["ip", "icmp", "tcp", "udp"]:
            print("Invalid protocol.")
            return False

        # Check if the source IP is valid.
        if not self.sourceIP:
            print("Invalid source IP.")
            return False

        # Check if the source port is an integer.
        if self.sourcePort.isdigit():
            self.sourcePort = int(self.sourcePort)
        elif self.sourcePort != "any":
            print("Invalid source port.")
            return False

        # Check if the destination IP is valid.
        if not self.destinationIP:
            print("Invalid destination IP.")
            return False

        # Check if the destination port is an integer.
        if self.destinationPort.isdigit():
            self.destinationPort = int(self.destinationPort)
        elif self.destinationPort != "any":
            print("Invalid destination port.")
            return False
    
    def log_message(self) -> None:
        """
        Logs the message to the outfile IDS_log.txt.
        """
        with open('IDS_log.txt', 'w') as logFile:
            currentTime = datetime.now()
            # Format the current time.
            formattedTime = currentTime.strftime("%Y-%m-%d %H:%M:%S")
            # Write the formatted time and the message to the log file.
            logFile.write(formattedTime, "Alert: ", self.msgStr)
    
    def check_packet_pass(self, packet) -> None:
        """
        Checks if the packet passes the rule.
        """
        if IP in packet:
            # Extract ip layer from packet.
            ipLayer = packet[IP]

            # Check if the packet's protocol matches the rule's protocol.
            if TCP in packet and self.protocol == "tcp":
                # Extract tcp layer from packet.
                tcpLayer = packet[TCP]
                # Check if ALL of the packet's properties match those specified
                # in the rule.
                if ((self.sourcePort == "any" or self.sourcePort == tcpLayer.sport) and
                    (self.sourceIP == "any" or self.sourceIp == ipLayer.src) and
                    (self.destinationPort == "any" or self.destinationPort == tcpLayer.dport) and 
                    (self.destinationIP == "any" or self.destinationIP == ipLayer.dst)):

                    self.log_message()
            
            elif UDP in packet and self.protocol == "udp":
                # Extract udp layer from packet.
                udpLayer = packet[UDP]
                # Check if ALL of the packet's properties match those specified
                # in the rule.
                if ((self.sourcePort == "any" or self.sourcePort == udpLayer.sport) and
                    (self.sourceIP == "any" or self.sourceIp == ipLayer.src) and
                    (self.destinationPort == "any" or self.destinationPort == udpLayer.dport) and 
                    (self.destinationIP == "any" or self.destinationIP == ipLayer.dst)):

                    self.log_message()


class RuleSet:
    """
    Models a set of rules in an IDS rule file.
    """
    def __init__(self, rulesFilePath: str):
        """
        Initializes a RuleSet object.
        """
        self.rules = []
        self.rulesFilePath = rulesFilePath
    
    def read_rules(self) -> None:
        """
        Reads rules from a file.
        """
        with open(self.rulesFilePath, 'r') as rulesFile:
            for line in rulesFile:
                if line.startswith("#"):
                    continue
                rule = Rule(line)
                self.rules.append(rule)
    
    def get_rules(self) -> list:
        """
        Returns the rules.
        """
        return self.rules


def main():
    # Check if the number of arguments in command line is correct.
    if len(sys.argv) != 3:
        print("Incorrect number of arguments.")

    # Parse and extract command line arguments.
    pcapFilePath = sys.argv[1]
    rulesFilePath = sys.argv[2]
    
    # Parse the IDS rules file.
    rules = RuleSet(rulesFilePath)
    rules.read_rules()
    for rule in rules.get_rules():
        rule.extract_rule_fields()
        rule.check_fields()

    # Read pcap file. Uses scapy Packet class.
    packets = rdpcap(pcapFilePath)

    for packet in packets:
        # Finish this logic by comparing packet to rule in ruleset.
        for rule in rules.get_rules():
            rule.check_packet_pass(packet)


if __name__ == '__main__':
    main()