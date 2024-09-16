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
        self.extract_rule_fields()
        self.check_fields()
    
    def extract_rule_fields(self):
        """
        Extracts fields from the rule.
        """
        self.action = self.rule[0]
        self.protocol = self.rule[1]
        self.sourceIP = self.rule[2]
        self.sourcePort = self.rule[3]
        self.destinationIP = self.rule[5] # Skip the "->" symbol.
        self.destinationPort = self.rule[6]
        self.message = " ".join(self.rule[7:])

    def check_fields(self):
        """
        Checks if the fields are valid.
        """
        # Check if the action is valid.
        if self.action != "alert":
            print("Invalid action.")
            return False
        
        # Check if the protocol is valid.
        if self.protocol not in ["tcp", "udp", "icmp"]:
            print("Invalid protocol.")
            return False

        # Check if the source IP is valid.
        if not self.sourceIP:
            print("Invalid source IP.")
            return False

        # Check if the source port is valid.
        if not self.sourcePort:
            print("Invalid source port.")
            return False

        # Check if the destination IP is valid.
        if not self.destinationIP:
            print("Invalid destination IP.")
            return False

        # Check if the destination port is valid.
        if not self.destinationPort:
            print("Invalid destination port.")
            return False

        return True

def main():
    # Check if the number of arguments in command line is correct.
    if len(sys.argv) != 3:
        print("Incorrect number of arguments.")

    # Parse and extract command line arguments.
    execProgram = sys.argv[0]
    pcapFilePath = sys.argv[1]
    rulesFilePath = sys.argv[2]

    # Read pcap file.
    packets = rdpcap(pcapFilePath)


def process_ids_rule(rule: str):
    """
    Takes a single rule and processes it.
    """
    


if __name__ == '__main__':
    main()