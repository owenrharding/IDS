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

        # Join the remainder of the rule (everything in parentheses) into a string.
        remainingOptions = " ".join(self.rule[7:])
    
        # From "alert tcp any any -> any any (msg: "receive a tcp packet";)",
        # the message should be "receive a tcp packet".
        openingBracketIndex = remainingOptions.find("(")
        firstSemiColonIndex = remainingOptions.find(";")
        # Will need to change this later to handle multiple options.
        # MSG DOES NOT ALWAYS GO FIRST.
        self.msgStr = remainingOptions[openingBracketIndex+1:firstSemiColonIndex]

    def check_fields(self) -> None:
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
    
    def get_protocol(self) -> str:
        return self.protocol
    
    def get_sourceIP(self) -> str:
        return self.sourceIP
    
    def get_sourcePort(self):
        return self.sourcePort
    
    def get_destinationIP(self):
        return self.destinationIP
    
    def get_destinationPort(self):
        return self.destinationPort


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
            # Task 1.
            if rule.get_protocol() == "tcp" and packet.haslayer(TCP):
                # Log message.
                rule.log_message()


if __name__ == '__main__':
    main()