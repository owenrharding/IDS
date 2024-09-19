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
from scapy.all import rdpcap, IP, ICMP, TCP, UDP, Raw
from datetime import datetime


class Rule:
    """
    Models a single rule in an IDS rule file.
    """
    def __init__(self, ruleStr: str, logFile: str):
        """
        Initializes a Rule object.
        """
        self.rule = ruleStr.split() # Split the ruleStr into a list of strings.
        self.extract_rule_fields()
        self.check_fields()
        self.logFile = logFile

    def print_rule(self) -> None:
        """
        Prints the rule. Used for debugging.
        """
        print("=== RULE ===")
        if self.action:
            print("Action:", self.action)
        if self.protocol:
            print("Protocol:", self.protocol)
        if self.sourceIP:
            print("Source IP:", self.sourceIP)
        if self.sourcePort:
            print("Source Port:", self.sourcePort)
        if self.destinationIP:
            print("Destination IP:", self.destinationIP)
        if self.destinationPort:
            print("Destination Port:", self.destinationPort)
        if self.msg:
            print("Message:", self.msg)
        if self.flag:
            print("Flag:", self.flag)
        if self.content:
            print("Content:", self.content)
    
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
        self.packetsProcessed = 0

    def extract_additional_options(self, additionalOptions) -> None:
        # From "alert tcp any any -> any any (msg: "receive a tcp packet";)",
        # Example additional options:
        # (msg: "TCP syn scan detected"; flags: S; detection_filter: count 10, seconds 2;)
        # the message should be "receive a tcp packet".
        self.msg = None
        self.flag = None
        self.flag_plus = False
        self.content = None
        self.detectionFilter = False
        self.count = None
        self.seconds = None
        self.timestampLog = []

        optionsStr = " ".join(additionalOptions)

        if "content" in optionsStr:
            # Find first occurrence of '"' and ';' after "content".
            firstQuotationMarkAfterContentIndex = optionsStr.find('"', optionsStr.find("content"))
            firstSemicolonAfterContentIndex = optionsStr.find(';', firstQuotationMarkAfterContentIndex)
            # Add one to the index of the first quotation mark to skip it.
            # Subtract one from the index of the first semicolon to skip the quotation mark.
            self.content = optionsStr[(firstQuotationMarkAfterContentIndex + 1) : (firstSemicolonAfterContentIndex - 1)]

        if "msg" in optionsStr:
            # Find first occurrence of '"' and ';' after "msg".
            firstQuotationMarkAfterMsgIndex = optionsStr.find('"', optionsStr.find("msg"))
            firstSemicolonAfterMsgIndex = optionsStr.find(';', firstQuotationMarkAfterMsgIndex)
            # Add one to the index of the first quotation mark to skip it.
            # Subtract one from the index of the first semicolon to skip the quotation mark.
            self.msg = optionsStr[(firstQuotationMarkAfterMsgIndex + 1) : (firstSemicolonAfterMsgIndex - 1)]

        if "flags" in optionsStr:
            # Find first occurrence of ';' after "flags".
            firstSemicolonAfterFlagsIndex = optionsStr.find(';', optionsStr.find("flags"))
            # Should be the character before the semicolon.
            self.flag = self.set_flag(optionsStr[optionsStr.find("flags") + 7 : firstSemicolonAfterFlagsIndex])

        if "detection_filter" in optionsStr:
            # Find first occurrence of ';' after "detection_filter".
            firstSemicolonAfterDetectionFilterIndex = optionsStr.find(';', optionsStr.find("detection_filter"))

            if "count" in optionsStr[optionsStr.find("detection_filter"):firstSemicolonAfterDetectionFilterIndex]:
                # Find first occurrence of ',' after "count".
                firstCommaAfterCountIndex = optionsStr.find(',', optionsStr.find("count"))
                count = optionsStr[optionsStr.find("count") + 6 : firstCommaAfterCountIndex]
                if count.isdigit():
                    self.count = int(count)
                else:
                    print("Invalid count.")

            if "seconds" in optionsStr[optionsStr.find("detection_filter"):firstSemicolonAfterDetectionFilterIndex]:
                # Find first occurrence of ';' after "seconds".
                firstSemicolonAfterSecondsIndex = optionsStr.find(';', optionsStr.find("seconds"))
                seconds = optionsStr[optionsStr.find("seconds") + 8 : firstSemicolonAfterSecondsIndex]
                if seconds.isdigit():
                    self.seconds = int(seconds)
                else:
                    print("Invalid seconds.")
            
            if self.count is not None and self.seconds is not None:
                self.detectionFilter = True
    
    def set_flag(self, flag: str) -> str:
        """
        Sets the flag based on a given string.
        Character should be one of "S" (SYN), "A" (ACK), "F" (FIN), "R" (RST),
        or "S+"/"A+"/"F+"/"R+" (extension meaning it's non-exclusive).
        """
        if "+" in flag:
            self.flag_plus = True

        if "S" in flag:
            return "S"
        elif "A" in flag:
            return "A"
        elif "F" in flag:
            return "F"
        elif "R" in flag:
            return "R"
        else:
            print("Invalid flag.")
            return None

    def check_fields(self) -> None:
        """
        Checks if the fields are valid.
        """
        # Currently no check for IP addresses, these are just strings
        # (as are the scapy IP adress fields).
        # Check if the action is valid.
        if self.action != "alert":
            print("Invalid/unimplemented action.")
            return False
        
        # Check if the protocol is valid.
        if self.protocol not in ["ip", "icmp", "tcp", "udp"]:
            print("Invalid protocol.")
            return False

        # Check if the source port is an integer.
        if self.sourcePort.isdigit():
            self.sourcePort = int(self.sourcePort)
        elif self.sourcePort != "any":
            print("Invalid source port.")
            return False

        # Check if the destination port is an integer.
        if self.destinationPort.isdigit():
            self.destinationPort = int(self.destinationPort)
        elif self.destinationPort != "any":
            print("Invalid destination port.")
            return False

        if self.flag not in [None, "S", "A", "F", "R"]:
            print("Invalid flag.")
            return False
    
    def log_message(self) -> None:
        """
        Logs the message to the outfile IDS_log.txt.
        """
        currentTime = datetime.now()
        # Format the current time.
        formattedTime = currentTime.strftime("%Y-%m-%d %H:%M:%S")
        # Write the formatted time and the message to the log file.
        self.logFile.write(formattedTime + " - Alert: " + self.msg + "\n")
    
    def content_in_packet(self, packet) -> bool:
        """
        Checks if the content is in the packet.
        """
        # Get packet string contents.
        # REF: Getting packet contents as a string inspired by:
        # https://stackoverflow.com/questions/29288848/
        # get-info-string-from-scapy-packet#comment95603401_45162911
        packetContents = packet.get_scapy_packet().show(dump=True)
        if self.content in packetContents:
            return True
        return False
    
    def detection_filter_alert(self, newPacketTimestamp) -> None:
        """
        Checks if the timestamps satisfy the detection filter.
        """
        self.timestampLog.append(newPacketTimestamp)
        # Keep the log the same size as the count.
        if len(self.timestampLog) > self.count:
            self.timestampLog = self.timestampLog[1:]
        # Sort timestamps. This way, if the the difference between the first
        # and fifth timestamp is less than or equal to the time window given in
        # the detection filter, then all five timestamps are sent within that
        # time window. This can be generalised to any number of timestamps
        # specified in the detection filter.
        self.packetsProcessed += 1
        print("========== TIMESTAMP LOG ==========")
        print("Number of timestamps:", len(self.timestampLog))
        print("Packet number:", self.packetsProcessed)
        print("Detection filter count:", self.count)
        print("Detection filter seconds:", self.seconds)
        print(self.timestampLog)
        if len(self.timestampLog) >= self.count:
            diff = self.timestampLog[-1] - self.timestampLog[0]
            print("Difference between", "(", self.timestampLog[0], ") and", "(", self.timestampLog[-1], ") is", diff)
            if diff <= self.seconds:
                print("*** FLOODING DETECTED ***")
                # Remove timestamps from i to i + count - 1.
                return True
        return False
    
    def check_packet(self, packet) -> None:
        """
        Checks if the given packet satisfies the properties of this rule.
        If it does, log the message.
        """
        if self.protocol != packet.protocol and self.protocol != "ip":
            return
        if self.sourceIP != "any" and self.sourceIP != packet.sourceIP:
            return
        if self.sourcePort != "any" and self.sourcePort != packet.sourcePort:
            return
        if self.destinationIP != "any" and self.destinationIP != packet.destinationIP:
            return
        if self.destinationPort != "any" and self.destinationPort != packet.destinationPort:
            return
        if self.content is not None and not self.content_in_packet(packet):
            return
        if self.flag is not None and self.flag not in packet.flags:
            return
        if self.detectionFilter:
            if not self.detection_filter_alert(packet.timestamp):
                return
        
        # If it's made it to this point, the packet satisfies the rule.
        self.log_message()
    

class RuleSet:
    """
    Models a set of rules in an IDS rule file.
    """
    def __init__(self, rulesFilePath: str, logFile: str):
        """
        Initializes a RuleSet object.
        """
        self.rules = []
        self.rulesFilePath = rulesFilePath
        self.logFile = logFile 
        self.read_rules()
    
    def read_rules(self) -> None:
        """
        Reads rules from a file.
        """
        with open(self.rulesFilePath, 'r') as rulesFile:
            for line in rulesFile:
                if line.startswith("#"):
                    continue
                rule = Rule(line, self.logFile)
                self.rules.append(rule)
    
    def get_rules(self) -> list:
        """
        Returns the rules.
        """
        return self.rules


class Packet:
    """
    Models a packet in a pcap file.
    """
    def __init__(self, packet):
        """
        Initializes a Packet object.
        """
        self.packet = packet
        self.extract_packet_fields()
    
    def extract_packet_fields(self) -> None:
        """
        Extracts fields from the packet.
        """
        self.ipLayer = self.packet[IP] if IP in self.packet else None
        self.tcpLayer = self.packet[TCP] if TCP in self.packet else None
        self.udpLayer = self.packet[UDP] if UDP in self.packet else None
        # REF: Getting flags from a packet inspired by:
        # https://stackoverflow.com/questions/20429674/get-tcp-flags-with-scapy
        self.flags = self.tcpLayer.flags if self.tcpLayer is not None else None
        self.protocol = self.extract_protocol()
        self.sourceIP = self.extract_source_ip()
        self.sourcePort = self.extract_source_port()
        self.destinationIP = self.extract_destination_ip()
        self.destinationPort = self.extract_destination_port()
        # REF: Getting the timestamp of a packet inspired by:
        # https://stackoverflow.com/questions/11615892/
        # scapy-get-packets-arrivals-time
        self.timestamp = self.packet.time

    def print_packet(self) -> None:
        """
        Prints the packet. Used for debugging.
        """
        print("=== PACKET ===")
        if self.protocol:
            print("Protocol:", self.protocol)
        if self.sourceIP:
            print("Source IP:", self.sourceIP)
        if self.sourcePort:
            print("Source Port:", self.sourcePort)
        if self.destinationIP:
            print("Destination IP:", self.destinationIP)
        if self.destinationPort:
            print("Destination Port:", self.destinationPort)
    
    def get_scapy_packet(self):
        """
        Returns the scapy packet.
        """
        return self.packet
    
    def extract_protocol(self) -> str:
        """
        Extracts the protocol of the packet.
        """
        # REF: Protocol extraction logic inspired by:
        # https://stackoverflow.com/questions/22093971/
        # how-to-verify-if-a-packet-in-scapy-has-a-tcp-layer
        if TCP in self.packet:
            return "tcp"
        elif UDP in self.packet:
            return "udp"
        elif ICMP in self.packet:
            return "icmp"

    def extract_source_ip(self) -> str:
        """
        Extracts the source IP of the packet.
        """
        # REF: Source/dest IP and source/dest port extraction logic inspired by:
        # https://stackoverflow.com/questions/19311673/
        # fetch-source-address-and-port-number-of-packet-scapy-script
        if self.ipLayer is not None:
            return self.ipLayer.src

    def extract_source_port(self) -> int:
        """
        Extracts the source port of the packet.
        """
        if self.tcpLayer is not None:
            return self.tcpLayer.sport
        elif self.udpLayer is not None:
            return self.udpLayer.sport

    def extract_destination_ip(self) -> str:
        """
        Extracts the destination IP of the packet.
        """
        if self.ipLayer is not None:
            return self.ipLayer.dst

    def extract_destination_port(self) -> int:
        """
        Extracts the destination port of the packet.
        """
        if self.tcpLayer is not None:
            return self.tcpLayer.dport
        elif self.udpLayer is not None:
            return self.udpLayer.dport


class PacketSet:
    """
    Models a set of packets in a pcap file.
    """
    def __init__(self, pcapFilePath: str):
        """
        Initializes a PacketSet object.
        """
        self.packets = []
        self.pcapFilePath = pcapFilePath
        self.read_packets()
    
    def read_packets(self) -> None:
        """
        Reads packets from a pcap file.
        """
        packets = rdpcap(self.pcapFilePath)
        for packet in packets:
            packet = Packet(packet)
            self.packets.append(packet)
    
    def get_packets(self) -> list:
        """
        Returns the packets.
        """
        return self.packets


def main():
    # Check if the number of arguments in command line is correct.
    if len(sys.argv) != 3:
        print("Incorrect number of arguments.")

    # Parse and extract command line arguments.
    pcapFilePath = sys.argv[1]
    rulesFilePath = sys.argv[2]

    logFile = open("IDS_log.txt", 'w')

    # Parse the IDS rules file.
    rules = RuleSet(rulesFilePath, logFile)

    # Read pcap file. Uses scapy Packet class.
    packets = PacketSet(pcapFilePath)

    for packet in packets.get_packets():
        for rule in rules.get_rules():
            rule.check_packet(packet)


if __name__ == '__main__':
    main()