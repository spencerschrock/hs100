import os
# Uncomment if on Mac OS and the OS is unable to find scapy.all
os.sys.path.append('/usr/local/lib/python2.7/site-packages')
from scapy.all import *
import sys
import binascii

# decodes TCP or UDP packet paylods
def decode(payload):
    # decode backwards
    s = str(payload)[::-1]
    ret = ""
    for i in range(len(s)):
        if i + 1 < len(s):
            c = chr(ord(s[i]) ^ ord(s[i+1]))
            ret += c

    ret = ret[::-1]

    # beginning of command is at location of first "
    begin = ret.find('\"')

    # manually append the missing {
    ret = '{' + ret[begin:] 

    # if properly formatted, print msg
    if ret.find('}') > -1:
        print ret

# if programming being run directly from CLI
if __name__ == "__main__":

    # check if the pcap was provided
    if len(sys.argv) < 2:
        print "Usage: python decode.py <pcap file>"
        quit()

    # open pcap using scapy
    pcap = PcapReader(sys.argv[1])

    # iterate through and extract all TCP or UDP payloads
    for pkt in pcap:   
        if TCP in pkt:
            decode(pkt[TCP].payload)  
        elif UDP in pkt:
            decode(pkt[UDP].payload)
