import scapy.all as scapy
from scapy_http import http
import optparse

def getUserInput():
    parseObject = optparse.OptionParser()
    parseObject.add_option("-i", "--interface", dest="interface", help="Enter the interface")
    (userInput, arguments) = parseObject.parse_args()

    if not userInput.interface:
        print("Enter the interface. (-i *required)")
    return userInput.interface

def listenPackets(interface):
    scapy.sniff(iface=interface, store=False, prn=analyzePackets)

def analyzePackets(packet):
    # packet.show()

    # checking the layers for example
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.Raw):
            print(packet[scapy.Raw].load)

interface = getUserInput()
if interface:
    listenPackets(interface)