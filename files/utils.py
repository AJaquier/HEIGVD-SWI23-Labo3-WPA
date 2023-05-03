from scapy.all import *
from binascii import a2b_hex, b2a_hex
#from pbkdf2 import pbkdf2_hex
from pbkdf2 import *
from numpy import array_split
from numpy import array
import hmac, hashlib

def collect_infos_from_pcap(pcapfile, constructor_mac_prefix=""):
    """
    This function parses a pcap file and returns the following parameters:
    - APmac
    - Clientmac
    - APnonce
    - Clientnonce
    - MIC
    - data
    """
    wpa = rdpcap(pcapfile)
    print("Constuctor MAC prefix: ", constructor_mac_prefix)

    # identify where is the first packet of the 4-way handshake
    for i in range(0, len(wpa)):
        if wpa[i].type == 2 and wpa[i].subtype == 8:
            try:
                if wpa[i][EAPOL].type == 3:
                    # Check if it is the first packet of the 4-way handshake based on the message info number
                    to_ds = wpa[i].FCfield & 0b01 != 0

                    # Identify the direction of the message C->AP or AP->C
                    if to_ds:
                       continue
                    else:
                        print("AP -> CLI")
                        print(i)
                    

                    if (constructor_mac_prefix == ""):
                        print("No constructor MAC prefix provided, we will use the first 4-way handshake found in the pcap")
                        break

                    #check MAC of the AP to keep only the 4-way handshake related to the constructor selected
                    print("AP MAC: ", str(wpa[i].addr2))
                    if (str(wpa[i].addr2).startswith(constructor_mac_prefix)):
                        break
                        
            except:
                pass

    if (i == len(wpa)-1):
        print("No 4-way handshake found in the pcap file")
        exit()


    # retrieve APmac and clientmac from the first packet of the 4-way handshake
    Clientmac = a2b_hex(wpa[i].addr1.replace(":", ""))
    APmac = a2b_hex(wpa[i].addr2.replace(":", ""))

    #retrieve pmkid
    pmkid = wpa[i].original[-20:-4]
    print("Index of the 4-way handshake: ", i)

    #retrieve ssid from the beacon frame
    #iterate over all packets before the 4-way handshake
    for j in range(0, i):
        #check if the packet is a beacon frame
        if wpa[j].type == 0 and wpa[j].subtype == 8:
            #check if the beacon frame is from the same AP as the 4-way handshake
            if str(wpa[j].addr2).replace(":", "") == APmac.hex():
                ssid = wpa[j].info.decode("utf-8")
                break
    
    if (j == i):
        print("No beacon frame found in the pcap file")
        exit()

    print("We found all required parameters for the attack in the pcap !")

    return ssid, APmac, Clientmac, pmkid
