import sys
import socket
import struct

fileName = "/Users/jacobc/Python Projects/CyberSec-PCAP-Analysis/CyberSecurity2026.pcap"

# set file name
with open(fileName, "rb") as pcapFile:
    Global_header = pcapFile.read(24)
    Global_header_count = len(Global_header)

    # set global header count

magic_Number = Global_header[0:4]
major_vers = Global_header[4:6]
minor_vers = Global_header[6:8]
snap_length = Global_header[16:20]
data_link_type = Global_header[20:24]

# analyse global header

magic_Number_dec = int.from_bytes(magic_Number, byteorder=sys.byteorder)

major_Vers_dec = int.from_bytes(major_vers, byteorder=sys.byteorder)

minor_Vers_dec = int.from_bytes(minor_vers, byteorder=sys.byteorder)

snap_Length_dec = int.from_bytes(snap_length, byteorder=sys.byteorder)

data_Link_type_dec = int.from_bytes(snap_length, byteorder=sys.byteorder)

# convert raw bytes to decimal values

if magic_Number == b'\xd4\xc3\xb2\xa1':  # check endianess for little
    print("Magic Number is little endian")
    # reverse processs here as little endian in decimal format
    # [::-1] inverses str converted integers
    print("---------------------------------------------------------")
    print("Magic Number in raw byte form: " + str(magic_Number))
    print("Magic Number in decimal value: " + str(magic_Number_dec))
    print("---------------------------------------------------------")
    little_endian_major_vers_len = str(major_Vers_dec)[::-1]
    print("Major Version: " + little_endian_major_vers_len)
    print("---------------------------------------------------------")
    little_endian_minor_vers_len = str(minor_Vers_dec)[::-1]
    print("Minor Version: " + little_endian_minor_vers_len)
    print("---------------------------------------------------------")
    little_endian_snap_length_len = str(snap_Length_dec)[::-1]
    print("Snap Length: " + little_endian_snap_length_len)
    print("---------------------------------------------------------")
    little_endian_data_link_type_len = str(data_Link_type_dec)[::-1]
    print("Data Link Type: " + little_endian_data_link_type_len)
    print("---------------------------------------------------------")

else:  # big endian check

    print("Magic Number is big endian")
    print("---------------------------------------------------------")
    print("Global Header Count: " + str(Global_header_count))
    print("---------------------------------------------------------")
    print("Magic Number in raw byte form: " + str(magic_Number))
    print("Magic Number in decimal value: " + str(magic_Number_dec))
    print("---------------------------------------------------------")
    print("Major Version: " + str(major_vers))
    print("Major Version in decimal value: " + str(major_Vers_dec))
    print("---------------------------------------------------------")
    print("Minor Version: " + str(minor_vers))
    print("Minor Version in decimal value: " + str(minor_Vers_dec))
    print("---------------------------------------------------------")
    print("Snap Length: " + str(snap_length))
    print("Snap Length in decimal value: " + str(snap_Length_dec))
    print("---------------------------------------------------------")
    print("Data Link Type: " + str(data_link_type))
    print("Data Link Type in decimal value: " + str(data_Link_type_dec))
    print("---------------------------------------------------------")
