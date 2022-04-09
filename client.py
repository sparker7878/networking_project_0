##################### IMPORTING LIBS #####################
import sys
import random
import os
from socket import *
from struct import pack, unpack_from
##################### DNS QUERY #####################
hostname = sys.argv[1]
#print("Given hostname is: " + hostname)
print("----------------------------------------------------------------------------")
print("Preparing DNS query..")
#Header Section
#LINE1
id_rand = random.getrandbits(16)
#print(id_rand)
header = pack(">H", id_rand) #formed strct header Hex

#LINE2
qr = "0"
opcode = "0000"
aatcrdra = "0010"
z = "000"
rcode = "0000"
header_line2 = qr + opcode + aatcrdra + z + rcode
header_line2_bin = int(header_line2,2)
header += pack(">H", header_line2_bin)

#LINE3
qdcount = "0000000000000001"
qdcount_bin = int(qdcount,2)
#LINE4
ancount = "0000000000000000"
ancount_bin = int(ancount,2)
#LINE5
nscount = "0000000000000000"
nscount_bin = int(nscount,2)
#LINE6
arcount = "0000000000000000"
arcount_bin = int(arcount,2)

header += pack(">H", qdcount_bin)
header += pack(">H", ancount_bin)
header += pack(">H", nscount_bin)
header += pack(">H", arcount_bin)
#print("header "+str(header)

### Question Section

# Transform URL to a form required for DNS query
# Split domain name into sections using '.' as a separator
# and transform every section into label
qname = b''
for section in hostname.split("."):
    # Each label consists of a length octet, followed by ASCII code octets
    qname += pack(">B", len(section))
    qname += bytes(section.encode('utf-8'))
#    for byte in bytes(section):
#        qname += byte
# QNAME terminates with the zero length octet for the null label of the root
qname += b'\x00'

# QTYPE: Set to 1 because we are only interested in A type records.type records for this assignment.
qtype = "0000000000000001"
qtype_bin = int(qtype,2)
qtype = pack(">H", qtype_bin)

# QCLASS - Internet
qclass = "0000000000000001"
qclass_bin = int(qclass,2)
qclass = pack(">H", qclass_bin)

# This is what we will send to DNS server
request = header + qname + qtype + qclass

##################### SEND QUERY #####################
print("Contacting DNS server..")
serverAddress = '8.8.8.8'
serverPort = 53 # 53 is DNS server
attempt_count = 0 #counter for keeping track of attempts to establish connection
clientSocket = socket(AF_INET, SOCK_DGRAM)

print("Sending DNS query..")
modifiedMessage = ''
clientSocket.sendto(request, (serverAddress, serverPort))
while attempt_count < 3:
    attempt_count += 1
    modifiedMessage, serverAddress = clientSocket.recvfrom(2048)
    if modifiedMessage:
        print("DNS  response received (attempt " + str(attempt_count) + " of 3)")
        break
        clientSocket.settimeout(5) #waiting for 5sec before timeout
clientSocket.close()

if len(modifiedMessage) == 0:
    print("Timeout querying DNS server")
    sys.exit(1)

#print(modifiedMessage)

print("Processing DNS response..")
print("----------------------------------------------------------------------------")
#header section
header = unpack_from(">HHHHHH", modifiedMessage)
#header line 2
p_qr = header[1]>>15
p_opcode = (header[1] & 0x7800)>>11
p_aa =  (header[1] & 0x400)>>10
p_tc =(header[1] & 0x200)>>9
p_rd = (header[1] & 0x100)>>8
p_ra =(header[1] & 0x80)>>7
p_z =(header[1] & 0x70)>>4
p_rcode = header[1] & 0xf
print("header.ID = " + str(header[0]))
print("header.QR = " + str(p_qr))
print("header.OPCODE = " + str(p_opcode))
print("header.AA = " + str(p_aa))
print("header.TC = " + str(p_tc))
print("header.RD = " + str(p_rd))
print("header.RA = " + str(p_ra))
print("header.Z = " + str(p_z))
print("header.RCODE = " + str(p_rcode))
print("header.QDCOUNT = " + str(header[2]))
print("header.ANCOUNT = " + str(header[3]))
print("header.NSCOUNT = " + str(header[4]))
print("header.ARCOUNT = " + str(header[5]))

#print(modifiedMessage)
#question section
p_qname = ''
for i in range(0, len(qname)):
    byte = unpack_from(">B", modifiedMessage, 12 + i)[0] #qname starts at 12
    if byte < 30:
        p_qname += '.'
    else:
        p_qname += chr(byte)
#print(p_qname)
p_qname = p_qname[1:-1]

p_qtype = unpack_from(">H", modifiedMessage, 12 + len(qname))[0]
p_qclass = unpack_from(">H", modifiedMessage, 12 + len(qname) + 2)[0]

print("question.QNAME = " + p_qname)
print("question.QTYPE = " + str(p_qtype))
print("question.QCLASS = " + str(p_qclass))

print("answer.NAME")
print("answer.TYPE")
print("answer.CLASS")
print("answer.TTL")
print("answer.RDLENGTH")
print("answer.RDATA")
print("----------------------------------------------------------------------------")
