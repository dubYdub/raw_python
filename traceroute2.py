#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#
#           Copyright 2018 Dept. CSE SUSTech
#           Copyright 2018 Suraj Singh Bisht
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#
#
# --------------------------------------------------------------------------
#                         Don't Remove Authors Info                        |
# --------------------------------------------------------------------------


__author__ = 'Suraj Singh Bisht, HHQ. ZHANG'
__credit__ = '["Suraj Singh Bisht",]'
__contact__ = 'contact@jinlab.cn'
__copyright__ = 'Copyright 2018 Dept. CSE SUSTech'
__license__ = 'Apache 2.0'
__Update__ = '2018-01-11 12:33:09.399381'
__version__ = '0.1'
__maintainer__ = 'HHQ. ZHANG'
__status__ = 'Production'

import random
import select
# import module
import socket
import time
import binascii

from raw_python import ICMPPacket,IPPacket, parse_icmp_header, parse_eth_header, parse_ip_header

def calc_rtt(time_sent):
    return time.time() - time_sent


def catch_ping_reply(s, ID, time_sent, timeout=1):
    # create while loop
    while True:
        starting_time = time.time()  # Record Starting Time

        # to handle timeout function of socket
        process = select.select([s], [], [], timeout)

        # check if timeout
        if not process[0]:
            return calc_rtt(time_sent), None, None

        # receive packet
        rec_packet, addr = s.recvfrom(1024)

        # extract icmp packet from received packet
        icmp = parse_icmp_header(rec_packet[20:28])


        return calc_rtt(time_sent), parse_ip_header(rec_packet[:20]), icmp

def traceroute_request( addr=None):

    sendSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    address = socket.gethostbyname(addr)
    print("Traceroute to "+addr+' '+'['+address+']'+ " 30 hops max")

    #30 hops at most
    for ttl in range(1,31):

        sign = ''
        #refresh the ttl
        sendSocket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        #set timeout
        sendSocket.settimeout(3)
        print (ttl, end='\t')
        for i in range(3):
            try:
                # Random Packet Id
                pkt_id = random.randrange(10000, 65000)
                packet = ICMPPacket(_id=pkt_id).raw
                sendSocket.sendto(packet, (socket.gethostbyname(address), 0))
                rtt, reply, icmp_reply = catch_ping_reply(sendSocket, pkt_id, time.time())

                if reply:
                    sign = reply
                    reply['length'] = reply['Total Length'] - 20  # sub header
                    print('{0:.2f} ms'.format(rtt*1000), end='\t')
                else:
                    print("*", end="\t")

            except socket.timeout:
                print("*", end="\t")
        if sign:
            # break the procedure when it has reached the destination
            if (sign["Source Address"] == address):
                print(addr+'\t'+'['+address+']')
                break;
            print('{0[Source Address]}'.format(sign), end='\t')
        print()

    # close socket
    sendSocket.close()
    return pkt_id

def main():
    # create socket

    # take Input
    addr = input("[+] Enter Domain Name : ") or "www.sustc.edu.cn"

    ID = traceroute_request(addr)

    return

if __name__ == '__main__':
    main()
