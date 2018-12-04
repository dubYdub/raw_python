import binascii
import os
import random
import socket
import struct
import sys
import time

tab = '\t'
DEFAULT_PAYLOAD = 32
DEFAULT_BUFFER = 1024
DEFAULT_PORT = 0
DEFAULT_TIMEOUT = 3


def binary_equivalent(hex):
    return (bin(int(hex, 16))[2:]).zfill(16)


def one_complement_sum(binary_1, binary_2):
    sum = bin(int(binary_1, 2) + int(binary_2, 2))[2:].zfill(16)
    if len(sum) == 16:
        return sum
    else:
        return one_complement_sum(sum[1:], sum[0])


def calculate_checksum(packet):
    parts = []
    hexdump = binascii.hexlify(packet)
    hexdump = hexdump.decode("utf-8")
    j = 0

    for i in range((len(hexdump) // 4)):
        parts.append(binary_equivalent(hexdump[j:j + 4]))
        j += 4

    # handling the remaining hex, if any, padding them with 0's
    left_over = len(hexdump[j:])
    for i in range(4 - left_over):
        hexdump += "0"

    parts.append(binary_equivalent(hexdump[j:]))

    checksum = one_complement_sum(parts[0], parts[1])
    for i in range(2, len(parts)):
        checksum = one_complement_sum(checksum, parts[i])

    inverted_checksum = ""
    for char in checksum:
        if char == "0":
            inverted_checksum += "1"
        else:
            inverted_checksum += "0"

    return int(inverted_checksum, 2)


def get_ttl(packet):
    packet = binascii.hexlify(packet).decode("utf-8")
    return str(int(packet[16:18], 16))


def add_payload(size):
    return os.urandom(size)


def icmp(seq_no, payload_size):
    type = 8
    code = 0
    chksum = 0
    id = random.randint(0, 0xFFFF)
    data = add_payload(payload_size)
    real_checksum = calculate_checksum(struct.pack("!BBHHH", type, code, chksum, id, seq_no) + data)
    icmp_pkt = struct.pack("!BBHHH", type, code, real_checksum, id, seq_no)
    return icmp_pkt + data


def get_type(packet):
    return int(str(packet[20]))


def traceroute(hostname, no_packets, detailed):
    try:
        host_ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        print("Invalid Address")
        exit(1)
    print()
    print("Tracing route to " + hostname + " [" + socket.gethostbyname(hostname) + "]")
    print("over a maximum of 30 hops:")
    print()

    soc = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    soc.settimeout(DEFAULT_TIMEOUT)
    flag = 0
    for ttl in range(1, 31):
        count_responses = 0
        print(ttl, end="\t")
        address = []
        for i in range(1, no_packets + 1):
            try:
                start = time.time()
                soc.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
                soc.sendto(icmp(i, DEFAULT_PAYLOAD), (socket.gethostbyname(hostname), DEFAULT_PORT))
                packet, address = soc.recvfrom(DEFAULT_BUFFER)
                end = time.time()
                round_trip_time = (end - start) * 1000
                print(str(int(round_trip_time)) + " ms", end='\t')
                count_responses += 1
                if get_type(packet) == 0:
                    flag = 1
                    # uncomment next line if you want to wait between sending packets.
                    # time.sleep(1)
            except socket.timeout:
                print("*\t", end="\t")

        if count_responses != 0:
            try:
                print(socket.gethostbyaddr(address[0])[0] + " [" + address[0] + "]")
            except socket.herror:
                print(address[0])
        else:
            print("Request timed out.")

        if flag == 1:
            break

    if flag == 1:
        print("Trace complete")
    else:
        print("Unable to reach " + hostname + " in 30 hops")


def main():
    """
    The main program which determines type of request.
    :return: None
    """
    if len(sys.argv) < 3:  # checking for commandline arguments
        print("Please enter a host name.")
        exit(1)

    hostname = sys.argv[2]

    if sys.argv[1] == "traceroute":
        traceroute(hostname, 3, True)
    else:
        print("I can only traceroute now!")
        exit(1)


if __name__ == '__main__':
    main()