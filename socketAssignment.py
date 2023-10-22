import socket
import os
import sys
import struct
import time
import select
import binascii

ICMP_ECHO_REQUEST = 8

# Function to calculate checksum for the ICMP packet
def checksum(packet):
    sum = 0
    countTo = (len(packet) // 2) * 2

    count = 0
    while count < countTo:
        thisVal = packet[count + 1] * 256 + packet[count]
        sum = sum + thisVal
        sum = sum & 0xffffffff
        count = count + 2

    if countTo < len(packet):
        sum = sum + packet[len(packet) - 1]
        sum = sum & 0xffffffff

    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

# Function to send a ping request
def send_ping_request(ping_socket, destination_addr, ID):
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    checksum_val = 0
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, checksum_val, ID, 1)
    data = b'PingData'
    checksum_val = checksum(header + data)

    # Create a new header with the correct checksum
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, socket.htons(checksum_val), ID, 1)
    packet = header + data
    ping_socket.sendto(packet, (destination_addr, 1))

# Function to receive the ping response
def receive_ping_response(ping_socket, ID, timeout):
    time_left = timeout
    while True:
        started_select = time.time()
        ready = select.select([ping_socket], [], [], time_left)
        how_long_in_select = (time.time() - started_select)
        if ready[0] == []:
            return -1

        time_received = time.time()
        rec_packet, addr = ping_socket.recvfrom(1024)
        icmp_header = rec_packet[20:28]
        type, code, checksum, packet_ID, sequence = struct.unpack("!BBHHH", icmp_header)

        if packet_ID == ID:
            bytes_In_double = struct.calcsize("d")
            time_sent = struct.unpack("d", rec_packet[28:28 + bytes_In_double])[0]
            return time_received - time_sent

        time_left = time_left - how_long_in_select
        if time_left <= 0:
            return -1

# Function to ping a host
def do_ping(host, timeout=1, count=4):
    try:
        my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
    except socket.error as e:
        print(f"Socket could not be created. Error: {e}")
        sys.exit()

    ID = os.getpid() & 0xFFFF

    for i in range(count):
        send_ping_request(my_socket, host, ID)
        delay = receive_ping_response(my_socket, ID, timeout)
        if delay == -1:
            print(f"Request timed out for {host}")
        else:
            print(f"Received ping response from {host} in {delay} seconds")

    my_socket.close()

# Example usage
if __name__ == '__main__':
    do_ping("www.google.com")
