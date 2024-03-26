import socket
import sys
import time
import os
import glob
import traceback
import threading


# Helper Functions

# The purpose of this function is to set up a socket connection.
def create_socket(host, port):
    # 1. Create a socket.
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # 2. Try connecting the socket to the host and port.
    try:
       soc.connect((host, port))
    except:
        print("Connection Error to", port)
        sys.exit()
    # 3. Return the connected socket.
    return soc


# The purpose of this function is to read in a CSV file.
def read_csv(path):
    # 1. Open the file for reading.
    table_file = open(path, "r")
    # 2. Store each line.
    table = table_file.readlines()
    # 3. Create an empty list to store each processed row.
    table_list = []
    # 4. For each line in the file:
    for line in table:
        # 5. split it by the delimiter,
        elements = line.strip().split(',')
        # 6. remove any leading or trailing spaces in each element, and
        elements = [element.strip() for element in elements]
        # 7. append the resulting list to table_list.
        table_list.append(elements)
    # 8. Close the file and return table_list.
    table_file.close()
    return table_list


# The purpose of this function is to find the default port
# when no match is found in the forwarding table for a packet's destination IP.
# table format: Destination, Netmask, Interface
def find_default_gateway(table):
    # 1. Traverse the table, row by row,
    for row in table:
        # 2. and if the network destination of that row matches 0.0.0.0,
        if row[0] == '0.0.0.0':
            # 3. then return the interface of that row.
            return row[3]

# The purpose of this function is to generate a forwarding table that includes the IP range for a given interface.
# In other words, this table will help the router answer the question:
# Given this packet's destination IP, which interface (i.e., port) should I send it out on?
def generate_forwarding_table_with_range(table):
    # 1. Create an empty list to store the new forwarding table.
    new_table = []
    # 2. Traverse the old forwarding table, row by row,
    for row in table:
        # 3. and process each network destination other than 0.0.0.0
        # (0.0.0.0 is only useful for finding the default port).
        if row[0] != '0.0.0.0':
            # 4. Store the network destination and netmask.
            network_dst_string = row[0]
            netmask_string = row[1]
            # 5. Convert both strings into their binary representations.
            network_dst_bin = ip_to_bin(network_dst_string)
            netmask_bin = ip_to_bin(netmask_string)
            # 6. Find the IP range.
            ip_range = find_ip_range(network_dst_bin, netmask_bin)
            # 7. Build the new row.
            new_row = [network_dst_string, netmask_string, ip_range[0], ip_range[1], row[3]]
            # 8. Append the new row to new_table.
            new_table.append(new_row)
    # 9. Return new_table.
    return new_table


# The purpose of this function is to convert a string IP to its binary representation.
def ip_to_bin(ip):
    # Split the IP into octets.
    ip_octets = ip.split('.')
    # Create an empty string to store each binary octet.
    ip_bin_string = ""
    # Traverse the IP, octet by octet,
    for octet in ip_octets:
        # and convert the octet to an int,
        int_octet = int(octet)
        # convert the decimal int to binary,
        bin_octet = bin(int_octet)
        # convert the binary to string and remove the "0b" at the beginning of the string,
        bin_octet_string = str(bin_octet)[2:]
        # while the sting representation of the binary is not 8 chars long,
        # then add 0s to the beginning of the string until it is 8 chars long
        # (needs to be an octet because we're working with IP addresses).
        while len(bin_octet_string) < 8:
            bin_octet_string = '0' + bin_octet_string
        # Finally, append the octet to ip_bin_string.
        ip_bin_string += bin_octet_string
    # Once the entire string version of the binary IP is created, convert it into an actual binary int.
    ip_int = int(ip_bin_string, 2)
    # 10. Return the binary representation of this int.
    return bin(ip_int)


# The purpose of this function is to find the range of IPs inside a given a destination IP address/subnet mask pair.
def find_ip_range(network_dst, netmask):
    # Perform a bitwise AND on the network destination and netmask
    # et the minimum IP address in the range.
    bitwise_and = int(network_dst, 2) & int(netmask, 2)
    # Perform a bitwise NOT on the netmask
    # to get the number of total IPs in this range.
    # Because the built-in bitwise NOT or compliment operator (~) works with signed ints,
    # we need to create our own bitwise NOT operator for our unsigned int (a netmask).
    compliment = bit_not(netmask)
    min_ip = bitwise_and
    # Add the total number of IPs to the minimum IP
    # to get the maximum IP address in the range.
    max_ip = min_ip + compliment
    # Return a list containing the minimum and maximum IP in the range.
    return [min_ip, max_ip]


# The purpose of this function is to perform a bitwise NOT on an unsigned integer.
def bit_not(n, numbits=32):
    n = int(n, 2)
    return (1 << numbits) - 1 - n


# The purpose of this function is to receive and process an incoming packet.
def receive_packet(connection, max_buffer_size):
    # Receive the packet from the socket.
    received_packet = connection.recv(max_buffer_size).decode("utf-8")
    print(f'received_packet= {received_packet}')
    # If the packet size is larger than the max_buffer_size, print a debugging message
    packet_size = sys.getsizeof(received_packet)
    if packet_size > max_buffer_size:
        print("The packet size is greater than expected", packet_size)
    # Decode the packet and strip any trailing whitespace.
    decoded_packet = received_packet.strip() 
    if not decoded_packet or decoded_packet is None:
        return
    # Add comma back to output
    # 3. Append the packet to received_by_router_2.txt.
    print("received packet", decoded_packet)
    write_to_file('output/received_by_router_3.txt', decoded_packet)
    # 4. Split the packet by the delimiter.
    packet = decoded_packet.split(',')
    print(f'packet: {packet}')
    # 5. Return the list representation of the packet.
    return packet


# The purpose of this function is to write packets/payload to file.
def write_to_file(path, packet_to_write, send_to_router=None):
    # 1. Open the output file for appending.
    out_file = open(path, "a")
    # 2. If this router is not sending, then just append the packet to the output file.
    if send_to_router is None:
        out_file.write(packet_to_write + "\n")
    # 3. Else if this router is sending, then append the intended recipient, along with the packet, to the output file.
    else:
        out_file.write(packet_to_write + " " + "to Router " + send_to_router + "\n")
    # 4. Close the output file.
    out_file.close()


def start_server(port, forwarding_table_with_range, default_gateway_port):
    host = '127.0.0.1'
  
    # Create a socket
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Bind the socket to the appropriate host and port
    try:
        soc.bind((host, port))
    except:
        print(f"Bind failed on port {port}. Error: {str(sys.exc_info())}")
        sys.exit()

    # Set the socket to listen
    soc.listen(5)
    print(f"Socket now listening on port {port}")

    try:
        while True:
            # Accept the connection
            connection, address = soc.accept()
            ip, port = str(address[0]), str(address[1])
            print(f"Connected with {ip}:{port}")

            # Start a new thread for receiving and processing the incoming packets
            try:
                threading.Thread(target=processing_thread, args=(connection, ip, port, forwarding_table_with_range, default_gateway_port)).start()
            except:
                print("Thread did not start.")
                traceback.print_exc()
    except KeyboardInterrupt:
        print("Server interrupted. Closing.")
    finally:
        soc.close()

def processing_thread(connection, ip, port, forwarding_table_with_range, default_gateway_port, max_buffer_size=5120):
    # Router 3 only need to receive packets 
    try:
        while True:
            # Receive the incoming packet, process it, and store its list representation
            packet = receive_packet(connection, max_buffer_size)

            # If the packet is empty, break out of the processing loop
            if packet is None or not packet:
                print("No more packets. Exiting processing loop.")
                break

            # Store the source IP, destination IP, payload, and TTL
            sourceIP, destinationIP, payload, ttl = packet

            # Decrement the TTL by 1 and construct a new packet with the new TTL
            new_packet = f"{sourceIP},{destinationIP},{payload},{ttl}"

            # Convert the destination IP into an integer for comparison purposes
            destinationIP_bin = ip_to_bin(destinationIP)
            destinationIP_int = int(destinationIP_bin, 2)

            # Find the appropriate sending port to forward this new packet to
            send_to_router = None
            for row in forwarding_table_with_range:
                min_ip = row[2]
                max_ip = row[3]
                if min_ip <= destinationIP_int <= max_ip:
                    send_to_router = row[4]
                    break

            # If no port is found, then set the sending port to the default port
            if send_to_router is None:
                send_to_router = default_gateway_port

            # Send the new packet to the appropriate port
            if int(ttl) < 0 or int(ttl) == 0:
                print("DISCARD:", new_packet)
                write_to_file('output/discarded_by_router_3.txt', new_packet)
            elif send_to_router == default_gateway_port or send_to_router == '127.0.0.1':
                print("OUT:", payload)
                write_to_file('output/out_router_3.txt', payload)
        sys.exit()
    except OSError as e:
        print(f"Error in processing_thread: {e}")
    finally:
        connection.close()

# Main Program 
# Remove any output files in the output directory
files = glob.glob('./output/*')
for f in files:
    os.remove(f)

# Read in and store the forwarding table
forwarding_table = read_csv('input/router_3_table.csv')

# # Store the default gateway port
default_gateway_port = find_default_gateway(forwarding_table)

# # Generate a new forwarding table that includes the IP ranges for matching against destination IPS
forwarding_table_with_range = generate_forwarding_table_with_range(forwarding_table)

# Start the server for Router 3 on port 8003
# Listen to port 8003 to get packets from Router 2
thread_8003 =threading.Thread(target=start_server, args=(8003, forwarding_table_with_range, default_gateway_port))
thread_8003.start()

