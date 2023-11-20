#!/usr/bin/python3
# Copyright Theodor-Ioan Rolea 2023
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

root_bridge_id = -1

def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    #dest_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])
    dest_mac = data[0:6]
    src_mac = data[6:12]
    
    # Extract ethertype. Under 802.1Q, this may be the bytes from the VLAN TAG
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    # Check for VLAN tag (0x8100 in network byte order is b'\x81\x00')
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF  # extract the 12-bit VLAN ID
        ether_type = (data[16] << 8) + data[17]

    return dest_mac, src_mac, ether_type, vlan_id

def create_vlan_tag(vlan_id):
    # 0x8100 for the Ethertype for 802.1Q
    # vlan_id & 0x0FFF ensures that only the last 12 bits are used
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)

def initialize_switch(interfaces, switch_priority, VLAN_Table):
    # Initialize the switch from the config file
    global root_bridge_id
    # Define the port status for each interface
    port_status = {}
    for interface in interfaces:
        if (VLAN_Table[interface] == -2):
            # Initially, set all trunk ports to BLOCKING
            port_status[interface] = -1 #BLOCKING
        else:
            # And all access ports to LISTENING
            port_status[interface] = 1 #LISTENING

    own_bridge_id = switch_priority
    root_bridge_id = own_bridge_id
    root_path_cost = 0
    root_port = -1

    # As we initially are the root bridge, set all ports to LISTENING   
    if (own_bridge_id == root_bridge_id):
        for interface in interfaces:
            port_status[interface] = 1 #LISTENING

    return port_status, own_bridge_id, root_bridge_id, root_path_cost, root_port

def send_bdpu_every_sec(own_bridge_id, interfaces, VLAN_Table, port_status):
    global root_bridge_id
    while True:
        time.sleep(1)
        # Send BPDU on trunks every second if we are the root bridge
        if (own_bridge_id == root_bridge_id):
            for interface in interfaces:
                if (VLAN_Table[interface] == -2):
                    send_to_link(interface, create_bpdu(root_bridge_id, own_bridge_id, 0), 16)

def create_bpdu(root_bridge_id, sender_bridge_id, sender_path_cost):
    # Create a BPDU packet and assign a packet type of 99 to check for incoming bpdus
    bpdu = struct.pack('!I', 99) + struct.pack('!I', root_bridge_id) + struct.pack('!I', sender_bridge_id) + struct.pack('!I', sender_path_cost)
    return bpdu

def parse_bpdu(bpdu):
    # Parse the BPDU packet
    packet_type = int.from_bytes(bpdu[0:4], byteorder='big')
    root_bridge_id = int.from_bytes(bpdu[4:8], byteorder='big')
    sender_bridge_id = int.from_bytes(bpdu[8:12], byteorder='big')
    sender_path_cost = int.from_bytes(bpdu[12:16], byteorder='big')
    return packet_type, root_bridge_id, sender_bridge_id, sender_path_cost


def bpdu_receive(bpdu, own_bridge_id, root_path_cost, port_status, interfaces, root_port, receiving_interface, VLAN_Table):
    bpdu_packet_type, bpdu_root_bridge_id, bpdu_sender_bridge_id, bpdu_sender_path_cost = parse_bpdu(bpdu)
    global root_bridge_id
    # If the received BPDU is from a switch with lower root_bridge_id, update the root bridge
    if bpdu_root_bridge_id < root_bridge_id:
        # If the switch is the root bridge, set all trunk ports to BLOCKING
        if own_bridge_id == root_bridge_id:
            for interface in interfaces:
                if VLAN_Table[interface] == -2:
                    port_status[interface] = -1  # BLOCKING

        # Update root bridge
        root_bridge_id = bpdu_root_bridge_id
        # Update root path cost
        root_path_cost = bpdu_sender_path_cost + 10
        # Update root port
        root_port = receiving_interface

        # Set the root port to LISTENING
        if port_status[root_port] == -1:  # BLOCKING
            port_status[root_port] = 1  # LISTENING

        # Update and forward BPDU to all other trunk ports
        for interface in interfaces:
            if port_status[interface] == -2 and interface != receiving_interface:
                send_to_link(interface, create_bpdu(root_bridge_id, own_bridge_id, root_path_cost), 16)

    elif bpdu_root_bridge_id == root_bridge_id:
        # If the path to the root bridge is better than the current path, update the root path cost
        if receiving_interface == root_port and bpdu_sender_path_cost + 10 < root_path_cost:
            root_path_cost = bpdu_sender_path_cost + 10
        elif receiving_interface != root_port:
            # Check if the current switch is on the best path to the root bridge
            if bpdu_sender_path_cost > root_path_cost:
                # Check if the port is not the Designated Port for this segment
                if port_status[receiving_interface] != 1:
                    port_status[receiving_interface] = 1  # LISTENING

    elif bpdu_sender_bridge_id == own_bridge_id:
        # Set port state to BLOCKING
        port_status[receiving_interface] = -1  # BLOCKING
    else:
        pass

    if own_bridge_id == root_bridge_id:
        # For each port on the bridge, set port as DESIGNATED_PORT
        for interface in interfaces:
            if port_status[interface] != -1:
                port_status[interface] = 1  # LISTENING

    return port_status, root_bridge_id, root_path_cost, root_port

def parse_switch_config(file_name):
    # Parse the switch config file
    with open(file_name, 'r') as file:
        lines = file.readlines()

    switch_priority = int(lines[0].strip())

    # Create a tuple with the interface name and VLAN ID
    vlan_tuples = []
    for line in lines[1:]:
        parts = line.split()
        name = parts[0]
        if (parts[1] == "T"):
            # Trunk ports have a VLAN ID of -2
            vlan_id = -2
        else:
            vlan_id = parts[1]
        vlan_tuples.append((name, vlan_id))

    return switch_priority, vlan_tuples

def main():
    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]
    MAC_Table = {}
    VLAN_Table = {}

    file_name = f"./configs/switch{switch_id}.cfg"
    switch_priority, tuples = parse_switch_config(file_name)

    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)

    global root_bridge_id

    # Create a dictionary that maps interface names to VLAN IDs
    for i in range(len(tuples)):
        for j in interfaces:
            if tuples[i][0] == get_interface_name(j):
                if (tuples[i][1] == "T"):
                    vlan_id = -2
                else:
                    vlan_id = tuples[i][1]
                VLAN_Table[j] = vlan_id

    # Initialize switch 
    port_status, own_bridge_id, root_bridge_id, root_path_cost, root_port = initialize_switch(interfaces, switch_priority, VLAN_Table)
   
    print("# Starting switch with id {}".format(switch_id), flush=True)
    print("[INFO] Switch MAC", ':'.join(f'{b:02x}' for b in get_switch_mac()))

    # Create and start a new thread that deals with sending BPDU
    t = threading.Thread(target=send_bdpu_every_sec, args=(own_bridge_id, interfaces, VLAN_Table, port_status))
    t.start()

    # Printing interface names
    for i in interfaces:
        print(get_interface_name(i))

    while True:
        # Note that data is of type bytes([...]).
        # b1 = bytes([72, 101, 108, 108, 111])  # "Hello"
        # b2 = bytes([32, 87, 111, 114, 108, 100])  # " World"
        # b3 = b1[0:2] + b[3:4].
        interface, data, length = recv_from_any_link()

        # Check if the received packet is a BPDU
        if int.from_bytes(data[0:4], byteorder='big') == 99:
            port_status, root_bridge_id, root_path_cost, root_port = bpdu_receive(data, own_bridge_id, root_path_cost, port_status, interfaces, root_port, interface, VLAN_Table)
        else:
            # Else, process as a normal packet
            dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)

            # Print the MAC src and MAC dst in human readable format
            dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
            src_mac = ':'.join(f'{b:02x}' for b in src_mac)

            # Note. Adding a VLAN tag can be as easy as
            # tagged_frame = data[0:12] + create_vlan_tag(10) + data[12:]

            print(f'Destination MAC: {dest_mac}')
            print(f'Source MAC: {src_mac}')
            print(f'EtherType: {ethertype}')

            print("Received frame of size {} on interface {}".format(length, interface), flush=True)

            # Packet sent from host to switch
            if (vlan_id == -1):
                for i in range(len(tuples)):
                    # Change the vlan_id that came from the host to the correct
                    # vlan_id of the interface
                    if tuples[i][0] == get_interface_name(interface):
                        vlan_id = int(tuples[i][1])
                        # Add the vlan tag to the packet
                        data = data[0:12] + create_vlan_tag(vlan_id) + data[12:]
                        length += 4

            # Add the MAC address to the MAC table
            MAC_Table[src_mac] = {'port': interface, 'vlan': vlan_id}

            # If the destination MAC address is in the MAC table, forward the packet
            if (dest_mac != "ff:ff:ff:ff:ff:ff" and dest_mac in MAC_Table):
                # If the vlan to the destination MAC address is the same as 
                # the vlan of the interface, forward the packet with the vlan tag
                if (str(VLAN_Table[MAC_Table[dest_mac]['port']]) == str(vlan_id)):
                    data = data[0:12] + data[16:]
                    length -= 4
                    send_to_link(MAC_Table[dest_mac]['port'], data, length)
                # If the vlan to the destination MAC address is trunk,
                # forward the packet
                elif (VLAN_Table[MAC_Table[dest_mac]['port']] == -2 and port_status[MAC_Table[dest_mac]['port']] == 1):
                    send_to_link(MAC_Table[dest_mac]['port'], data, length)

            # If the destination MAC address is not in the MAC table, broadcast
            else:
                for i in interfaces:
                    # If the vlan of the interface is the same as the vlan of the
                    # packet, forward the packet without the vlan tag
                    if (i != interface and str(VLAN_Table[i]) == str(vlan_id)):
                        new_data = data[0:12] + data[16:]
                        new_length = length - 4
                        send_to_link(i, new_data, new_length)
                    # If the vlan of the interface is trunk, forward the packet
                    elif (i != interface and VLAN_Table[i] == -2 and port_status[i] == 1):
                        send_to_link(i, data, length)

if __name__ == "__main__":
    main()
