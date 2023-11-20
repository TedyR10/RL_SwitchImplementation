**Theodor-Ioan Rolea**
**333CA**

## Switch Implementation

### Overview:

* The goal of this project is to implement a basic switch. The switch operates at Layer 2 of the OSI model and uses the IEEE 802.1Q VLAN protocol for virtual LAN tagging. The switch is designed to forward Ethernet frames based on MAC addresses and VLAN information.

### How the program works:

* **In depth comments throughout the code**
* As the switch starts, parse the switch priority and interface tuples (tuple of interface_name & vlan id) from the configuration file. Then, initialize the VLAN_Table, assigning every interface a VLAN from the tuple (-2 for trunks for create_vlan_tag function). Initialize the root_bridge_id, own_bridge_id, root_path_cost and port_status. A separate thread will send BPDUs every second if the current switch is the root_bridge for the STP protocol.

* When a packet is received, check if it is a BPDU (by checking the packet type <<99, set randomly, just to check for BPDUs>>), case which we process the BPDU. Else, forward the packet accordingly. If the received packet came from an access interface and its vlan_id is -1, update its vlan_id from the VLAN_Table and tag it.

* A MAC_Table will store the interface and vlan_id for a given MAC. Check if the destination MAC is in the MAC_Table, case which we forward the packet accordingly, making sure to untag the packet if we send it to an access interface. Else, broadcast.

### About implementation:

* The logic was implemented using the pseudocodes given by the RL team.

### Other comments:

* Because this is an implementation of a simplified version of the STP protocol, the interfaces are not listening and blocking properly all the time, leading to BLOCKING - BLOCKING on the same interface between 2 switches. More conditions should be added to check for the switch's ID to determine which port should be BLOCKING and which port should be LISTENING.

### Resources:

* https://ocw.cs.pub.ro/courses/rl/teme/tema1_sw - for pseudocodes