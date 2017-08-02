# VPP_P4
A subset of VPP implemented in P4

The project aims to implement the features of VPP in P4. Initially the program here implements only a certain set of basic features.
IPV4 unicast features
1. Compares to check if the packet expected and the packet comming out are as expected. Also points out where they differed, if they are different.
2. Drops the packets if the forwarding detail is not found among the table entries.
3. Checks for the ttl of the packet in the header, and drops the packets with ttl = 1 or 0. 
4. Also checks for the difference in number of packets expected and the number of packets actually came out and tells the difference.
5. The P4 program is implemented such that it checks the table entries for MTU and drops the packets if the packet size is greater than the MTU. A number of test cases are checked for this, by constructing packets with Raw input appended.

The test cases implemented are in python and have the functionality to send and receive packets on different port numbers.
The sent packet and the received packet are checked to verify if the same packet sent, was received. Also the test case is written such that, the number of packets expected and the number of packets that actually came out are compared and accordingly the error is displayed. To analyze different cases functions are written, which can be called to test different packets.

Scapy is used to send and receive packets on the required virtual ethernet interface.

Simple switch is like a interface to connect to hardware. It obtains the json file and creates the necessary maps to execute the p4 program.

Steps to execute the test cases:

Traverse to the path where the python file is stored, here in VPP_P4 folder.
Type the following command:
sudo filename.py --json json_file_name_with_path_where_the_file_is_stored
sudo ./test_1.py --json /home/rucha/VPP_P4/demo1.p4_16.json
where
./test_1.py - name of the test file
--json - command whihc will execute the json file of the P4 prgram.
/home/rucha/VPP_P4/demo1.p4_16.json - json file name, along with the path where the file is stored.

This will run the simple switch, assign port numbers to veth interfaces and the simple switch remains running until the packets are received on the expcted ports.

If the above steps don't work, One can try with the following steps. 

1. Compile and execute the P4 program.

The P4 program is used from another git repository: https://github.com/jafingerhut/p4-guide. The P4 program updated to implement VPP's IPv4 unicast features is in the repository.
One needs to run the simple switch to assign ports to virtual ethernet addresses. 

Steps:
Open a new terminal

Traverse to the folder containing the p4 program you want to execute.
cd ~/p4/p4-guide/demo1

Execute the simple switch program now....
sudo simple_switch --log-console -i 0@veth2 -i 1@veth4 -i 2@veth6 -i 3@veth8 -i 4@veth10 -i 5@veth12 -i 6@veth14 -i 7@veth16 demo1.p4_16.json

Keep the simple switch running all the time as you implement the test cases.


2. Execute the .py file to send packets - test1

Open new terminal

Traverse to the folder containing the python test program.
cd ~/VPP_P4

To execute the .py file (run the program)
sudo ./test_1.py

This program when executed will flood the table with data required to enter the table first time. Also it has commands to send the packet over the needed port number. 
'sudo' is used to complie the file with root permissions. 

To see the packets being sent on particular veth interface, one can observe the tcp dump.
Enter the following commands on new terminals

Example: to check the packet flow on veth2
sudo tcpdump -e -n --number -v -i veth2

Example: to check the packet flow on veth6 
sudo tcpdump -e -n --number -v -i veth6


4. To check which processes are already running 
ps ax
This displays the processes still running along with their process IDs. 

To kill a process 
sudo kill PID
using sudo will force the process to terminate.




