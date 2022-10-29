#!/usr/bin/env python3

import scapy.all as scapy
import argparse  # the argparse module allow us to get arguments from the user, parse them and use them on the code

# Network Scanner - Discover clients on network
# Algorithm Steps:
# [1] create arp request directed to broadcast MAC asking for IP
# [2] send packet and receive response
# [3] parse the response
# [4] print result


def get_arguments():  # the function get the argument from the user (using the argparse module)
    parser = argparse.ArgumentParser()  # creating an ArgumentParser object
    # creating the "--target" / "-t" arg option and help
    parser.add_argument("-t", "--target", dest="target", help="target network ip range")
    options = parser.parse_args()
    if not options.target:  # if no target network defined
        parser.error("[-] Please specify ip range to scan --help for more info.")
    return options  # if an interface was defined and a new MAC address was entered, return options


# the function create an arp request and send it to the broadcast MAC address, for all ips on the network
def scan(ip):
    # [1] create arp request directed to broadcast MAC asking for IP
    arp_request = scapy.ARP(pdst=ip)  # use ARP to ask who has target IP
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  # set destination MAC to broadcast MAC
    arp_request_broadcast = broadcast/arp_request  # combine the arp request with the broadcast to one packet
    # [2] send packet and receive response
    # scapy.srp - send/receive packet with custom ether part & capture only the first list into the answered_list var
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    # [3] parse the response

    clients_list = []  # creating an empy list
    for element in answered_list:
        client_dict = {"ip":element[1].psrc, "mac":element[1].hwsrc}  # creating a dict with the relevant data
        clients_list.append(client_dict)  # append the dict to the list of the clients
    return clients_list  # return the list of clients we found on the network


def print_result(result_list):
    print("IP\t\t\tMAC Address\n------------------------------------------------")
    for client in result_list:  # iterate  the result_list (clients)
        print(client["ip"] + "\t\t" + client["mac"])  # print the keys value's for each client


options = get_arguments()  # store the output of the get_arguments function in the options variable
scan_result = scan(options.target)   # capture the input from the scan function in scan_result
print_result(scan_result)  # send the scan_result to the print_result function