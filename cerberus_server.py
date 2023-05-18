#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from scapy.all import *
from datetime import datetime
from hashlib import sha256
import os
import configparser
import sys


def start_message():
    # Timestamp Format
    timestamp_formatted = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f")

    # Create a log to tell the user that Cerberus started
    log = "{}{}  - {}".format("INI: ", timestamp_formatted, " Cerberus started listening")

    # Print in logs that Cerberus started
    print_log(log)


def whitelist_ip(ip, port):
    # Whitelist IP on specific port
    os.system("iptables -A INPUT -p tcp --dport " + str(port) + " -s " + str(ip) + " -j ACCEPT")

    # Timestamp Format
    timestamp_formatted = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f")

    # Create the log to inform the user that an IP is whitelisted
    log = "{}{}  - {}".format("WL : ", timestamp_formatted, str(ip) + " whitelisted on port " + str(port))

    # Print in logs that the ip is whitelisted
    print_log(log)


def listening(interface):
    # Log a start message
    start_message()

    # Create an array for packet entry
    ip_list = []

    # Only sniff TCP and inbound packet
    sniff(filter="inbound and tcp", iface=interface, prn=lambda packet: packet_reception(packet, ip_list))


def packet_reception(packet, ip_list):
    # Print the packet log in the terminal and in the log file
    print_packet_logs(packet)

    # Add the new entry at the end of the list
    ip_list.append({"ip": packet["IP"].src, "timestamp": packet.time, "port": packet["TCP"].dport})

    # Delete the first item if the list is too long
    if len(ip_list) >= 50:
        ip_list.pop(0)

    # If the last request ip isn't the last member of the port pass (to save time), we return
    if PORT_PASS[-1] != packet["TCP"].dport:
        return

    # Check for all the entries and check if there are more or equal entries than the port pass, if not, we return
    if sum(1 for item in ip_list if item["ip"] == packet["IP"].src) < len(PORT_PASS):
        return

    # Create variable for the actual index in the list
    index_port_pass = 0
    # Reverse the port list
    rev_port_pass = list(reversed(PORT_PASS))

    # Validation variable
    validated = False

    # Create a list to contain hash, to counter playback attacks
    hash_list = []

    # We check for each element in the IP list
    for item in list(reversed(ip_list)):

        # If the IP isn't the same IP of the last packet, we come back at the top of the for instruction
        if item["ip"] != packet["IP"].src:
            continue

        # If validated is True
        if validated:
            # We whitelist the IP
            whitelist_ip(item["ip"], item["port"])
            return

        # We check if the port is in the list, and we increment the index, else, we return
        if item["port"] == rev_port_pass[index_port_pass]:
            index_port_pass += 1
        else:
            return

        # If mode with password is enabled
        if MODE_PASS:
            try:
                # We put the data received in a new variable
                data_received = packet[Raw].load.decode('utf-8')

                # Check if data has 64 characters for SHA256
                if len(data_received) != 64:
                    return

                # If the hash is in the hash list
                if data_received in hash_list:
                    return
                # We add the hash in the list
                hash_list.append(hash_list)

                # If the hash received isn't the same as the calculated hash from the server
                if data_received != authentication_string_server(PASSWORD, packet["TCP"].dport, packet.time):
                    return
            except:
                return

        # If the index is the same as the length of the port pass, it means the port pass is correct
        if index_port_pass == len(PORT_PASS):

            # We check if the delta is more than the reject time
            if packet.time - item["timestamp"] <= REJECT_TIME:
                validated = True


def print_packet_logs(scapy_packet):
    # Timestamp formatting
    timestamp_formatted = datetime.fromtimestamp(scapy_packet.time).strftime("%Y-%m-%d %H:%M:%S.%f")

    # Summarized packet information with format :
    # Timestamp     Source_IP     Destination_Port     Data_If_Present

    try:
        # We create log without data
        summary_log = "{}{}{:>17}{:>9}".format("RCV: ", timestamp_formatted, scapy_packet["IP"].src, scapy_packet["TCP"].dport)
    except:
        return "Packet Err"

    try:
        # Add data if present
        if len(scapy_packet["Raw"].load.decode('utf-8')) == 64:
            summary_log = "{}       {}".format(summary_log, scapy_packet["Raw"].load.decode('utf-8'))
    except:
        summary_log = summary_log

    # Print summary into the logs file
    print_log(summary_log)

    # Return the summary of the log
    return summary_log


def print_log(log):
    # Print log in terminal
    print(log)

    # Print log in logs files
    with open(LOGS_FILE_PATH, "a+") as logs_file:
        logs_file.write(log + "\n")


def authentication_string_server(password, port, packet_timestamp):
    # Get the timestamp for the actual 10 seconds
    timestamp = int(packet_timestamp // 10)

    # Concatenation of the password and the salt
    secure_string = str(timestamp) + ":" + str(password) + ":" + str(port)

    # Hash1 : SHA-256
    sha256_hash = sha256(secure_string.encode()).hexdigest()

    return sha256_hash


if __name__ == '__main__':

    # If there is no argument
    if len(sys.argv) != 2:
        print("Usage : python3 server.py config.ini")
        exit(0)

    # Open the argument as config file
    config = configparser.ConfigParser()
    config.read(sys.argv[1])

    # Obtain values from the config file
    INTERFACE = str(config["GLOBAL"]["INTERFACE"])
    LOGS_FILE_PATH = str(config["GLOBAL"]["LOGS_FILE_PATH"])
    REJECT_TIME = int(config["GLOBAL"]["REJECT_TIME"])
    # Transform the port list (str) into a list of int
    PORT_PASS = [int(num) for num in config["PASS"]["PORT_PASS"].split(", ")]
    MODE_PASS = eval(config["PASS"]["MODE_PASS"])
    PASSWORD = str(config["PASS"]["PASSWORD"])

    # Start listening with Scapy
    listening(INTERFACE)

else:
    print("This program need to be directly opened")

