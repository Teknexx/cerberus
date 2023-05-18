#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from scapy.all import *
from datetime import datetime
from hashlib import sha256
from requests import get
import signal


class TimeoutError(Exception):
    pass


def raise_timeout(signum, frame):
    raise TimeoutError()


def sending_packet(hostname, port):
    # Open and close a port
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((hostname, int(port)))
    s.close()


def sending_packet_with_pass(destination_ip, source_ip, port, pass_string):

    secure_pass_string = authentication_string(pass_string, port)

    # Packet creation
    scapy_packet = IP(src=source_ip, dst=destination_ip) / TCP(dport=port) / Raw(load=secure_pass_string)

    # Packet sending without writing output
    send(scapy_packet, verbose=False)


def authentication_string(password, port):
    # Get the timestamp for the actual 10 seconds
    timestamp = int(datetime.now().timestamp() // 10)

    # Concatenation of the timestamp, the password and the port
    secure_string = str(timestamp) + ":" + str(password) + ":" + str(port)

    # Hash  SHA-256
    sha256_hash = sha256(secure_string.encode()).hexdigest()

    return sha256_hash


def knocking(hostname, port_to_open, ports_list):
    # Adding the port to open to port list
    ports_list.insert(0, port_to_open)

    for port in ports_list:
        # Start a 500ms timer, and if the nothing comes in response, a TimeoutError is raised
        signal.signal(signal.SIGALRM, raise_timeout)
        signal.setitimer(signal.ITIMER_REAL, 0.5)

        # Knock on the port
        try:
            sending_packet(hostname, port)
            signal.setitimer(signal.ITIMER_REAL, 0)
            print("Connected to port " + str(port) + " on " + hostname)

        # If RST packet is received (due to firewall on REJECT policy)
        except ConnectionRefusedError:
            print("Port " + str(port) + " open on " + hostname)

        # If nothing is received (due to firewall on DROP policy)
        except TimeoutError:
            print("DROPPED on port " + str(port) + " on " + hostname + " (or host isn't up)")

        # We reset the timer to don't raise TimeoutError
        signal.setitimer(signal.ITIMER_REAL, 0)


def knocking_with_pass(hostname, port_to_open, ports_list, pass_string):
    # Get the host public IP
    print("Collecting public IP...")
    source_ip = get('https://api.ipify.org').content.decode('utf8')
    print("Collected !")

    # Adding the port to open to port list
    ports_list.insert(0, port_to_open)

    for port in ports_list:
        # Knock on the port
        sending_packet_with_pass(hostname, source_ip, port, pass_string)
        print("Packet with pass sent to port " + str(port) + " on " + hostname)


def help():
    print(
"""          _____        __                  
         / ___/__ ____/ /  ___ ______ _____
        / /__/ -_) __/ _ \/ -_) __/ // (_-<
        \___/\__/_/ /_.__/\__/_/  \_,_/___/
                                           by TekneX

        This file should not be executed directly.
   Use this file as a module like the following example:

Into Python script:
    import cerberus_client as crb
    crb.knocking("127.0.0.1", 8080, [1111, 2222, 3333, 4444, 5555])
    crb.knocking_with_pass("45.125.76.98", 22, [123, 456], "P@ssword123") # Need root privileges !

Format:
    crb.knocking("DestinationIP", Destination_Port, [Port_list])
    crb.knocking_with_pass("DestinationIP", Destination_Port, [Port_list], "Password") # Need root privileges !
""")


if __name__ == '__main__':
    help()
