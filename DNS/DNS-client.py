#!/usr/bin/python3
# -*- coding:utf-8 -*-

import os
import socket
import struct
import random
import time

tcp_dns = 0
edns_payload = 0
server_addr = ("123.1.1.90", 53)

'''
struct.pack() 
!£ºÍøÂç×Ö½ÚÐò
B: 1bit
H: 2bit
L: 4bit
Q: 8bit
'''

def generate_ecs_ipv4(ip):
    # code + length + family + source_mask + scope_mask + client_subnet
    ecs = struct.pack("!HHHBBL", 8, 8, 1, 32, 0, ip) 
    return ecs

def build_dns_request(query_name):
    bufsize = 4096
    #transaction_id = random.randint(40000,50000)
    transaction_id = random.randint(20000,30000)

    # QR + opcode + AA + TC + RD
    flag_high = 0
    flag_high |= 0x01  # RD
    # RA + Z + RCODE 
    flag_low  = 0 
    # id + flag
    question = struct.pack("!HBB", transaction_id, flag_high, flag_low)
    # cnt
    if edns_payload:
        question += struct.pack("!HHHH", 1, 0, 0, 1)
    else:
        question += struct.pack("!HHHH", 1, 0, 0, 0)

    # question rr name
    qname = query_name
    for ele in qname.split("."):
        question += struct.pack("!B", len(ele)) + ele.encode()
    question += struct.pack("!B", 0)
    # question rr type class
    question += struct.pack("!HH", 1, 1)
    # EDNS name[0], type[41], class[payload:1323], ttl:0, rdlen, rdata
    if edns_payload:
        if not bufsize:
            bufsize = 1323
        ecs1 = generate_ecs_ipv4(100)
        ecs2 = generate_ecs_ipv4(111)
        question += struct.pack("!BHHLH", 0, 41, bufsize, 0, len(ecs1)+len(ecs2))  #ednsÍ·
        question += ecs1
        question += ecs2
    # tcp head
    if tcp_dns:
        question = struct.pack("!H", len(question)) + question
    return question

def create_socket(server_addr):
    if tcp_dns:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(server_addr)
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)
    return sock

def send_data(sock, data, server):
    if tcp_dns:
        sock.send(data)
    else:
        sock.sendto(data, server)

def recv_data(sock):
    if tcp_dns:
        reply = sock.recv(10240)
    else:
        reply, _ = sock.recvfrom(10240)
    return reply
        

def main1():
    qname = ["cname.lill.com", "www.lill.com", "taga.tagb.lill.com", "bind1.lill.com", "www.lill.com", "bind1.lill.com", "cname.lill.com", "taga.tagb.lill.com"]
    client_socket = create_socket(server_addr)
    for i in range(0, len(qname)):
        query = build_dns_request(qname[i])
        print("query {}:\n {}\n".format(i, query))
        reply = None
        try:
            # send query
            send_data(client_socket, query, server_addr)
            # wait reply
            reply = recv_data(client_socket)
        except socket.timeout:
            print("socket.timeout\n")
        print("response:\n{}\n".format(reply))
    time.sleep(5)
    client_socket.close()

def main2():
    sock = create_socket(server_addr)
    query = build_dns_request("www.lill.com")
    i = 0
    while i < len(query):
        print("send query")
        send_data(sock, query[i:i+10], server_addr)
        time.sleep(0.2)
        i = i + 10
    print("send query ok\nlen: {}\nquery: {}".format(len(query), query))
    reply = recv_data(sock)
    print("recv reply\nlen: {}\nreply: {}".format(len(reply), reply))
    #time.sleep(1)
    sock.close()


def main3():
    client = create_socket(server_addr)
    qname = ["www.lill.com", "www.uaaanreach.com", "www.lill.com"]
    for i in range(0, len(qname)):
        query = build_dns_request(qname[i])
        print("query {}: {}".format(i, query))
        reply = None
        try:
            send_data(client, query, server_addr)
            reply = recv_data(client)
        except socket.timeout:
            print("socket.timeout")
        print("response:\n{}\n".format(reply))
    time.sleep(2)
    client.close()

def main4():
    client = create_socket(server_addr)
    qname = ["www.lill.com", "www.lillerr.com", "bind1.lill.com"]
    for i in range(0, len(qname)):
        query = build_dns_request(qname[i])
        print("query {}: {}".format(i, query))
        send_data(client, query, server_addr)
    reply = recv_data(client)
    print("response:\n{}\n".format(reply))
    time.sleep(2)
    client.close()

def main5():
    qname = ["cname.lill.com", "www.lill.com", "taga.tagb.lill.com", "multi.lill.com"]
    client_socket = create_socket(server_addr)
    querys = b''
    for i in range(0, len(qname)):
        query = build_dns_request(qname[i])
        print("query {}:\n {}\n".format(i, query))
        querys += query
    # send query
    send_data(client_socket, querys, server_addr)
    # reply
    reply = recv_data(client_socket)
    print("response:\n{}\n".format(reply))
    time.sleep(5)
    client_socket.close()

def main6():
    client_socket = create_socket(server_addr)
    for i in range(0, 100):
        send_data(client_socket, build_dns_request("www.lill.com"), server_addr)
        recv_data(client_socket)
        print("ok ", i)


if __name__ == "__main__":
    #main1()
    #main2()
    #main3()
    #main4()
    #main5()
    main6()

