#!/usr/bin/env python
#  coding = unf-8

import configparser
import socket
import time
import string
import os
import re
import struct
import random


def dns_codec(hostname):
    '''''
    Function:请求消息编码
    Input：hostname：主机名，如www.baidu.com
    Output: 编码后的字节流
    author: socrates
    date:2012-12-14
    '''

    index = os.urandom(2)
    hoststr = ''.join(chr(len(x)) + x for x in hostname.split('.'))
    print(index)
    transaction_id = random.randint(20000, 30000)
    flags = 0x0120
    RRs = (1, 0, 0, 1)
    # data = str(index) + str(flags) + RRs +hoststr+'\x00\x00\x01\x00\x01'

    data = struct.pack('!6H9sB2H', transaction_id, flags, 1, 0, 0, 0, hoststr.encode(), 0, 1, 1)
    print(data)
    return data


def dns_decode(in_sock):
    '''''
    Function:响应消息解码
    Input：in_sock：接收消息的socket
    Output:解码后的内容
    author: socrates
    date:2012-12-14
    '''
    rfile = in_sock.makefile('rb')
    size = struct.unpack('!H', rfile.read(2))[0]
    data = rfile.read(size)
    iplist = re.findall('\xC0.\x00\x01\x00\x01.{6}(.{4})', data)
    return ['.'.join(str(ord(x)) for x in s) for s in iplist]


def dns_sendmsg():
    '''''
    Function:通过socket发送DNS查询消息
    Input：None
    Output:None
    author: socrates
    date:2012-12-14
    '''
    ens_client_config = configparser.ConfigParser()

    # 读取配置文件
    try:
        ens_client_config.read('ens_client_config.ini')
    except configparser.Error:
        print('read ens_client_config.ini failed.')
        # 获取需要的信息
    server_ip_1 = ens_client_config.get("server_info", "ip_1")
    server_port_1 = ens_client_config.get("server_info", "port_1")
    sockettype_1 = ens_client_config.get("server_info", "sockettype_1")
    heartbeat_1 = ens_client_config.get("server_info", "heartbeat_1")
    msg_1 = ens_client_config.get("server_info", "msg_1")

    # IP类型
    address_family = {True: socket.AF_INET6, False: socket.AF_INET}[':' in server_ip_1]
    # 传输类型
    socket_type = {True: socket.SOCK_STREAM, False: socket.SOCK_DGRAM}['TCP' == sockettype_1.upper()]

    try:
        sock = socket.socket(address_family, socket_type)
    except socket.error as e:
        print('create socket return error. errno = ', e.arge[0], 'errmsg = ', e.args[1])

        # 连接服务器并发送消息
    try:
        # 连接服务端
        sock.connect((server_ip_1, int(server_port_1)))

        while True:
            # 发送频率
            time.sleep(int(heartbeat_1))

            # 发送消息
            sock.sendall(dns_codec(msg_1))

            # 接收并打印消息
            # print(dns_decode(sock))
            break

    except socket.error as e:
        print('connect server failed. errno = %d, errmsg = %s' % (e.args[0], e.args[1]))

    sock.close()


if __name__ == '__main__':
    dns_sendmsg()
