#!/usr/bin/env python
#  coding = unf-8

import configparser
import socket
import time
import re
import struct
import random
import argparse


def dns_codec(hostname, flags = 0x0120, RRs = (1, 0, 0, 0), dns_type = 1, dns_class = 1):
    '''''
    hostname：解析的域名
    flags：标志位
    RRS：实体数目
    dns_type:type
    dns_class:class
    '''

    print("flags:",flags)
    print("RRs:",RRs)
    print("type:", dns_type)
    print("class:", dns_class)
    packed_data = ()
    #随机获取一个请求包ID
    transaction_id = random.randint(1, 30000)
    packed_data += (transaction_id,)

    #DNS数据包标志位
    #flags = 0x0120
    packed_data += (flags,)

    #DNS实体数目
    #RRs = (1, 0, 0, 0)
    packed_data += RRs

    #分离域名,分解为长度加域名段的格式，并在结尾添加一个0作为结束标志位
    hoststr = ''.join(chr(len(x)) + x for x in hostname.split('.'))
    packed_data += (hoststr.encode(), 0)

    #指定type和CLASS
    #dns_type = 1
    #dns_class = 1
    packed_data += (dns_type, dns_class)
    print(packed_data)
    print(type(packed_data))

    #指定数据包的编码格式并初始化包装的数据
    host_len = str(len(hoststr))
    print(host_len)
    packed = struct.Struct('!6H'+host_len+'sB2H')
    data = packed.pack(*packed_data)
    print(data)
    return data


def dns_decode(in_sock):
    '''''

    '''
    rfile = in_sock.makefile('rb')
    size = struct.unpack('!H', rfile.read(2))[0]
    data = rfile.read(size)
    iplist = re.findall('\xC0.\x00\x01\x00\x01.{6}(.{4})', data)
    return ['.'.join(str(ord(x)) for x in s) for s in iplist]


def dns_sendmsg(host, flags, RRs, dns_type, dns_class):
    '''''

    '''
    ens_client_config = configparser.ConfigParser()
    print("send_RRs:",RRs)
    print(type(RRs))
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
            sock.sendall(dns_codec(host, flags=flags, RRs=RRs, dns_type=dns_type, dns_class=dns_class))

            # 接收并打印消息
            # print(dns_decode(sock))
            break

    except socket.error as e:
        print('connect server failed. errno = %d, errmsg = %s' % (e.args[0], e.args[1]))

    sock.close()

def parse_get_opt():
    parser = argparse.ArgumentParser()

    #可选参数
    parser.add_argument('host',type=tuple,
                        help="host")
    parser.add_argument('-f', type=int, default=0x0120,
                        help="input dns type")
    parser.add_argument('-r', type=tuple, default=(1, 0, 0, 0),
                        help="input dns type")
    parser.add_argument('-t', type=int, default=1,
                        help="input dns type")
    parser.add_argument('-c', type=int, default=1,
                        help="input dns type")
    args = parser.parse_args()

    print("args.host:", args.host)
    for host in args.host:
        print("hsot:",host)

    exit(0)

    #将元组中的字符转换成int型，便于后面转换成结构体
    r_tmp = args.r
    args.r = ()
    for count in r_tmp:
        args.r += (int(count),)

    return args

if __name__ == '__main__':
    args = parse_get_opt()
    print("get_RRs:",args.r)
    print("type:",type(args.r))
    dns_sendmsg(host=args.host, flags=args.f, RRs=args.r, dns_type=args.t, dns_class=args.c)
