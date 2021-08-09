#!/usr/bin/env python
#  coding = unf-8

import configparser
import socket
import time
import re
import struct
import random
import argparse


def dns_codec(domain, flags=0x0120, RRs=(1, 0, 0, 0), dns_type=1, dns_class=1, trans_type='UDP'):
    '''''
    hostname：解析的域名
    flags：标志位
    RRS：实体数目
    dns_type:type
    dns_class:class
    '''

    packed_data = ()
    #随机获取一个请求包ID
    transaction_id = random.randint(1, 30000)
    packed_data += (transaction_id,)

    #DNS数据包标志位
    packed_data += (flags,)

    #DNS实体数目
    packed_data += RRs

    #分离域名,分解为长度加域名段的格式，并在结尾添加一个0作为结束标志位
    hoststr = ''.join(chr(len(x)) + x for x in domain.split('.'))
    packed_data += (hoststr.encode(), 0)

    #指定type和CLASS
    packed_data += (dns_type, dns_class)

    #指定数据包的编码格式并初始化包装的数据
    host_len = str(len(hoststr))
    packed = struct.Struct('!6H'+host_len+'sB2H')
    data = packed.pack(*packed_data)
    if trans_type.upper() == 'TCP':
        data = struct.pack("!H", len(data)) + data
    return data


def dns_sendmsg(domain, host, port, flags, RRs, dns_type, dns_class, trans_type):


    # IP类型
    address_family = {True: socket.AF_INET6, False: socket.AF_INET}[':' in host]
    # 传输类型
    socket_type = {True: socket.SOCK_STREAM, False: socket.SOCK_DGRAM}['TCP' == trans_type.upper()]

    try:
        sock = socket.socket(address_family, socket_type)
    except socket.error as e:
        print('create socket return error. errno = ', e.arge[0], 'errmsg = ', e.args[1])

        # 连接服务器并发送消息
    try:
        # 连接服务端
        sock.connect((host, port))

        for i in range(1,3):

            # 发送消息
            sock.sendall(dns_codec(domain, flags=flags, RRs=RRs, dns_type=dns_type, dns_class=dns_class, trans_type=trans_type))
            print("sent successful")
            i=i+1

    except socket.error as e:
        print('connect server failed. errno = %d, errmsg = %s' % (e.args[0], e.args[1]))
    time.sleep(1)
    sock.close()

def parse_get_opt():
    parser = argparse.ArgumentParser()

    #可选参数
    parser.add_argument('domain',
                        help="指定访问的域名")
    parser.add_argument('host', type=str,
                        help="指定服务器IP")
    parser.add_argument('-f', type=int, default=0x0120,
                        help="指定标志位，默认值为0x0120")
    parser.add_argument('-r', type=tuple, default=(1, 0, 0, 0),
                        help="指定各实体的数目，默认为1000")
    parser.add_argument('-t', type=int, default=1,
                        help="指定请求的记录类型，默认为1（A记录）")
    parser.add_argument('-c', type=int, default=1,
                        help="指定请求的class，默认为1（IN）")
    parser.add_argument('-p', type=int, default=53,
                        help="指定访问的服务器的端口，默认为53")
    parser.add_argument('-tt', type=str, default='UDP',
                        help="指定传输类型，默认为UDP")


    args = parser.parse_args()


    #将元组中的字符转换成int型，便于后面转换成结构体
    r_tmp = args.r
    args.r = ()
    for count in r_tmp:
        args.r += (int(count),)

    return args

if __name__ == '__main__':
    args = parse_get_opt()
    dns_sendmsg(domain=args.domain, host=args.host, port=args.p, flags=args.f, RRs=args.r, dns_type=args.t, dns_class=args.c, trans_type=args.tt)
