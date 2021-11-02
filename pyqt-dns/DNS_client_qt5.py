#!/usr/bin/env python
#  coding = unf-8

import configparser
import socket
import time
#import re
import struct
import random
import argparse
#from IPy import IP

class DNS_client(object):
        def dns_codec(self,domains, ecs, bufsize, flags=0x0120, RRs=(1, 0, 0, 0), dns_type=1, dns_class=1, trans_type='UDP'):
            '''''
            hostname：解析的域名
            flags：标志位
            RRS：实体数目
            dns_type:type
            dns_class:class
            '''
            #print("code"+domains)
            struct_format = '!6H'
            packed_data = ()
            #随机获取一个请求包ID
            transaction_id = random.randint(1, 30000)
            packed_data += (transaction_id,)

            #DNS数据包标志位
            packed_data += (flags,)

            #DNS实体数目
            packed_data += RRs


            #便利每个域名，再分离域名,分解为长度加域名段的格式，并在结尾添加一个0作为结束标志位；多个域名时bind服务器貌似不认，正常情况下只请求一个域名
            for domain in domains:
                hoststr = ''
                hoststr += hoststr.join(chr(len(x)) + x for x in domain.split('.'))
                packed_data += (hoststr.encode(), 0)
                # 指定type和CLASS
                packed_data += (dns_type, dns_class)
                struct_format += str(len(hoststr)) + 'sB2H'


            if RRs[3] >= 1:
                edns_name = 0
                edns_type = 41
                edns_payload = bufsize
                edns_Hb = 0
                edns_version = 0
                edns_z = 0
                packed_data += (edns_name, edns_type, edns_payload, edns_Hb, edns_version, edns_z)
                struct_format += 'B2H2BH'
                if ecs == None:
                    edns_data_length = 0
                    packed_data += (edns_data_length,)
                    struct_format += 'H'
                else:
                    # 分离ecs的IP和掩码
                    ecs_ip, ecs_mask = ecs.split('/')

                    #数据包中携带的ECS字节数与掩码有关，需要根据掩码改变最后的client subnet长度
                    data_ecs_len = int((int(ecs_mask)/8))

                    op_code = 8
                    sco_netmask = 0
                    ecs_ip_int = ()
                    if ':' in ecs_ip:
                        op_fam = 2
                        for ip in ecs_ip.split(':'):
                            if ip:
                                ecs_ip_int += (int(ip, 16),)
                            else :
                                ecs_ip0 = len(ecs_ip_int)
                        ecs_ip0_tuple = (0,)*(data_ecs_len-len(ecs_ip_int))
                        ecs_ip_int = ecs_ip_int[:ecs_ip0] + ecs_ip0_tuple + ecs_ip_int[ecs_ip0:]
                    else :
                        op_fam = 1
                        for ip in ecs_ip.split('.'):
                            ecs_ip_int += (int(ip),)

                    op_length = 4 + data_ecs_len
                    edns_data_length = 8 + data_ecs_len
                    ecs_ip_int = ecs_ip_int[:data_ecs_len]
                    if ':' in ecs:
                        struct_format += '4H2B' + str(len(ecs_ip_int)) + 'H'
                    else:
                        struct_format += '4H2B' + str(len(ecs_ip_int)) + 'B'
                    packed_data += (edns_data_length, op_code, op_length, op_fam, int(ecs_mask), sco_netmask, *ecs_ip_int)



            #指定数据包的编码格式并初始化包装的数据
            packed = struct.Struct(struct_format)
            data = packed.pack(*packed_data)

            if trans_type.upper() == 'TCP':
                    data = struct.pack("!H", len(data)) + data
            return data


        def dns_sendmsg(self,domains, host, port=53, flags=0x0120, RRs=(1, 0, 0, 0), dns_type=1, dns_class=1, trans_type="UDP", ecs=None, bufsize=None):

            #print("sendmsg"+domains)
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
                #for i in range(1,2):

                # 发送消息
                sock.sendall(self.dns_codec(domains, flags=flags, RRs=RRs, dns_type=dns_type, dns_class=dns_class, trans_type=trans_type, ecs=ecs, bufsize=bufsize))
                print("sent successful")
                    #i=i+1

            except socket.error as e:
                print('connect server failed. errno = %d, errmsg = %s' % (e.args[0], e.args[1]))
            time.sleep(1)
            sock.close()

        def parse_get_opt(self):
            parser = argparse.ArgumentParser()

            #可选参数
            parser.add_argument('domain', nargs='+',        #nargs=+ :允许输入多个值来对应一个参数，如果没有赋值则会报错
                                help="指定访问的域名")
            parser.add_argument('host', type=str,
                                help="指定服务器IP")
            parser.add_argument('-f', type=int, default=0x0120,
                                help="指定标志位，默认值为0x0120")
            parser.add_argument('-r', type=tuple,
                                help="指定各实体的数目，默认为1000")
            parser.add_argument('-t', type=int, default=1,
                                help="指定请求的记录类型，默认为1（A记录）")
            parser.add_argument('-c', type=int, default=1,
                                help="指定请求的class，默认为1（IN）")
            parser.add_argument('-p', type=int, default=53,
                                help="指定访问的服务器的端口，默认为53")
            parser.add_argument('-tt', type=str, default='UDP',
                                help="指定传输类型，默认为UDP")
            parser.add_argument('-edns', action='store_true',
                                help="请求携带EDNS")
            parser.add_argument('-ecs', type=str,
                                help="指定ECS")
            parser.add_argument('-bufsize', type=int, default=4096,
                                help="指定UDP payload size")


            args = parser.parse_args()

            #根据是否携带EDNS修改RRs值
            args.r = {True: (1, 0, 0, 1), False: (1, 0, 0, 0)}[(args.edns == True or args.ecs != None or args.bufsize) and args.r == None ]
            #将RRs元组中的字符转换成int型，便于后面转换成结构体
            r_tmp = args.r
            args.r = ()
            for count in r_tmp:
                args.r += (int(count),)

            return args

if __name__ == '__main__':
    dns_client = DNS_client()
    #args=dns_client.parse_get_opt()
    #args.dns_sendmsg(domains=args.domain, host=args.host, port=args.p, flags=args.f, RRs=args.r, dns_type=args.t, dns_class=args.c, trans_type=args.tt, ecs=args.ecs, bufsize=args.bufsize)
    dns_client.dns_sendmsg(domains=("zjy.com",), host="10.146.22.128")