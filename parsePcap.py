from __future__ import absolute_import, unicode_literals
#!/usr/bin/python
# -*- coding:utf-8 -*-
from scapy.all import *
import scapy_http.http as http

def HTTP_Pcap(http_header):
    try:
        if http_header["Host"]:
            if http_header.get('Method', 'POST'):
                if pkt.haslayer("Raw"):
                    print(http_header["Host"], http_header["Method"], http_header["Path"], pkt.getlayer(Raw).load)
                else:
                    print(http_header["Host"], http_header["Method"], http_header["Path"], http_header['Cookie'])

            elif http_header.get('Method', 'GET'):
                print(http_header["Host"], http_header["Method"], http_header["Path"], http_header["Params"], http_header['Cookie'])

            elif http_header.get('Method', 'DELETE'):
                print(p.getlayer(Raw).load)

            elif http_header.get('Method', 'PUT'):
                if pkt.haslayer("Raw"):
                    print(http_header["Host"], http_header["Method"], http_header["Path"], pkt.getlayer(Raw).load)
                else:
                    print(http_header["Host"], http_header["Method"], http_header["Path"], http_header['Cookies'])

            elif http_header.get('Method', 'TRACE'):
                print(http_header["Host"], http_header["Method"], http_header["Path"], http_header['Cookies'])

            elif http_header.get('Method', 'OPTIONS'):
                print(http_header["Host"], http_header["Method"], http_header["Path"], http_header['Cookie'])

            elif http_header.get('Method', 'HEAD'):
                print(http_header["Host"], http_header["Method"], http_header["Path"], http_header['Cookie'])
        else:
            pass
    except Exception as e:
        pass


def parsePcap(pkt):

    for p in pkt:
        try:
            if p.getlayer(Raw):
                a = str(p.getlayer(Raw).load)
                if 'Host' in a:

                    with open('requests.txt', 'w+') as f:
                        f.write(str(a))

                    with open("requests.txt", "r") as f:
                        data = f.readlines()
                        for line in data:
                            x = line.replace("\\r\\n", '\r\n')
                            x = x.replace("b\'", '')
                            with open('requests.txt', 'w+') as f:
                                f.write(x)

                        with open('requests.txt', "r") as f:
                            lines = f.read().splitlines()
                            for line in lines:
                                if 'HTTP/1.1' in line:
                                    print(line)
                                if 'Host' in line:
                                    print(line)
                                    print(lines[-1])
                                    if 'Cookie' in line:
                                        print(line)
                                        print('\r\n')
                                    else:
                                        print('\r\n')

            else:
                pass

        except Exception as e:
            pass

if __name__ == '__main__':

    path = '/Users/alewong/Desktop/QiAnXin/skyeye/pcap/L5'#读取文件夹路径
    items = os.listdir(path)

    for item in items:
        #print(item)
        if 'pcap' in item:
            pkts = rdpcap(path + '/' + item)
    #pkts = rdpcap('/Users/alewong/Desktop/test2.pcap') #只读取单个pcap
            for pkt in pkts:
                if pkt.haslayer(http.HTTPRequest):
                    http_header = pkt[http.HTTPRequest].fields
                    #pkt.show()
                    HTTP_Pcap(http_header)

                else:
                    if pkt.getlayer(Raw):
                        parsePcap(pkt)

                    else:
                        pass
