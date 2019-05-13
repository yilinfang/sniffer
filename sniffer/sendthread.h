#ifndef SENDTHREAD_H
#define SENDTHREAD_H

#include <QThread>
#include <QMutex>
#define WPCAP
#define HAVE_REMOTE
#include <pcap.h>
#include <remote-ext.h>
#include <winsock.h>
#include <protocol.h>
#include "arphead.h"

class SendThread : public QThread
{
    Q_OBJECT
public:
    SendThread(pcap_t *_adhandle, u_char *_currentMac, u_long _targetIp, u_char * _targetMac, u_long _gateIp, u_char *_gateMac);
    void stop();
protected:
    void run();
private:
    u_char *BuildArpPacket(u_char *srcMac, u_long fakeIP, u_char *targetMac, u_long targetIP);
    QMutex mlock;
    volatile bool isStopped;
    u_char *fakeTargetArpPkt;       //发送给目标主机的伪造arp数据包
    u_char *fakeGateArpPkt;         //发送给网关的伪造ARP数据包
    pcap_t *adhandle;
    u_char *currentMac;
    u_long targetIp;
    u_char *targetMac;
    u_long gateIp;
    u_char *gateMac;

signals:
    void sendLogMsg(QString msg);
};

#endif // SENDTHREAD_H
