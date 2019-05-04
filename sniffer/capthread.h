#ifndef CAPTHREAD_H
#define CAPTHREAD_H
#include <QThread>
#include <QMutex>
#define WPCAP
#define HAVE_REMOTE
#include <pcap.h>
#include <remote-ext.h>
#include <winsock.h>
#include <protocol.h>
class CapThread : public QThread
{
    Q_OBJECT
public:
    CapThread(pcap_t *_adhandle, pktCount *_npacket, datapktVec &_dataPktLink, dataVec &_dataCharLink);
    void stop();
protected:
    void run();
private:
    QMutex mlock;
    volatile bool isStopped;
    pcap_t *adhandle;
    pktCount *npacket;
    datapktVec &dataPktLink;
    dataVec &dataCharLink;
signals:
    void updateCapInfo(QString time, QString srcMac, QString destMac, QString len, QString protoType, QString srcIP, QString dstIP);
};

#endif // CAPTHREAD_H
