#ifndef ARPCHEATTOOL_H
#define ARPCHEATTOOL_H

#include <pcap.h>
#include "protocol.h"
#include "utilities.h"

class ArpCheatTool
{
public:
    ArpCheatTool(pcap_if_t *_dev);
    ~ArpCheatTool();
    bool isAble;
private:
    pcap_if_t *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *adhandle;
};

#endif // ARPCHEATTOOL_H
