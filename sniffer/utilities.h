#ifndef UTILITIES_H
#define UTILITIES_H

#define WPCAP
#define HAVE_REMOTE

#include <iostream>
#include <pcap.h>
#include <remote-ext.h>
#include <winsock.h>
#include <protocol.h>


int analyze_frame(const u_char *pkt, datapkt *data, pktCount *npacket);
int analyze_arp(const u_char *pkt, datapkt *data, pktCount *npacket);
int analyze_ip(const u_char *pkt, datapkt *data, pktCount *npacket);
int analyze_icmp(const u_char *pkt, datapkt *data, pktCount *npacket);
int analyze_tcp(const u_char *pkt, datapkt *data, pktCount *npacket);
int analyze_udp(const u_char *pkt, datapkt *data, pktCount *npacket);
static const u_char * pktInitialAddress;

#endif // UTILITIES_H
