#include "utilities.h"
#include <QDebug>

int utilities::analyze_frame(const u_char *pkt, datapkt *data, pktCount *npacket)
{
    pktInitialAddress = pkt;
    ethhdr *ethh = (ethhdr *)pkt;
    data->ethh = (ethhdr *)malloc(sizeof(ethhdr));
    if (data->ethh == NULL)
    {
        qDebug() << "failed to malloc ethh space." << endl;
        return -1;
    }
    for (int i = 0; i < 6; ++i)
    {
        data->ethh->dest[i] = ethh->dest[i];
        data->ethh->src[i] = ethh->src[i];
    }
    //数据包的总数加1
    npacket->n_sum++;
    //由于网络字节顺序的原因，需要进行对齐
    data->ethh->type = ntohs(ethh->type);

    int ret = 0;

    //对上层协议类型做进一步的判断，并做进一步的拆包分析
    switch (data->ethh->type)
    {
    case PROTO_IP:
        ret = analyze_ip((u_char *)pkt + 14, data, npacket);
        break;
    case PROTO_ARP:
        ret = analyze_arp((u_char *)pkt + 14, data, npacket);
        break;
    default:
        npacket->n_other++;
        ret = -1;
        break;
    }
    return ret;
}

//对链路层协议的上一层协议继续进行分析
int utilities::analyze_arp(const u_char *pkt, datapkt *data, pktCount *npacket)
{
    arphdr *arph = (arphdr *)pkt;
    data->arph = (arphdr *)malloc(sizeof(arphdr));
    if (data->arph == NULL)
    {
        qDebug() << "failed to malloc arph space!" << endl;
        return -1;
    }
    //复制IP以及MAC地址
    for (int i = 0; i < 6; i++)
    {
        if (i < 4)
        {
            data->arph->senderIp[i] = arph->senderIp[i];
            data->arph->destIp[i] = arph->destIp[i];
        }
        data->arph->senderMac[i] = arph->senderMac[i];
        data->arph->destMac[i] = arph->destMac[i];
    }

    data->arph->htype = ntohs(arph->htype);
    data->arph->prtype = ntohs(arph->prtype);
    data->arph->hsize = arph->hsize;
    data->arph->prsize = arph->prsize;
    data->arph->opcode = ntohs(arph->opcode);
    strcpy(data->pktType, "ARP");
    npacket->n_arp++;
    return 1;
}

/*分析网络层：IP*/
int utilities::analyze_ip(const u_char *pkt, datapkt *data, pktCount *npacket)
{
    iphdr *iph = (iphdr *)pkt;
    data->iph = (iphdr *)malloc(sizeof(iphdr));
    if (data->iph == NULL)
    {
        return -1;
    }
    data->iph->hchecksum = ntohs(iph->hchecksum);
    npacket->n_ip++;
    for (int i = 0; i < 4; i++)
    {
        data->iph->daddr[i] = iph->daddr[i];
        data->iph->saddr[i] = iph->saddr[i];
    }
    data->iph->tos = iph->tos;
    data->iph->ip_vhl = iph->ip_vhl;
    data->iph->ip_len = ntohs(iph->ip_len);
    data->iph->identification = ntohs(iph->identification);
    data->iph->flags_fo = ntohs(iph->flags_fo);
    data->iph->ttl = iph->ttl;
    data->iph->proto = iph->proto;
    u_int ipheader_len = IP_HL(data->iph) * 4;
    int ret = 0;
    switch (iph->proto)
    {
    case PROTO_ICMP:
        ret = analyze_icmp((u_char *)iph + ipheader_len, data, npacket);
        break;
    case PROTO_TCP:
        ret = analyze_tcp((u_char *)iph + ipheader_len, data, npacket);
        break;
    case PROTO_UDP:
        ret = analyze_udp((u_char *)iph + ipheader_len, data, npacket);
        break;
    default:
        npacket->n_other++;
        ret = -1;
        break;
    }
    return ret;
}

int utilities::analyze_icmp(const u_char *pkt, datapkt *data, pktCount *npacket)
{
    icmphdr *icmph = (icmphdr *)pkt;
    data->icmph = (icmphdr *)malloc(sizeof(icmphdr));
    if (NULL == data->icmph)
    {
        return  -1;
    }
    data->icmph->chk_sum = icmph->chk_sum;
    data->icmph->code = icmph->code;
    data->icmph->seq = ntohs(icmph->seq);
    data->icmph->type = icmph->type;
    data->icmph->identification = ntohs(icmph->identification);
    data->icmph->chk_sum = ntohs(icmph->chk_sum);
    strcpy(data->pktType, "ICMP");
    npacket->n_icmp++;
    return 1;
}

int utilities::analyze_tcp(const u_char *pkt, datapkt *data, pktCount *npacket)
{
    tcphdr *tcphr = (tcphdr *)pkt;
    data->tcph = (tcphdr *)malloc(sizeof(tcphdr));
    if (data->tcph == NULL)
    {
        return -1;
    }
    npacket->n_tcp++;
    data->tcph->srcPort = ntohs(tcphr->srcPort);
    data->tcph->destPort = ntohs(tcphr->destPort);
    data->tcph->seq = ntohl(tcphr->seq);
    data->tcph->ack_sql = ntohl(tcphr->ack_sql);
    data->tcph->th_offx2 = tcphr->th_offx2;
    data->tcph->th_flags = tcphr->th_flags;
    data->tcph->wnd_size = ntohs(tcphr->wnd_size);
    data->tcph->checksum = ntohs(tcphr->checksum);
    data->tcph->urg_ptr = ntohs(tcphr->urg_ptr);
    //根据端口是否为80端口初步过滤出HTTP协议
    if (data->tcph->srcPort == 80 || data->tcph->destPort == 80)
    {

        u_char *httpdata = (u_char *)tcphr + TH_OFF(tcphr) * 4;
        const char *token[] = {"GET", "POST", "HTTP/1.1", "HTTP/1.0"};
        u_char *httpHeader;
        for (int i = 0; i < 4; i++)
        {
            httpHeader = (u_char *)strstr((char *)httpdata, token[i]);
            if (httpHeader)
            {

                npacket->n_http++;
                strcpy(data->pktType, "HTTP");
                data->isHttp = true;
                int size = data->len - ((u_char *)httpdata - pktInitialAddress);
                data->httpsize = size;
                data->apph = (u_char *)malloc(size * sizeof(u_char));
                for (int j = 0; j < size; j++)
                {
                    data->apph[j] = httpdata[j];
                }
                return 1;
            }
        }
    }
    strcpy(data->pktType, "TCP");
    return 1;
}

int utilities::analyze_udp(const u_char *pkt, datapkt *data, pktCount *npacket)
{
    udphdr *udphr = (udphdr *)pkt;
    data->udph = (udphdr *)malloc(sizeof(udphdr));
    if (data->udph == NULL)
    {
        qDebug() << "failed to malloc udp header space!" << endl;
        return -1;
    }
    data->udph->sport = ntohs(udphr->sport);
    data->udph->dport = ntohs(udphr->dport);
    data->udph->len = ntohs(udphr->len);
    data->udph->crc = ntohs(udphr->crc);
    strcpy(data->pktType, "UDP");
    npacket->n_udp++;
    return 1;
}
