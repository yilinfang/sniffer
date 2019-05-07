#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    ui->treeWidget_tab1->clear();
    ui->tableWidget_tab1->setColumnCount(8);
    ui->tableWidget_tab1->setColumnCount(8);
    ui->tableWidget_tab1->setHorizontalHeaderLabels(QStringList() << tr("序号") << tr("时间")
                                              << tr("源MAC地址") << tr("目的MAC地址")
                                              << tr("长度") << tr("协议类型")
                                              << tr("源IP地址") << tr("目的IP地址"));
    ui->tableWidget_tab1->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->tableWidget_tab1->setSelectionMode(QAbstractItemView::SingleSelection);
    ui->tableWidget_tab1->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui->tableWidget_tab1->setColumnWidth(0, 60);
    ui->tableWidget_tab1->setColumnWidth(1, 180);
    ui->tableWidget_tab1->setColumnWidth(2, 210);
    ui->tableWidget_tab1->setColumnWidth(3, 210);
    ui->tableWidget_tab1->setColumnWidth(4, 60);
    ui->tableWidget_tab1->setColumnWidth(5, 85);
    ui->tableWidget_tab1->setColumnWidth(6, 145);
    ui->tableWidget_tab1->setColumnWidth(7, 145);
    ui->tableWidget_tab1->verticalHeader()->setVisible(false);
    ui->treeWidget_tab1->setColumnCount(1);
    ui->treeWidget_tab1->setHeaderLabel(tr("协议分析"));
    ui->treeWidget_tab1->header()->setSectionResizeMode(QHeaderView::ResizeToContents);
    ui->treeWidget_tab1->header()->setStretchLastSection(false);
    if(initCap() < 0)
    {
        QMessageBox::warning(this, tr("sniffer"), tr("无法找到网络适配器"),QMessageBox::Yes);
    }
    for(dev = alldev; dev; dev = dev->next)
    {
        ui->comboBox_devs->addItem(QString(dev->description));
    }
    npacket = (pktCount *)malloc(sizeof(pktCount));
    memset(npacket, 0, sizeof(pktCount));
    capThread = NULL;
}

MainWindow::~MainWindow()
{
    if(alldev)
    {
        pcap_freealldevs(alldev);
    }
    if(capThread)
    {
        if(capThread->isRunning())
        {
            capThread->stop();
            capThread->quit();
        }
        while(!capThread->isFinished());
        delete capThread;
        capThread = NULL;
    }
    for(std::vector<datapkt *>::iterator it = dataPktVec.begin(); it != dataPktVec.end(); it++)
    {
        free((*it)->ethh);
        free((*it)->arph);
        free((*it)->iph);
        free((*it)->icmph);
        free((*it)->udph);
        free((*it)->tcph);
        free((*it)->apph);
        free(*it);
    }
    for(std::vector<u_char *>::iterator it = dataVec.begin(); it != dataVec.end(); it++)
    {
        free(*it);
    }
    if(npacket)
    {
        free(npacket);
    }
    delete ui;
}

int MainWindow::initCap()
{
    devCount = 0;
    if(pcap_findalldevs(&alldev, errbuf) == -1)
    {
        return -1;
    }
    for(dev = alldev; dev; dev = dev->next)
    {
        devCount++;
    }
    return 0;
}

int MainWindow::startCap()
{
    u_int netmask;
    struct bpf_program fcode;   //bpf_program结构体在编译BPF过滤规则函数执行成功后将会被填
    //int filterIndex = ui->comboBox_filter_tab1->currentIndex();

    if(!(adhandle = pcap_open_live(dev->name,    //设备名
                                  65536,    //捕获数据包长度
                                  1,    //设置成混杂模式
                                  1000,    //读超时设置
                                  errbuf  //错误信息缓冲
                                  )))
    {
        QMessageBox::warning(this, "open error", tr("网卡接口打开失败"), QMessageBox::Ok);
        pcap_freealldevs(alldev);
        alldev = NULL;
        return -1;
    }

    //检查链路层，判断所在网络是否为以太网
    if(pcap_datalink(adhandle) != DLT_EN10MB)
    {
        QMessageBox::warning(this, "Sniffer", tr("只支持以太网环境"), QMessageBox::Ok);
        pcap_freealldevs(alldev);
        alldev = NULL;
        return -1;
    }

    //获取接口第一个地址的子网掩码，如果接口没有地址，假设这个接口在C类网络中
    if(dev->addresses)
    {
        netmask = ((struct sockaddr_in *)(dev->addresses->netmask))->sin_addr.S_un.S_addr;
    }
    else
    {
        netmask = 0xffffff;

    }
    QString filter_qstr = ui->lineEdit_filter_tab1->text();
    if(filter_qstr == "")
    {
        char filter[] = "";
        if(pcap_compile(adhandle, &fcode, filter, 1, netmask) < 0)
        {
            QMessageBox::warning(this, "Sniff", tr("无法编译包过滤器，请检查语法"), QMessageBox::Ok);
            pcap_freealldevs(alldev);
            alldev = NULL;
            return -1;
        }
    }
    else
    {
        QByteArray ba = filter_qstr.toLatin1();
        char *filter = NULL;
        filter = ba.data();     //上述转换中要求QString中不含有中文，否则会出现乱码
        if(pcap_compile(adhandle, &fcode, filter, 1, netmask) < 0)
        {
            QMessageBox::warning(this, "Sniff", tr("无法编译包过滤器，请检查语法"), QMessageBox::Ok);
            pcap_freealldevs(alldev);
            alldev = NULL;
            return -1;
        }

    }

    //设置过滤器
    if(pcap_setfilter(adhandle, &fcode) < 0)
    {
        QMessageBox::warning(this, "Sniff", tr("设置过滤器发生错误"), QMessageBox::Ok);
        pcap_freealldevs(alldev);
        alldev = NULL;
        return -1;
    }

    //获取当前路径
    QString path = QDir::currentPath();
    qDebug() << path << endl;
    //判断当前路径下文件是否存在
    QString direcPath = path + "//SavedData";
    QDir dir(direcPath);
    if(!dir.exists())
    {
        if(!dir.mkdir(direcPath))
        {
            QMessageBox::warning(this, "warning", tr("保存路径创建失败!"), QMessageBox::Ok);
            return -1;
        }
    }
    capThread = new CapThread(adhandle, npacket, dataPktVec, dataVec);
    connect(capThread, SIGNAL(updateCapInfo(QString,QString,QString,QString,QString,QString,QString)), this, SLOT(on_updateCapInfo(QString,QString,QString,QString,QString,QString,QString)));
    capThread->start();
    return 1;

}

void MainWindow::showHexData(u_char *data, int len)
{
    QString tempnum,tempchar;
    QString oneline;
    int i;
    tempchar = "  ";
    oneline = "";
    for(i = 0 ; i < len ; i ++)
    {
        if(i % 16 == 0)
        {
            //输出行号
            oneline += tempnum.sprintf("%04x  ",i);
        }
        oneline += tempnum.sprintf("%02x ",data[i]);
        if(isprint(data[i]))
        {     //判断是否为可打印字符
            tempchar += data[i];
        }
        else
        {
            tempchar += ".";
        }
        if((i+1)%16 == 0)
        {
            ui->textEdit_tab1->append(oneline + tempchar);
            tempchar = "  ";
            oneline = "";
        }
    }
    i %= 16;
    for(; i < 16 ; i ++)
    {
        oneline += "   ";
    }
    ui->textEdit_tab1->append(oneline + tempchar);
}

void MainWindow::showProtoTree(datapkt *data, int num)
{
    QString showStr;
    char buf[100];
    sprintf(buf, "接收到的第%d个数据包", num);
    showStr = QString(buf);

    QTreeWidgetItem *root = new QTreeWidgetItem(ui->treeWidget_tab1);
    root->setText(0, showStr);

    //处理帧数据
    showStr = QString("链路层数据");
    QTreeWidgetItem *level1 = new QTreeWidgetItem(root);
    level1->setText(0, showStr);

    sprintf(buf, "%02x-%02x-%02x-%02x-%02x-%02x", data->ethh->src[0], data->ethh->src[1],
            data->ethh->src[2], data->ethh->src[3], data->ethh->src[4], data->ethh->src[5]);
    showStr = "源MAC: " + QString(buf);
    QTreeWidgetItem *srcEtherMac = new QTreeWidgetItem(level1);
    srcEtherMac->setText(0, showStr);

    sprintf(buf, "%02x-%02x-%02x-%02x-%02x-%02x", data->ethh->dest[0], data->ethh->dest[1],
            data->ethh->dest[2], data->ethh->dest[3], data->ethh->dest[4], data->ethh->dest[5]);
    showStr = "目的MAC: " + QString(buf);
    QTreeWidgetItem *destEtherMac = new QTreeWidgetItem(level1);
    destEtherMac->setText(0, showStr);

    sprintf(buf, "%04x", data->ethh->type);
    showStr = "类型:0x" + QString(buf);
    QTreeWidgetItem *etherType = new QTreeWidgetItem(level1);
    etherType->setText(0, showStr);

    //处理IP,ARP类型的数据包
    if(data->ethh->type == 0x0806)      //ARP
    {
        //添加ARP协议头
        showStr = QString("ARP协议头");
        QTreeWidgetItem *level2 = new QTreeWidgetItem(root);
        level2->setText(0, showStr);

        sprintf(buf, "硬件类型: 0x%04x", data->arph->htype);
        showStr = QString(buf);
        QTreeWidgetItem *arpHtype = new QTreeWidgetItem(level2);
        arpHtype->setText(0, showStr);

        sprintf(buf, "协议类型: 0x%04x", data->arph->prtype);
        showStr = QString(buf);
        QTreeWidgetItem *arpPrtype = new QTreeWidgetItem(level2);
        arpPrtype->setText(0, showStr);

        sprintf(buf, "硬件地址长度: %d", data->arph->hsize);
        showStr = QString(buf);
        QTreeWidgetItem *arpHsize = new QTreeWidgetItem(level2);
        arpHsize->setText(0, showStr);

        sprintf(buf, "协议地址长度: %d", data->arph->prsize);
        showStr = QString(buf);
        QTreeWidgetItem *arpPrsize = new QTreeWidgetItem(level2);
        arpPrsize->setText(0, showStr);

        sprintf(buf, "操作码: %d", data->arph->opcode);
        showStr = QString(buf);
        QTreeWidgetItem *arpCode = new QTreeWidgetItem(level2);
        arpCode->setText(0, showStr);

        sprintf(buf, "%02x-%02x-%02x-%02x-%02x-%02x", data->arph->senderMac[0], data->arph->senderMac[1],
                data->arph->senderMac[2], data->arph->senderMac[3], data->arph->senderMac[4], data->arph->senderMac[5]);
        showStr = "发送方MAC: " + QString(buf);
        QTreeWidgetItem *srcArpMac = new QTreeWidgetItem(level2);
        srcArpMac->setText(0, showStr);

        sprintf(buf, "%d.%d.%d.%d", data->arph->senderIp[0], data->arph->senderIp[1], data->arph->senderIp[2]
                ,data->arph->senderIp[3]);
        showStr = "发送方IP: " + QString(buf);
        QTreeWidgetItem *srcArpIp = new QTreeWidgetItem(level2);
        srcArpIp->setText(0, showStr);

        sprintf(buf, "%02x-%02x-%02x-%02x-%02x-%02x", data->arph->destMac[0], data->arph->destMac[1],
                data->arph->destMac[2], data->arph->destMac[3], data->arph->destMac[4], data->arph->destMac[5]);
        showStr = "接收方MAC: " + QString(buf);
        QTreeWidgetItem *destArpMac = new QTreeWidgetItem(level2);
        destArpMac->setText(0, showStr);

        sprintf(buf, "%d.%d.%d.%d", data->arph->destIp[0], data->arph->destIp[1], data->arph->destIp[2]
                ,data->arph->destIp[3]);
        showStr = "接收方IP: " + QString(buf);
        QTreeWidgetItem *destArpIp = new QTreeWidgetItem(level2);
        destArpIp->setText(0, showStr);
    }
    else if(data->ethh->type == 0x0800)     //IP
    {
        //添加IP协议头
        showStr = QString("IP协议头");
        QTreeWidgetItem *level3 = new QTreeWidgetItem(root);
        level3->setText(0, showStr);

        sprintf(buf, "版本: %d", IP_V(data->iph));
        showStr = QString(buf);
        QTreeWidgetItem *ipVersion = new QTreeWidgetItem(level3);
        ipVersion->setText(0, showStr);

        sprintf(buf, "IP首部长度: %d", IP_HL(data->iph));
        showStr = QString(buf);
        QTreeWidgetItem *ipHeaderLen = new QTreeWidgetItem(level3);
        ipHeaderLen->setText(0, showStr);

        sprintf(buf, "服务类型: %d", data->iph->tos);
        showStr = QString(buf);
        QTreeWidgetItem *ipTos = new QTreeWidgetItem(level3);
        ipTos->setText(0, showStr);

        sprintf(buf, "总长度: %d", data->iph->ip_len);
        showStr = QString(buf);
        QTreeWidgetItem *ipTotalLen = new QTreeWidgetItem(level3);
        ipTotalLen->setText(0, showStr);

        sprintf(buf, "标识: 0x%04x", data->iph->identification);
        showStr = QString(buf);
        QTreeWidgetItem *ipIdentify = new QTreeWidgetItem(level3);
        ipIdentify->setText(0, showStr);

        sprintf(buf, "标志(Reserved Fragment Flag): %d", (data->iph->flags_fo & IP_RF) >> 15);
        showStr = QString(buf);
        QTreeWidgetItem *flag0 = new QTreeWidgetItem(level3);
        flag0->setText(0, showStr);

        sprintf(buf, "标志(Don't fragment Flag): %d", (data->iph->flags_fo & IP_DF) >> 14);
        showStr = QString(buf);
        QTreeWidgetItem *flag1 = new QTreeWidgetItem(level3);
        flag1->setText(0, showStr);

        sprintf(buf, "标志(More Fragment Flag): %d", (data->iph->flags_fo & IP_MF) >> 13);
        showStr = QString(buf);
        QTreeWidgetItem *flag3 = new QTreeWidgetItem(level3);
        flag3->setText(0, showStr);

        sprintf(buf, "段偏移: %d", data->iph->flags_fo & IP_OFFMASK);
        showStr = QString(buf);
        QTreeWidgetItem *ipOffset = new QTreeWidgetItem(level3);
        ipOffset->setText(0, showStr);

        sprintf(buf, "生存期: %d", data->iph->ttl);
        showStr = QString(buf);
        QTreeWidgetItem *ipTTL = new QTreeWidgetItem(level3);
        ipTTL->setText(0, showStr);

        sprintf(buf, "协议: %d", data->iph->proto);
        showStr = QString(buf);
        QTreeWidgetItem *ipProto = new QTreeWidgetItem(level3);
        ipProto->setText(0, showStr);

        sprintf(buf, "首部校验和: 0x%04x", data->iph->hchecksum);
        showStr = QString(buf);
        QTreeWidgetItem *ipHCheckSum = new QTreeWidgetItem(level3);
        ipHCheckSum->setText(0, showStr);

        sprintf(buf, "%d.%d.%d.%d", data->iph->saddr[0], data->iph->saddr[1], data->iph->saddr[2]
                ,data->iph->saddr[3]);
        showStr = "源IP: " + QString(buf);
        QTreeWidgetItem *ipSrcIp = new QTreeWidgetItem(level3);
        ipSrcIp->setText(0, showStr);

        sprintf(buf, "%d.%d.%d.%d", data->iph->daddr[0], data->iph->daddr[1], data->iph->daddr[2]
                ,data->iph->daddr[3]);
        showStr = "目的IP: " + QString(buf);
        QTreeWidgetItem *ipDestIp = new QTreeWidgetItem(level3);
        ipDestIp->setText(0, showStr);

        //处理传输层udp, icmp, tcp
        if(data->iph->proto == PROTO_ICMP)  //ICMP协议
        {
            //添加ICMP协议头
            showStr = QString("ICMP协议头");
            QTreeWidgetItem *level4 = new QTreeWidgetItem(root);
            level4->setText(0, showStr);

            sprintf(buf, "类型: %d", data->icmph->type);
            showStr = QString(buf);
            QTreeWidgetItem *icmpType = new QTreeWidgetItem(level4);
            icmpType->setText(0, showStr);

            sprintf(buf, "代码: %d", data->icmph->code);
            showStr = QString(buf);
            QTreeWidgetItem *icmpCode = new QTreeWidgetItem(level4);
            icmpCode->setText(0, showStr);

            sprintf(buf, "校验和: 0x%04x", data->icmph->chk_sum);
            showStr = QString(buf);
            QTreeWidgetItem *icmpCheck = new QTreeWidgetItem(level4);
            icmpCheck->setText(0, showStr);

            sprintf(buf, "标识: 0x%04x", data->icmph->identification);
            showStr = QString(buf);
            QTreeWidgetItem *icmpIdentify = new QTreeWidgetItem(level4);
            icmpIdentify->setText(0, showStr);

            sprintf(buf, "序列号: 0x%04x", data->icmph->seq);
            showStr = QString(buf);
            QTreeWidgetItem *icmpSeq = new QTreeWidgetItem(level4);
            icmpSeq->setText(0, showStr);
        }
        else if(data->iph->proto == PROTO_TCP)  //TCP协议
        {
            showStr = QString("TCP协议头");
            QTreeWidgetItem *level5 = new QTreeWidgetItem(root);
            level5->setText(0, showStr);

            sprintf(buf, "源端口: %d", data->tcph->srcPort);
            showStr = QString(buf);
            QTreeWidgetItem *tcpSrcPort = new QTreeWidgetItem(level5);
            tcpSrcPort->setText(0, showStr);

            sprintf(buf, "目的端口: %d", data->tcph->destPort);
            showStr = QString(buf);
            QTreeWidgetItem *tcpDestPort = new QTreeWidgetItem(level5);
            tcpDestPort->setText(0, showStr);

            sprintf(buf, "序列号: 0x%08x", data->tcph->seq);
            showStr = QString(buf);
            QTreeWidgetItem *tcpSeq = new QTreeWidgetItem(level5);
            tcpSeq->setText(0, showStr);

            sprintf(buf, "确认号: 0x%08x", data->tcph->ack_sql);
            showStr = QString(buf);
            QTreeWidgetItem *tcpAck = new QTreeWidgetItem(level5);
            tcpAck->setText(0, showStr);

            sprintf(buf, "首部长度: %d bytes (%d)", TH_OFF(data->tcph) * 4, TH_OFF(data->tcph));
            showStr = QString(buf);
            QTreeWidgetItem *tcpOFF = new QTreeWidgetItem(level5);
            tcpOFF->setText(0, showStr);

            sprintf(buf, "FLAG: 0x%02x", data->tcph->th_flags);
            showStr = QString(buf);
            QTreeWidgetItem *tcpFlag = new QTreeWidgetItem(level5);
            tcpFlag->setText(0, showStr);

            sprintf(buf, "CWR: %d", (data->tcph->th_flags & TH_CWR) >> 7);
            showStr = QString(buf);
            QTreeWidgetItem *cwrflag = new QTreeWidgetItem(tcpFlag);
            cwrflag->setText(0, showStr);

            sprintf(buf, "ECE: %d", (data->tcph->th_flags & TH_ECE) >> 6);
            showStr = QString(buf);
            QTreeWidgetItem *eceflag = new QTreeWidgetItem(tcpFlag);
            eceflag->setText(0, showStr);

            sprintf(buf, "URG: %d", (data->tcph->th_flags & TH_URG) >> 5);
            showStr = QString(buf);
            QTreeWidgetItem *urgflag = new QTreeWidgetItem(tcpFlag);
            urgflag->setText(0, showStr);

            sprintf(buf, "ACK: %d", (data->tcph->th_flags & TH_ACK) >> 4);
            showStr = QString(buf);
            QTreeWidgetItem *ackflag = new QTreeWidgetItem(tcpFlag);
            ackflag->setText(0, showStr);

            sprintf(buf, "PUSH: %d", (data->tcph->th_flags & TH_PUSH) >> 3);
            showStr = QString(buf);
            QTreeWidgetItem *pushflag = new QTreeWidgetItem(tcpFlag);
            pushflag->setText(0, showStr);

            sprintf(buf, "RST: %d", (data->tcph->th_flags & TH_RST) >> 2);
            showStr = QString(buf);
            QTreeWidgetItem *rstflag = new QTreeWidgetItem(tcpFlag);
            rstflag->setText(0, showStr);

            sprintf(buf, "SYN: %d", (data->tcph->th_flags & TH_SYN) >> 1);
            showStr = QString(buf);
            QTreeWidgetItem *synflag = new QTreeWidgetItem(tcpFlag);
            synflag->setText(0, showStr);

            sprintf(buf, "FIN: %d", (data->tcph->th_flags & TH_FIN));
            showStr = QString(buf);
            QTreeWidgetItem *finflag = new QTreeWidgetItem(tcpFlag);
            finflag->setText(0, showStr);

            sprintf(buf, "窗口大小: %d", data->tcph->wnd_size);
            showStr = QString(buf);
            QTreeWidgetItem *tcpWndSize = new QTreeWidgetItem(level5);
            tcpWndSize->setText(0, showStr);

            sprintf(buf, "校验和: 0x%04x", data->tcph->checksum);
            showStr = QString(buf);
            QTreeWidgetItem *tcpCheck = new QTreeWidgetItem(level5);
            tcpCheck->setText(0, showStr);

            sprintf(buf, "紧急指针: %d", data->tcph->urg_ptr);
            showStr = QString(buf);
            QTreeWidgetItem *tcpUrgPtr = new QTreeWidgetItem(level5);
            tcpUrgPtr->setText(0, showStr);

            if(data->isHttp == true)
            {
                showStr = QString("HTTP协议头");
                QTreeWidgetItem *level8 = new QTreeWidgetItem(root);
                level8->setText(0, showStr);

                QString content = "";
                u_char *httpps = data->apph;

                qDebug() << QString(*httpps) << QString(*(httpps + 1)) << QString(*(httpps + 2)) << endl;

                u_char *httpps2 = NULL;

                const char *token[] = {"GET","POST","HTTP/1.1","HTTP/1.0"};
                for(int i = 0 ; i < 4 ; i ++)
                {
                    httpps2 = (u_char *)strstr((char *)httpps,token[i]);
                    if(httpps2){
                        break;
                    }
                }
                int size = data->httpsize - (httpps2 - httpps);

                for(int i = 0 ; i < size; i++)
                {
                    if(httpps2[i] == 0x0d)
                    {
                        //如果到达http正文结尾
                        if(httpps2[i+1] == 0x0a && httpps2[i+2] == 0x0d && httpps2[i+3] == 0x0a)
                        {
                            content += "\\r\\n";
                            level8->addChild(new QTreeWidgetItem(level8,QStringList(content)));
                            level8->addChild(new QTreeWidgetItem(level8,QStringList("\\r\\n")));
                            break;
                        }
                        else if(httpps2[i+1] == 0x0a)
                        {
                            level8->addChild(new QTreeWidgetItem(level8,QStringList(content + "\\r\\n")));
                            content = "";
                            i ++;
                            continue;
                        }
                    }
                    content += httpps2[i];
                }
                level8->addChild(new QTreeWidgetItem(level8,QStringList("(Data)(Data)")));
            }
        }
        else if(data->iph->proto == PROTO_UDP)  //UDP协议
        {
            //添加UDP协议头
            showStr = QString("UDP协议头");
            QTreeWidgetItem *level6 = new QTreeWidgetItem(root);
            level6->setText(0, showStr);

            sprintf(buf, "源端口: %d", data->udph->sport);
            showStr = QString(buf);
            QTreeWidgetItem *udpSrcPort = new QTreeWidgetItem(level6);
            udpSrcPort->setText(0, showStr);

            sprintf(buf, "目的端口: %d", data->udph->dport);
            showStr = QString(buf);
            QTreeWidgetItem *udpDestPort = new QTreeWidgetItem(level6);
            udpDestPort->setText(0, showStr);

            sprintf(buf, "总长度: %d", data->udph->len);
            showStr = QString(buf);
            QTreeWidgetItem *udpLen = new QTreeWidgetItem(level6);
            udpLen->setText(0, showStr);

            sprintf(buf, "校验和: 0x%04x", data->udph->crc);
            showStr = QString(buf);
            QTreeWidgetItem *udpCrc = new QTreeWidgetItem(level6);
            udpCrc->setText(0, showStr);
        }
    }
}


void MainWindow::on_comboBox_devs_currentIndexChanged(int index)
{
    dev = alldev;
    for(int i = 0; i < index - 1; i++)
    {
        dev = dev->next;
    }
    qDebug() << ui->comboBox_devs->currentText();
    qDebug() << QString(dev->description);
    if (!(adhandle = pcap_open_live(dev->name, 65536, 1, 1000, errbuf)))
    {
        QMessageBox::warning(this, tr("sniffer"), tr("无法打开接口"),QMessageBox::Yes);
        pcap_freealldevs(alldev);
        alldev = NULL;
    }
}

void MainWindow::on_tableWidget_tab1_cellClicked(int row, int column)
{
    ui->textEdit_tab1->clear();
    ui->treeWidget_tab1->clear();
    datapkt *mem_data = (datapkt*)dataPktVec[row];
    u_char *print_data = (u_char *)dataVec[row];
    int print_len = mem_data->len;
    showHexData(print_data, print_len);
    showProtoTree(mem_data, row + 1);
    if(rowCount > 1)
    {
        ui->tableWidget_tab1->scrollToItem(ui->tableWidget_tab1->item(rowCount, 0), QAbstractItemView::PositionAtBottom);
    }

}

void MainWindow::on_updateCapInfo(QString time, QString srcMac, QString destMac, QString len, QString protoType, QString srcIP, QString dstIP)
{
    rowCount = ui->tableWidget_tab1->rowCount();
    ui->tableWidget_tab1->insertRow(rowCount);
    QString number = QString::number(rowCount, 10);
    ui->tableWidget_tab1->setItem(rowCount, 0, new QTableWidgetItem(number));
    ui->tableWidget_tab1->setItem(rowCount, 1, new QTableWidgetItem(time));
    ui->tableWidget_tab1->setItem(rowCount, 2, new QTableWidgetItem(srcMac));
    ui->tableWidget_tab1->setItem(rowCount, 3, new QTableWidgetItem(destMac));
    ui->tableWidget_tab1->setItem(rowCount, 4, new QTableWidgetItem(len));
    ui->tableWidget_tab1->setItem(rowCount, 5, new QTableWidgetItem(protoType));
    ui->tableWidget_tab1->setItem(rowCount, 6, new QTableWidgetItem(srcIP));
    ui->tableWidget_tab1->setItem(rowCount, 7, new QTableWidgetItem(dstIP));
    ui->label_TCP_tab1->setText("TCP:" + QString::number(npacket->n_tcp));
    ui->label_UDP_tab1->setText("UDP:" + QString::number(npacket->n_udp));
    ui->label_ICMP_tab1->setText("ICMP:" + QString::number(npacket->n_icmp));
    ui->label_HTTP_tab1->setText("HTTP:" + QString::number(npacket->n_http));
    ui->label_ARP_tab1->setText("ARP:" + QString::number(npacket->n_arp));
    ui->label_IPV4_tab1->setText("IPV4:" + QString::number(npacket->n_ip));
    ui->label_other_tab1->setText("其他:" + QString::number(npacket->n_other));
    ui->label_all_tab1->setText("合计:" + QString::number(npacket->n_sum));
}

void MainWindow::on_pushButton_startPcap_tab1_clicked()
{
    for(std::vector<datapkt *>::iterator it = dataPktVec.begin(); it != dataPktVec.end(); it++)
    {
        free((*it)->ethh);
        free((*it)->arph);
        free((*it)->iph);
        free((*it)->icmph);
        free((*it)->udph);
        free((*it)->tcph);
        free((*it)->apph);
        free(*it);
    }
    for(std::vector<u_char *>::iterator it = dataVec.begin(); it != dataVec.end(); it++)
    {
        free(*it);
    }

    DataPktVec().swap(dataPktVec);
    DataVec().swap(dataVec);

    memset(npacket, 0, sizeof(pktCount));


    if(capThread)
    {
        if(capThread->isRunning())
        {
            capThread->stop();
            capThread->quit();
        }
        while(!capThread->isFinished());
        delete capThread;
        capThread = NULL;
    }

    ui->textEdit_tab1->clear();
    ui->treeWidget_tab1->clear();
    ui->tableWidget_tab1->clearContents();
    ui->tableWidget_tab1->setRowCount(0);

    if(startCap() < 0)
    {
        return;
    }

}

void MainWindow::on_pushButton_stopPcap_tab1_clicked()
{
    if(capThread)
    {
        capThread->stop();
        capThread->quit();
        while(!capThread->isFinished());
        delete capThread;
        capThread = NULL;
    }
}
