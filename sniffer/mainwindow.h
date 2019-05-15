#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QMessageBox>
#include <QDebug>
#include <pcap.h>
#include "protocol.h"
#include "utilities.h"
#include "capthread.h"
#include "sendthread.h"
#include <QDir>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private:
    int initCap();
    int startCap();
    int startArpCheat();
    void showHexData(u_char* data, int len);
    void showProtoTree(datapkt* data, int num);

private slots:
    void on_comboBox_devs_currentIndexChanged(int index);

    void on_tableWidget_tab1_cellClicked(int row, int column);

    void on_updateCapInfo(QString time, QString srcMac, QString destMac, QString len, QString protoType, QString srcIP, QString dstIP);

    void on_pushButton_startPcap_tab1_clicked();

    void on_pushButton_stopPcap_tab1_clicked();

    void on_tabWidget_currentChanged(int index);

    void on_pushButton_start_lab2_clicked();

    void on_pushButton_stop_lab2_clicked();

    void on_updateArpCheatMsg(QString msg);

    void on_updateSendInfo(QString str);
private:
    Ui::MainWindow *ui;
    int devCount;
    pcap_if_t *alldev;
    pcap_if_t *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *adhandle;
    pktCount *npacket;
    DataPktVec dataPktVec;
    DataVec dataVec;
    int rowCount;
    CapThread *capThread;
    SendThread *sendThread;
    u_char* getSelfMac(char *devname);
    void transMac(const char* src, u_char* dest);
    u_char* selfmac;
    u_char* targetMac;
    u_char* gateMac;
    u_long targetIp;
    u_long gateIp;
};

#endif // MAINWINDOW_H
