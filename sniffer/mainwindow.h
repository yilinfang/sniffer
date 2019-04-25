#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QMessageBox>
#include <QDebug>
#include <pcap.h>
#include "protocol.h"
#include "utilities.h"

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
    void showHexData(u_char* data, int len);
    void showProtoTree(datapkt* data, int num);

private slots:
    void on_comboBox_devs_currentIndexChanged(int index);
    void on_comboBox_filter_tab1_currentIndexChanged(int index);
    void on_tableWidget_tab1_cellClicked(int row, int column);

private:
    Ui::MainWindow *ui;
    int devCount;
    pcap_if_t *alldev;
    pcap_if_t *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *adhandle;
    pcap_dumper_t *dumpfile;
    pktCount *npacket;
    datapktVec dataPktLink;
    dataVec dataCharLink;
    int rowCount;
};

#endif // MAINWINDOW_H
