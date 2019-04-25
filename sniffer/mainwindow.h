#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QMessageBox>
#include <QDebug>
#include "winpcap/Include/pcap.h"

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

private slots:
    void on_comboBox_devs_tab1_currentIndexChanged(int index);
    void on_comboBox_filter_tab1_currentIndexChanged(int index);

private:
    Ui::MainWindow *ui;
    int devCount;
    pcap_if_t *alldev;
    pcap_if_t *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *adhandle;


};

#endif // MAINWINDOW_H
