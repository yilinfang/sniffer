#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    //ui->comboBox_devs_tab1->addItems();
    if(initCap() < 0)
    {
        QMessageBox::warning(this, tr("sniffer"), tr("无法找到网络适配器"),QMessageBox::Yes);
    }
    for(dev = alldev; dev; dev = dev->next)
    {
        ui->comboBox_devs_tab1->addItem(QString(dev->name));
    }
}

MainWindow::~MainWindow()
{
    if(alldev)
    {
        pcap_freealldevs(alldev);
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

void MainWindow::on_comboBox_devs_tab1_currentIndexChanged(int index)
{
    dev = alldev;
    for(int i = 0; i < index - 1; i++)
    {
        dev = dev->next;
    }
    qDebug() << ui->comboBox_devs_tab1->currentText();
    qDebug() << QString(dev->description);
    if (!(adhandle = pcap_open_live(dev->name, 65536, 1, 1000, errbuf)))
    {
        QMessageBox::warning(this, tr("sniffer"), tr("无法打开接口"),QMessageBox::Yes);
        pcap_freealldevs(alldev);
        alldev = NULL;
    }
}


void MainWindow::on_comboBox_filter_tab1_currentIndexChanged(int index)
{

}
