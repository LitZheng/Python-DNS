# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'dns_ui.ui'
#
# Created by: PyQt5 UI code generator 5.15.4
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(400, 492)
        MainWindow.setMinimumSize(QtCore.QSize(10, 10))
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.widget = QtWidgets.QWidget(self.centralwidget)
        self.widget.setGeometry(QtCore.QRect(31, 64, 295, 282))
        self.widget.setObjectName("widget")
        self.verticalLayout = QtWidgets.QVBoxLayout(self.widget)
        self.verticalLayout.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout.setObjectName("verticalLayout")
        self.formLayout = QtWidgets.QFormLayout()
        self.formLayout.setObjectName("formLayout")
        self.server_ip_txt = QtWidgets.QLabel(self.widget)
        self.server_ip_txt.setMinimumSize(QtCore.QSize(120, 10))
        self.server_ip_txt.setObjectName("server_ip_txt")
        self.formLayout.setWidget(0, QtWidgets.QFormLayout.LabelRole, self.server_ip_txt)
        self.server_ip = QtWidgets.QLineEdit(self.widget)
        self.server_ip.setMinimumSize(QtCore.QSize(0, 0))
        self.server_ip.setObjectName("server_ip")
        self.formLayout.setWidget(0, QtWidgets.QFormLayout.FieldRole, self.server_ip)
        self.req_domain_txt = QtWidgets.QLabel(self.widget)
        self.req_domain_txt.setObjectName("req_domain_txt")
        self.formLayout.setWidget(1, QtWidgets.QFormLayout.LabelRole, self.req_domain_txt)
        self.req_domain = QtWidgets.QLineEdit(self.widget)
        self.req_domain.setObjectName("req_domain")
        self.formLayout.setWidget(1, QtWidgets.QFormLayout.FieldRole, self.req_domain)
        self.verticalLayout.addLayout(self.formLayout)
        self.textBrowser = QtWidgets.QTextBrowser(self.widget)
        self.textBrowser.setObjectName("textBrowser")
        self.verticalLayout.addWidget(self.textBrowser)
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.send = QtWidgets.QPushButton(self.widget)
        self.send.setObjectName("send")
        self.horizontalLayout.addWidget(self.send)
        self.reset = QtWidgets.QPushButton(self.widget)
        self.reset.setObjectName("reset")
        self.horizontalLayout.addWidget(self.reset)
        self.exit = QtWidgets.QPushButton(self.widget)
        self.exit.setObjectName("exit")
        self.horizontalLayout.addWidget(self.exit)
        self.verticalLayout.addLayout(self.horizontalLayout)
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 400, 22))
        self.menubar.setObjectName("menubar")
        self.menuDNS = QtWidgets.QMenu(self.menubar)
        self.menuDNS.setObjectName("menuDNS")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)
        self.menubar.addAction(self.menuDNS.menuAction())

        self.retranslateUi(MainWindow)
        self.reset.clicked.connect(self.server_ip.clear)
        self.reset.clicked.connect(self.req_domain.clear)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow"))
        self.server_ip_txt.setText(_translate("MainWindow", "服务器IP "))
        self.req_domain_txt.setText(_translate("MainWindow", "请求域名"))
        self.send.setText(_translate("MainWindow", "发送"))
        self.reset.setText(_translate("MainWindow", "重置"))
        self.exit.setText(_translate("MainWindow", "退出"))
        self.menuDNS.setTitle(_translate("MainWindow", "DNS客户端"))
