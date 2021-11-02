import sys
# PyQt5中使用的基本控件都在PyQt5.QtWidgets模块中
from PyQt5.QtWidgets import QApplication, QMainWindow
# 导入designer工具生成的login模块
from dns_ui import Ui_MainWindow
from DNS_client_qt5 import DNS_client


class MyMainForm(QMainWindow, Ui_MainWindow):
    def __init__(self, parent=None):
        super(MyMainForm, self).__init__(parent)
        self.setupUi(self)
        # 添加登录按钮信号和槽。注意display函数不加小括号()
        self.send.clicked.connect(self.display)
        # 添加退出按钮信号和槽。调用close函数
        self.exit.clicked.connect(self.close)

    def display(self):
        # 利用line Edit控件对象text()函数获取界面输入
        server_ip = self.server_ip.text()
        req_domain = self.req_domain.text()

        #利用text Browser控件对象setText()函数设置界面显示
        req_domains = (req_domain,)
        self.textBrowser.setText("发送成功!\n" + "服务器IP: " + server_ip + "\n请求域名： " + req_domain)
        dns_client = DNS_client()
        dns_client.dns_sendmsg(req_domains,server_ip)


if __name__ == "__main__":

    # 固定的，PyQt5程序都需要QApplication对象。sys.argv是命令行参数列表，确保程序可以双击运行
    app = QApplication(sys.argv)
    # 初始化
    myWin = MyMainForm()
    # 将窗口控件显示在屏幕上
    myWin.show()
    # 程序运行，sys.exit方法确保程序完整退出。
    sys.exit(app.exec_())
