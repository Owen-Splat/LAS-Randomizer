# -*- coding: utf-8 -*-

################################################################################
## Form generated from reading UI file 'ui_progress_form.ui'
##
## Created by: Qt User Interface Compiler version 6.3.0
##
## WARNING! All changes made in this file will be lost when recompiling UI file!
################################################################################

from PySide6.QtCore import (QCoreApplication, QDate, QDateTime, QLocale,
    QMetaObject, QObject, QPoint, QRect,
    QSize, QTime, QUrl, Qt)
from PySide6.QtGui import (QBrush, QColor, QConicalGradient, QCursor,
    QFont, QFontDatabase, QGradient, QIcon,
    QImage, QKeySequence, QLinearGradient, QPainter,
    QPalette, QPixmap, QRadialGradient, QTransform)
from PySide6.QtWidgets import (QApplication, QLabel, QMainWindow, QProgressBar,
    QPushButton, QSizePolicy, QWidget)

class Ui_ProgressWindow(object):
    def setupUi(self, ProgressWindow):
        if not ProgressWindow.objectName():
            ProgressWindow.setObjectName(u"ProgressWindow")
        ProgressWindow.setWindowModality(Qt.ApplicationModal)
        ProgressWindow.resize(472, 125)
        ProgressWindow.setMinimumSize(QSize(472, 125))
        self.centralwidget = QWidget(ProgressWindow)
        self.centralwidget.setObjectName(u"centralwidget")
        self.progressBar = QProgressBar(self.centralwidget)
        self.progressBar.setObjectName(u"progressBar")
        self.progressBar.setGeometry(QRect(10, 82, 451, 31))
        self.progressBar.setValue(0)
        self.progressBar.setAlignment(Qt.AlignCenter)
        self.progressBar.setTextVisible(False)
        self.label = QLabel(self.centralwidget)
        self.label.setObjectName(u"label")
        self.label.setGeometry(QRect(10, 12, 451, 61))
        self.label.setAlignment(Qt.AlignCenter)
        self.openOutputFolder = QPushButton(self.centralwidget)
        self.openOutputFolder.setObjectName(u"openOutputFolder")
        self.openOutputFolder.setEnabled(True)
        self.openOutputFolder.setGeometry(QRect(180, 85, 121, 24))
        self.openOutputFolder.setCheckable(False)
        ProgressWindow.setCentralWidget(self.centralwidget)

        self.retranslateUi(ProgressWindow)

        QMetaObject.connectSlotsByName(ProgressWindow)
    # setupUi

    def retranslateUi(self, ProgressWindow):
        ProgressWindow.setWindowTitle(QCoreApplication.translate("ProgressWindow", u"ProgressWindow", None))
        self.progressBar.setFormat("")
        self.label.setText(QCoreApplication.translate("ProgressWindow", u"Getting ready...", None))
        self.openOutputFolder.setText(QCoreApplication.translate("ProgressWindow", u"Open output folder", None))
    # retranslateUi

