from PySide6.QtCore import Qt, QEvent, QObject
from PySide6.QtWidgets import (QLabel, QMainWindow, QProgressBar, QPushButton, QWidget, QVBoxLayout)


class Ui_ProgressWindow(QObject):
    def setupUi(self, window: QMainWindow) -> None:
        central_widget = QWidget()
        vl = QVBoxLayout()

        self.label = QLabel("", central_widget)
        self.label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        label_font = self.label.font()
        label_font.setPointSize(14)
        self.label.setFont(label_font)
        self.progress_bar = QProgressBar(central_widget)
        self.progress_bar.setMaximum(0) # non-progress bar, too lazy to calculate steps
        self.folder_button = QPushButton("Open Output Folder", central_widget)
        self.folder_button.clicked.connect(window.openOutputFolderButtonClicked)

        vl.addWidget(self.label)
        vl.addWidget(self.progress_bar)
        vl.addWidget(self.folder_button)
        self.folder_button.hide()

        central_widget.setLayout(vl)
        window.setCentralWidget(central_widget)
        window.setMinimumSize(600, 100)
