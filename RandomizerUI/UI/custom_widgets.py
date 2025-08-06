from PySide6.QtWidgets import QComboBox, QListWidgetItem, QMainWindow, QMessageBox, QWidget, QVBoxLayout, QScrollArea, QLabel
from re import split


class RandoListItem(QListWidgetItem):
    """Custom QListWidgetItem that sorts alphanumerically"""

    def __lt__(self, other: QListWidgetItem) -> bool:
        """Override of the sorting method to implement custom sort"""

        convert = lambda text: int(text) if text.isdigit() else text
        alphanum_key = lambda key: [convert(c) for c in split('([0-9]+)', key)]
        result = sorted([self.text(), other.text()], key=alphanum_key)
        return self.text() == result[0]



class RandoComboBox(QComboBox):
    """Custom QComboBox that resets the explanation text when the drop-down popup is closed"""

    def hidePopup(self):
        QComboBox.hidePopup(self)
        if isinstance(self.window(), QMainWindow):
            self.window().ui.setExplanationText()



class RandoHelpWindow(QMessageBox):
    def __init__(self, title: str, text: str, with_scroll: bool = False):
        super(RandoHelpWindow, self).__init__()
        self.setWindowTitle(title)
        self.content = QWidget()
        vl = QVBoxLayout(self.content)
        if with_scroll:
            vl.addWidget(QLabel(text, self))
            scroll = QScrollArea(self)
            scroll.setWidgetResizable(True)
            scroll.setWidget(self.content)
            self.layout().addWidget(scroll, 0, 0, 1, 1)
            self.setStyleSheet("QScrollArea{min-width:600 px; min-height: 450px}")
        else:
            self.setText(text)
