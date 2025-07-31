from PySide6.QtCore import Signal
from PySide6.QtWidgets import QComboBox, QListWidgetItem
from re import split


class RandoListWidget(QListWidgetItem):
    """Custom QListWidgetItem to sort locations alphanumerically"""

    def __lt__(self, other: QListWidgetItem) -> bool:
        """Override of the sorting method to implement custom sort"""

        convert = lambda text: int(text) if text.isdigit() else text
        alphanum_key = lambda key: [convert(c) for c in split('([0-9]+)', key)]
        result = sorted([self.text(), other.text()], key=alphanum_key)
        return self.text() == result[0]



class RandoComboBox(QComboBox):
    """Custom QComboBox to emit a signal when the popup is closed, even when the user clicks off"""
    popup_closed = Signal()

    def hidePopup(self):
        QComboBox.hidePopup(self)
        self.popup_closed.emit()
