from PySide6.QtWidgets import QComboBox, QListWidgetItem, QMainWindow
from re import split


class RandoListWidget(QListWidgetItem):
    """Custom QListWidgetItem that sorts locations alphanumerically"""

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
