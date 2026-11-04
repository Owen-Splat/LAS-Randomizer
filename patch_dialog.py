"""Qt front end for the deterministic LAS patch pipeline."""
from pathlib import Path
from PySide6 import QtCore, QtWidgets
from patch_pipeline import generate


class Worker(QtCore.QThread):
    completed = QtCore.Signal(object)
    failed = QtCore.Signal(str)
    log = QtCore.Signal(str)

    def __init__(self, options, parent):
        super().__init__(parent)
        self.options = options

    def run(self):
        try:
            self.completed.emit(generate(**self.options, log=self.log.emit))
        except Exception as exc:
            self.failed.emit(str(exc))


class PatchDialog(QtWidgets.QDialog):
    def __init__(self, config, manifest="", parent=None):
        super().__init__(parent)
        self.config = config
        self.worker = None
        self.setWindowTitle("Generate LAS from Archipelago patch")
        self.resize(820, 650)
        layout = QtWidgets.QVBoxLayout(self)
        label = QtWidgets.QLabel(
            "Open the .lasap file generated for your Archipelago player. The LAS generator uses its seed data; "
            "the normal Randomize button creates a separate standalone seed.\n\n"
            "Generate game builds a beta mod and runs its native checks before publishing it. "
            "Use a fresh save. A complete live playthrough is still being validated.")
        label.setWordWrap(True)
        layout.addWidget(label)
        form = QtWidgets.QFormLayout()
        layout.addLayout(form)
        self.fields = {}
        self.form_rows={}
        for key, title, value, kind in (
            ("manifest_path", "Archipelago patch", manifest, "file"),
            ("romfs", "Clean RomFS", config.get("romfs", ""), "directory"),
            ("exefs", "Matching ExeFS", config.get("exefs", ""), "directory"),
            ("output", "New output folder", str(Path(config.get("output_parent", ".")) / "LAS-AP-build"), "output"),
            ("backend", "Native LAS module", "", "directory"),
            ("save_id", "Test save identity", "", None),
        ):
            line = QtWidgets.QLineEdit(value)
            self.fields[key] = line
            row = QtWidgets.QHBoxLayout()
            row.addWidget(line)
            if kind:
                button = QtWidgets.QPushButton("Browse…")
                button.clicked.connect(lambda checked=False, line=line, kind=kind: self.browse(line, kind))
                row.addWidget(button)
            form.addRow(title, row)
            self.form_rows[key]=(row,form.itemAt(form.rowCount()-1,QtWidgets.QFormLayout.ItemRole.LabelRole).widget())
        self.mode = QtWidgets.QComboBox()
        self.mode.addItem('Generate Archipelago game (beta, verified build)','play')
        self.mode.addItem("Prepare patch inputs", "prepare")
        self.mode.addItem("Test LAS generator — diagnostic files only", "test")
        self.mode.addItem("Test native integration (copied saves only)", "native-development")
        self.mode.addItem("Test generated native checks — copied saves only", "native-checks")
        self.mode.addItem("Generate Archipelago mod — requires native module", "mod")
        form.addRow("Action", self.mode)
        self.mode.currentIndexChanged.connect(self.update_mode)
        self.world_visuals=QtWidgets.QCheckBox('Experimental shell ground models (copied-save test)')
        self.world_visuals.setToolTip('Uses original shell actors with assigned visual definitions. Further source-family gameplay validation is required.')
        layout.addWidget(self.world_visuals)
        self.run_button = QtWidgets.QPushButton("Run selected action")
        self.run_button.clicked.connect(self.start)
        layout.addWidget(self.run_button)
        self.status = QtWidgets.QLabel("")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        self.log = QtWidgets.QPlainTextEdit()
        self.log.setReadOnly(True)
        layout.addWidget(self.log)
        self.update_mode()

    def update_mode(self,*args):
        mode=self.mode.currentData()
        self.world_visuals.setVisible(mode=='native-development')
        for key,visible in (('backend',mode=='mod'),('save_id',mode!='play')):
            row,label=self.form_rows[key];label.setVisible(visible)
            for i in range(row.count()):
                widget=row.itemAt(i).widget()
                if widget:widget.setVisible(visible)

    def browse(self, line, kind):
        if kind == "file":
            value, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Choose patch", "", "LAS AP patch (*.lasap)")
        elif kind == "output":
            parent = QtWidgets.QFileDialog.getExistingDirectory(self, "Choose output parent")
            value = str(Path(parent) / "LAS-AP-build") if parent else ""
        else:
            value = QtWidgets.QFileDialog.getExistingDirectory(self, "Choose folder", line.text())
        if value:
            line.setText(value)

    def start(self):
        options = {key: line.text().strip() for key, line in self.fields.items()}
        if any(not options[key] for key in ("manifest_path", "romfs", "exefs", "output")):
            self.status.setText("Choose the patch file, RomFS, ExeFS and a new output folder.")
            return
        options.update(source=self.config["source"], mode=self.mode.currentData())
        options['world_visuals']=self.world_visuals.isChecked() and self.mode.currentData()=='native-development'
        self.run_button.setEnabled(False)
        self.status.setText("Working… please keep this window open.")
        self.log.clear()
        self.worker = Worker(options, self)
        self.worker.log.connect(self.log.appendPlainText)
        self.worker.failed.connect(lambda text: self.status.setText("Failed: " + text))
        self.worker.completed.connect(self.done_generation)
        self.worker.finished.connect(lambda: self.run_button.setEnabled(True))
        self.worker.start()

    def done_generation(self, report):
        self.status.setText(
            "Finished. Files saved to " + self.fields["output"].text() +
            (". Beta game ready; native checks passed. Open its seed.lasap with the LAS client." if report['mode']=='play' else
             ". Development build ready for isolated testing." if report["mode"]=="native-development" else
             ". Live gameplay validation remains required." if report["mode"] == "mod" else
             ". This output is preparation/diagnostic material, not a playable Archipelago mod."))

    def reject(self):
        if self.worker and self.worker.isRunning():
            self.status.setText("Wait for generation to finish before closing.")
            return
        super().reject()

    def closeEvent(self, event):
        if self.worker and self.worker.isRunning():
            event.ignore()
        else:
            event.accept()
