"""Launch the original LAS randomizer with an Archipelago patch import menu."""
import argparse
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent


def load_config(path):
    path = Path(path).resolve()
    config = json.loads(path.read_text(encoding="utf-8-sig"))
    for key in ("romfs", "exefs", "output_parent", "source", "gui_source"):
        if config.get(key):
            value = Path(config[key])
            config[key] = str((value if value.is_absolute() else path.parent / value).resolve())
    return config


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", nargs="?")
    parser.add_argument("--config", type=Path, default=ROOT / "local_setup.json")
    parser.add_argument("--smoke-test", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    config = load_config(args.config)
    from patch_pipeline import check_source
    source = check_source(config["source"])
    # The AP backend stays pinned; the standalone window uses the separately
    # tested category-enabled source so its Randomize button has real support.
    gui_source = Path(config.get("gui_source", str(source))).resolve()
    if not (gui_source / "RandomizerUI/main_window.py").is_file():
        raise ValueError("The configured standalone GUI source is missing")
    # Original LAS derives resources from argv[0]. Keep its source untouched.
    sys.path.insert(0, str(gui_source))
    sys.argv[0] = str(gui_source / "randomizer.py")
    from PySide6 import QtCore, QtGui, QtWidgets
    from RandomizerCore.Paths import randomizer_paths
    # User settings belong to this integration, not the reference source.
    settings = ROOT / ("build/ui-standalone" if gui_source != source else "build/ui")
    settings.mkdir(parents=True, exist_ok=True)
    randomizer_paths.SETTINGS_PATH = str(settings / "settings.txt")
    randomizer_paths.LOGS_PATH = str(settings / "log.txt")
    import RandomizerUI.main_window as original
    from patch_dialog import PatchDialog
    # Disable source self-updates: the adapter requires a pinned source version.
    class PinnedUpdate(original.UpdateProcess):
        def run(self):
            self.can_update.emit(False)
    original.UpdateProcess = PinnedUpdate
    original.MainWindow.checkLogic = lambda self: None
    app = QtWidgets.QApplication([])
    if not QtGui.QFontDatabase.families() and os.name == "nt":
        QtGui.QFontDatabase.addApplicationFont(str(Path(os.environ.get("WINDIR", "C:/Windows")) / "Fonts/segoeui.ttf"))
        app.setFont(QtGui.QFont("Segoe UI", 10))
    window = original.MainWindow()
    # Upstream fixes the entire window at 780x650 and positions controls
    # absolutely. Preserve their layout inside a scrollable, resizable shell.
    content = window.takeCentralWidget()
    content.setMinimumSize(780, 625)
    scroll = QtWidgets.QScrollArea(window)
    scroll.setWidgetResizable(True)
    scroll.setWidget(content)
    window.setCentralWidget(scroll)
    window.setMaximumSize(16777215, 16777215)
    window.setMinimumSize(480, 360)
    window.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
    window.setWindowFlag(QtCore.Qt.WindowMaximizeButtonHint, True)
    window.resize(820, 740)
    window.setWindowTitle(window.windowTitle() + " — Archipelago patch tools")
    window.ui.lineEdit.setText(config.get("romfs", ""))
    window.ui.lineEdit_2.setText(config.get("output_parent", ""))
    menu = window.menuBar().addMenu("Archipelago")
    action = menu.addAction("Generate from Archipelago patch (.lasap)…")
    def open_patch(manifest=""):
        dialog = PatchDialog(config, manifest, window)
        dialog.exec()
    action.triggered.connect(lambda: open_patch())
    notice = QtWidgets.QLabel("Archipelago seeds: use the Archipelago menu to open your .lasap patch.")
    window.statusBar().addWidget(notice)
    window.show()
    if args.manifest:
        QtCore.QTimer.singleShot(0, lambda: open_patch(args.manifest))
    if args.smoke_test:
        window.resize(1000, 800)
        app.processEvents()
        assert window.width() == 1000 and window.height() == 800
        window.resize(600, 450)
        app.processEvents()
        assert scroll.verticalScrollBar().maximum() > 0
        assert scroll.horizontalScrollBar().maximum() > 0
        scroll.ensureWidgetVisible(window.ui.randomizeButton)
        app.processEvents()
        assert scroll.verticalScrollBar().value() > 0
        print("PASS: Window resizes and scrolls to the bottom controls.")
        from RandomizerUI import settings_manager
        for name in ("seashellsCheck", "trendyCheck", "shopCheck"):
            control = getattr(window.ui, name)
            assert control.isEnabled() and control.isCheckable(), name
            assert not control.font().strikeOut(), name
            control.setChecked(True)
        selected = settings_manager.loadRandomizerSettings(window, "gui-smoke")
        for key in ("randomize-shells", "randomize-trendy", "randomize-shop"):
            assert selected[key], key
        print("PASS: Shells, Trendy and Shop controls are selectable and feed generation settings.")
        dialog = PatchDialog(config, "", window)
        assert dialog.world_visuals.isHidden()
        dialog.mode.setCurrentIndex(dialog.mode.findData('native-development'))
        assert not dialog.world_visuals.isHidden()
        dialog.mode.setCurrentIndex(dialog.mode.findData('play'))
        assert dialog.world_visuals.isHidden()
        print('PASS: Experimental world-visual control is restricted to copied-save test mode.')
        dialog.show()
        QtCore.QTimer.singleShot(300, dialog.close)
        QtCore.QTimer.singleShot(600, window.close)
        QtCore.QTimer.singleShot(800, app.quit)
    return app.exec()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        import traceback
        traceback.print_exc()
        sys.exit(1)
