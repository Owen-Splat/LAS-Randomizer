from RandomizerCore.Tools.event_tools import readFlow, writeFlow
from RandomizerCore.Tools.oead_tools import readSheet, writeSheet, SARC
from RandomizerCore.Tools.text_tools import TextFile
from RandomizerCore.Tools.leb import Room
from RandomizerCore.Tools.lvb import Level
from pathlib import Path


class FileManager:
    def __init__(self, mod_generator) -> None:
        self.parent = mod_generator
        self.out_files = set()


    def readFile(self, file_name: str, return_path=False):
        """Reads the given file from the rom path, or the output path if it already exists"""

        dir = self.getRelativeDir(file_name)

        file_path = str(self.parent.romfs_dir / dir / file_name)
        if file_name not in self.out_files:
            file_path = str(self.parent.rom_path / dir / file_name)

        if return_path:
            return file_path

        if file_name.endswith('bfevfl'):
            return readFlow(file_path)
        elif file_name.endswith('gsheet'):
            return readSheet(file_path)
        elif file_name.endswith('arc'):
            return SARC(file_path)

        with open(file_path, 'rb') as f:
            file_data = f.read()

        if file_name.endswith('leb'):
            return Room(file_data)
        elif file_name.endswith('lvb'):
            return Level(file_data)


    def writeFile(self, file_name: str, data) -> None:
        """Writes the file to the output and updates the progress bar"""

        if not self.parent.thread_active:
            return

        dir = self.getRelativeDir(file_name)
        if dir is not None:
            file_path = self.parent.romfs_dir / dir / file_name
        else:
            file_path = self.parent.exefs_dir / file_name

        file_path.parent.mkdir(parents=True, exist_ok=True)

        if file_name.endswith('bfevfl'):
            writeFlow(file_path, data)
        elif file_name.endswith('gsheet'):
            writeSheet(file_path, data)
        elif file_name.endswith(('leb', 'lvb', 'arc')):
            with open(file_path, 'wb') as f:
                f.write(data.repack())
        else:
            with open(file_path, 'wb') as f:
                f.write(data)

        self.out_files.add(file_name)
        self.parent.progress_value += 1
        self.parent.progress_update.emit(self.parent.progress_value)


    def getRelativeDir(self, file_name):
        """Reads the file_name to determine the directory relative to the romfs"""

        if file_name.endswith('leb'):
            dir = Path("region_common") / "level" / file_name.split("_")[0]
        elif file_name.endswith('lvb'):
            dir = Path("region_common") / "level" / file_name.split(".")[0]
        elif file_name.endswith('gsheet'):
            dir = Path("region_common") / "datasheets"
        elif file_name.endswith('bfevfl'):
            dir = Path("region_common") / "event"
        elif file_name.endswith('arc'):
            dir = Path("region_common") / "ui"
        else:
            return None

        return dir


    def getAllTextFiles(self, file_name: str) -> list[tuple[Path, TextFile]]:
        """Gets all text files matching file_name from either the rom path or output directories

        Returns a list of full paths to the files"""

        text_files = []
        regions = ("regionCN", "regionEU", "regionJP", "regionKR", "regionTW", "regionUS")

        for region in regions:
            region_path: Path = self.parent.rom_path / region
            subdirs = [item for item in region_path.iterdir() if item.is_dir()]
            for subdir in subdirs:
                if subdir.name == "common":
                    continue
                relative_path = Path(f"{region}/{subdir.name}/message")
                if Path(self.parent.romfs_dir / relative_path / file_name).exists():
                    text_files.append((relative_path, TextFile(self.parent.romfs_dir / relative_path / file_name)))
                else:
                    text_files.append((relative_path, TextFile(self.parent.rom_path / relative_path / file_name)))

        return text_files


    def writeTextFile(self, relative_path: Path, file_name: str, text_file: TextFile) -> None:
        """Writes the text file to the relative path with the given file name"""

        text_file.write(self.parent.romfs_dir / relative_path, file_name)
        self.parent.progress_value += 1
        self.parent.progress_update.emit(self.parent.progress_value)
