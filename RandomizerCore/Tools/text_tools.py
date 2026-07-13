from lms.message.msbtio import read_msbt as readMSBT
from lms.message.msbtio import write_msbt as writeMSBT
from lms.message.msbtentry import MSBTEntry
from pathlib import Path
import re, copy


class TextFile:
    def __init__(self, path: Path):
        with open(path, 'rb') as f:
            self.msbt = readMSBT(f.read())


    def getEntry(self, entry_name: str) -> MSBTEntry:
        entry = self.msbt.get_entry_by_name(entry_name)
        return entry


    def copyEntry(self, entry_name: str, new_name: str) -> None:
        entry = copy.deepcopy(self.msbt.get_entry_by_name(entry_name))
        entry.name = new_name
        self.msbt.add_entry(entry)


    def makeEntryWaitForInput(self, entry_name: str) -> None:
        for entry in self.msbt.entries:
            if entry.name == entry_name:
                # remove existing tags since some appear to not be supported by this library?
                if ']' in entry.message.text:
                    clean_text = re.sub(r'\[.*?\]', '', entry.message.text)
                    entry.message.text = clean_text

                # add tag so that the text waits for user input before going away
                entry.message.text += "[1:4]"
                break


    def write(self, output_path: Path, file_name: str) -> None:
        output_path.mkdir(parents=True, exist_ok=True)
        with open(output_path / file_name, 'wb') as f:
            f.write(writeMSBT(self.msbt))


    def getTextDict(self) -> dict:
        text_entries = {}
        for e in self.msbt.entries:
            text_entries[e.name] = e.message.text
        return text_entries
