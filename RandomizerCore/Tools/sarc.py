def readInt(data, start, length, signed=False):
    return int.from_bytes(data[start : start + length], "little", signed=signed)


def calculate_hash(filename):
    hash = 0
    for byte in bytes(filename, "utf-8"):
        hash = hash * 101 + byte
    return hash & 0xFFFFFFFF


class SARC:
    """Nintendo's trustworthy archive format. Not a complete parser.
    
    We only need to export and reimport a single file so that's all this does currently"""

    def __init__(self, data: bytes) -> None:
        if data[:4] != b'SARC':
            raise TypeError("File is not of type SARC!")

        # we don't care about most of the header since most is the same across all sarc files
        self.data = data
        self.data_offset = readInt(data, 0xC, 4)

        # SFAT section, same deal, we only care to grab file offsets
        number_of_files = readInt(data, 0x1a, 2)
        offset = 0x20
        self.fat_entries: list[FAT] = []
        for i in range(number_of_files):
            self.fat_entries.append(FAT(data[offset : offset + 0x10]))
            offset += 0x10


    def getFileData(self, filename: str) -> bytes:
        namehash = calculate_hash(filename)
        fats = [f for f in self.fat_entries if f.hash == namehash]
        if not fats:
            return ValueError("File not found! Make sure you include the path to the file!")
        entry = fats[0]
        start = self.data_offset + entry.data_start
        end = self.data_offset + entry.data_end
        return self.data[start : end]


    def replaceFile(self, filename: str, filedata: bytes) -> None:
        namehash = calculate_hash(filename)
        fats = [f for f in self.fat_entries if f.hash == namehash]
        if not fats:
            return ValueError("File not found! Make sure you include the path to the file!")
        entry = fats[0]

        # replace the file data
        old_data = self.data[self.data_offset + entry.data_start : self.data_offset + entry.data_end]
        self.data = self.data.replace(old_data, filedata)

        # shift offsets
        normal_size = entry.data_end - entry.data_start
        shift_amount = len(filedata) - normal_size
        offset = 0x20
        for fentry in self.fat_entries:
            if fentry.data_start >= entry.data_start:
                if (fentry.data_start != entry.data_start):
                    fentry.data_start += shift_amount
                fentry.data_end += shift_amount
                new_offsets_data = fentry.data_start.to_bytes(4, "little") + fentry.data_end.to_bytes(4, "little")
                self.data = self.data.replace(self.data[offset + 0x8 : offset + 0x10], new_offsets_data, 1)
            offset += 0x10


class FAT:
    def __init__(self, data) -> None:
        self.hash = readInt(data, 0, 4)
        self.attributes = readInt(data, 0x4, 4)
        self.data_start = readInt(data, 0x8, 4)
        self.data_end = readInt(data, 0xC, 4)
