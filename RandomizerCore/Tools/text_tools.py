import yaml


class Msbt:
    def __init__(self, data: bytes):
        self.data = data
        self.magic = self.readString(0x0, 8)
        self.endianness = 'little' if data[0x8] == 0xff else 'big'
        self.encoding = self.readInt(0xc, 1)
        self.version = self.readInt(0xd, 1)
        section_count = self.readInt(0xe, 2)
        self.file_size = self.readInt(0x12, 4)
        self.offset = 0x20
        labels = {}
        texts = []
        self.messages = {}

        for i in range(section_count):
            sect_magic = self.readString(self.offset, 4)
            sect_size = self.readInt(self.offset+0x4, 4)
            self.offset += 0x10

            if sect_magic == 'LBL1':
                labels = self.readLabels()
            elif sect_magic == 'TXT2':
                texts = self.readTexts(sect_size)
            
            self.offset += ((sect_size + 0xf) // 0x10) * 0x10
        
        if labels and texts:
            for lab in labels:
                self.messages[lab] = texts[labels[lab]]


    def readLabels(self):
        offset_count = self.readInt(self.offset, 4)
        table_offset = self.offset + 0x4
        labels = {}

        for i in range(offset_count):
            string_count = self.readInt(table_offset, 4)
            string_offset = self.offset + self.readInt(table_offset+0x4, 4)

            for i in range(string_count):
                string_length = self.readInt(string_offset, 1)
                start = string_offset + 0x1
                label = self.readString(start, string_length)
                label_index = self.readInt(start + string_length, 4)
                labels[label] = label_index
                string_offset += 0x1 + string_length + 0x4
            
            table_offset += 0x8
        
        return labels


    def readTexts(self, section_size):
        offset_count = self.readInt(self.offset, 4)
        table_offset = self.offset + 0x4
        texts = []

        for i in range(offset_count):
            string_offset = self.offset + self.readInt(table_offset, 4)
            table_offset += 0x4

            if (i + 1) < offset_count:
                end = (self.offset + self.readInt(table_offset, 4)) - 1
            else:
                end = (self.offset + section_size) - 1
            
            texts.append(self.readString(string_offset, end - string_offset))
        
        return texts


    def addMessage(self, label: str, msg: str, choices: tuple):
        if choices != None:
            choices_text = "\x0E\x01\0\a\0\0\0"
            for i,choice in enumerate(choices):
                choices_text += '\x0E\0\0\x04\0\0\0'
                if i == len(choices) - 1:
                    choices_text += '\x0E\x01\0\t\0\0\0'
                choices_text += choice
            msg += choices_text
        else:
            msg += '\x0E\x01\0\x04\0\0\0' # add confirmation box for the dialogue
        
        self.messages[label] = f'{msg}'


    def readInt(self, start, length):
        return int.from_bytes(self.data[start : start + length], self.endianness)


    def readString(self, start, length):
        result = b''
        index = start

        while index < start+length:
            result += self.data[index : index + 1]
            index += 1

        return str(result, 'latin-1')

romfs_dir = "C:/Users/Owen3/Desktop/The Legend of Zelda_ Link's Awakening v65536 (01006BB00C6F0800) (UPD)/romfs"
with open(f'{romfs_dir}/regionUS/USen/message/System.msbt', 'rb') as f:
    data = f.read()
    f.seek(0)
    text = Msbt(f.read())

text.addMessage('Custom', 'Hello bitch! LOOOOOL', ('Hey!', 'Fuck you!'))

with open('Test/Test.yml', 'w') as f:
    yaml.dump(text.messages, f, sort_keys=False, encoding='utf-8')
