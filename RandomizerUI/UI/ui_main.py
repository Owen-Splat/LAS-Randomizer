from PySide6.QtCore import Qt, QEvent, QObject
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (QCheckBox, QLineEdit, QListWidget, QPushButton,
    QHBoxLayout, QVBoxLayout, QMainWindow, QTabWidget, QMessageBox, QMenuBar,
    QWidget, QLabel, QSpacerItem, QSizePolicy, QGroupBox, QFileDialog,
    QSpinBox)
from RandomizerUI.UI.custom_widgets import *
from RandomizerCore.randomizer_data import (LIGHT_STYLESHEET, DARK_STYLESHEET,
    DIAMONDBLACK_STYLESHEET, CHANGE_LOG, KNOWN_ISSUES, HELPFUL_TIPS, ABOUT_INFO,
    APP_VERSION, DESC_DEFS)


class Ui_MainWindow(QObject):
    def setupUi(self, window: QMainWindow) -> None:
        window.setWindowTitle(f"DEV BUILD - Link's Awakening Switch Randomizer v{APP_VERSION}")
        self.window = window
        self.theme = str('light')
        self.spacing = 175
        self.setupMenuBar()
        self.setupMainLayout()
        self.setLightMode()
        self.addOptionDescriptions()


    def setupMenuBar(self) -> None:
        menu_bar = QMenuBar()

        tm = menu_bar.addMenu("Theme")
        lb = tm.addAction('Light')
        lb.triggered.connect(self.setLightMode)
        tm.addSeparator()
        db = tm.addAction('Dark')
        db.triggered.connect(self.setDarkMode)
        tm.addSeparator()
        gb = tm.addAction('Diamond Black')
        gb.triggered.connect(self.setDiamondBlackMode)

        am = menu_bar.addMenu("About")
        nb = am.addAction("What's New")
        nb.triggered.connect(self.showChangelog)
        am.addSeparator()
        ib = am.addAction('Known Issues')
        ib.triggered.connect(self.showIssues)
        am.addSeparator()
        tb = am.addAction('Helpful Info')
        tb.triggered.connect(self.showTips)
        am.addSeparator()
        hb = am.addAction('Help')
        hb.triggered.connect(self.showAbout)

        self.window.setMenuBar(menu_bar)


    def setupMainLayout(self) -> None:
        central_widget = QWidget(self.window)
        vl = QVBoxLayout(central_widget)

        tab_widget = QTabWidget(central_widget)
        tab_widget.setObjectName('MainTabWidget')
        tab_widget.addTab(self.createSettingsTab(), 'Randomizer Settings')
        tab_widget.addTab(self.createStartingItemsTab(), 'Starting Items')
        tab_widget.addTab(self.createLocationsTab(), 'Locations')
        tab_widget.addTab(self.createLogicTab(), 'Logic')
        tab_widget.currentChanged.connect(self.window.tabChanged)
        vl.addWidget(tab_widget, 5)

        label = QLabel(central_widget)
        label.setObjectName('ExplanationText')
        label.setText('Hover over an option to see what it does')
        label.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        label.setFixedHeight(50)
        vl.addWidget(label)

        line = QLineEdit(central_widget)
        line.setObjectName('SettingsLine')
        line.setDisabled(True)
        vl.addWidget(line)

        hl = QHBoxLayout()
        button = QPushButton('Copy Settings', central_widget)
        button.setObjectName('CopyButton')
        hl.addWidget(button)
        button = QPushButton('Paste Settings', central_widget)
        button.setObjectName('PasteButton')
        hl.addWidget(button)
        button = QPushButton('Reset Settings', central_widget)
        button.setObjectName('ResetButton')
        hl.addWidget(button)
        button = QPushButton('Random Settings', central_widget)
        button.setObjectName('RandomSettingsButton')
        hl.addWidget(button)
        hl.addSpacerItem(QSpacerItem(1, 1, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum))
        button = QPushButton('Randomize', central_widget)
        button.setObjectName('RandomizeButton')
        hl.addWidget(button)
        vl.addLayout(hl)

        central_widget.setLayout(vl)
        self.window.setCentralWidget(central_widget)


    ########################################################################
    ## START ==> RANDOMIZER SETTINGS TAB
    ########################################################################
    def createSettingsTab(self) -> QWidget:
        tab = QWidget()
        vl = QVBoxLayout()

        hl = QHBoxLayout()
        label = QLabel('RomFS Path', tab)
        label.setMinimumWidth(80)
        romfs_line = QLineEdit(tab)
        romfs_line.setObjectName('RomfsLine')
        button = QPushButton('Browse', tab)
        button.clicked.connect(lambda: self.window.browseButton_Clicked(romfs_line.objectName()))
        hl.addWidget(label)
        hl.addWidget(romfs_line)
        hl.addWidget(button)
        vl.addLayout(hl, 1)

        hl = QHBoxLayout()
        label = QLabel('Output Path', tab)
        label.setMinimumWidth(80)
        output_line = QLineEdit(tab)
        output_line.setObjectName('OutputLine')
        button = QPushButton('Browse', tab)
        button.clicked.connect(lambda: self.window.browseButton_Clicked(output_line.objectName()))
        hl.addWidget(label)
        hl.addWidget(output_line)
        hl.addWidget(button)
        vl.addLayout(hl, 1)

        hl = QHBoxLayout()
        label = QLabel('Optional Seed', tab)
        label.setMinimumWidth(80)
        line = QLineEdit(tab)
        line.setObjectName('SeedLine')
        line.setPlaceholderText('Leave empty for random seed')
        button = QPushButton('New Seed', tab)
        button.clicked.connect(self.window.generateSeed)
        hl.addWidget(label)
        hl.addWidget(line)
        hl.addWidget(button)
        vl.addLayout(hl)

        tab_widget = QTabWidget(tab)
        tab_widget.addTab(self.createSettingsMainTab(), 'Main Settings')
        tab_widget.addTab(self.createSettingsAdvancedTab(), 'Advanced Settings')
        tab_widget.addTab(self.createSettingsWorldTab(), 'World Settings')
        tab_widget.addTab(self.createSettingsGameplayTab(), 'Gameplay Settings')
        tab_widget.addTab(self.createSettingsUserTab(), "User Settings")
        vl.addWidget(tab_widget)

        for c in tab.findChildren(QCheckBox):
            c.setFixedWidth(self.spacing)
        for c in tab.findChildren(RandoComboBox):
            c.setFixedWidth(self.spacing)

        tab.setLayout(vl)
        return tab


    def createSettingsMainTab(self) -> QWidget:
        tab = QWidget()
        vl = QVBoxLayout()

        group = QGroupBox('Main Checks', tab)
        group.setAlignment(Qt.AlignmentFlag.AlignCenter)
        chests_check = QCheckBox('Chests', group)
        gifts_check = QCheckBox('Free Gifts', group)
        trade_check = QCheckBox('Trade Quest', group)
        leaves_check = QCheckBox('Golden Leaves', group)
        hearts_check = QCheckBox('Heart Pieces', group)
        shells_check = QCheckBox('Seashells', group)
        misc_check = QCheckBox('Miscellaneous', group)
        mansion_box = RandoComboBox(group)
        mansion_box.addItems((
            'Seashell Mansion:  0',
            'Seashell Mansion:  5',
            'Seashell Mansion:  15',
            'Seashell Mansion:  30',
            'Seashell Mansion:  40',
            'Seashell Mansion:  50'
        ))
        shop_check = QCheckBox('Shop', group)
        boss_check = QCheckBox('Boss Drops', group)
        companions_check = QCheckBox("Companions", group)
        companions_check.setEnabled(False)
        hl = QHBoxLayout()
        hl.addWidget(chests_check)
        hl.addSpacerItem(self.createHorizontalSpacer())
        hl.addWidget(gifts_check)
        hl.addSpacerItem(self.createHorizontalSpacer())
        hl.addWidget(trade_check)
        gvl = QVBoxLayout()
        gvl.addLayout(hl)
        hl = QHBoxLayout()
        hl.addWidget(leaves_check)
        hl.addSpacerItem(self.createHorizontalSpacer())
        hl.addWidget(hearts_check)
        hl.addSpacerItem(self.createHorizontalSpacer())
        hl.addWidget(shells_check)
        gvl.addLayout(hl)
        hl = QHBoxLayout()
        hl.addWidget(misc_check)
        hl.addSpacerItem(self.createHorizontalSpacer())
        hl.addWidget(shop_check)
        hl.addSpacerItem(self.createHorizontalSpacer())
        hl.addWidget(mansion_box)
        gvl.addLayout(hl)
        hl = QHBoxLayout()
        hl.addWidget(boss_check)
        hl.addSpacerItem(self.createHorizontalSpacer())
        hl.addWidget(companions_check)
        hl.addSpacerItem(self.createHorizontalSpacer())
        padding = QLabel("", group)
        padding.setFixedWidth(self.spacing)
        hl.addWidget(padding)
        gvl.addLayout(hl)
        group.setLayout(gvl)
        vl.addWidget(group)

        group = QGroupBox('Dungeon Settings', tab)
        group.setAlignment(Qt.AlignmentFlag.AlignCenter)
        map_label = QLabel("Dungeon Maps: ", group)
        map_label.setFixedWidth(self.spacing)
        map_label.setAlignment(Qt.AlignmentFlag.AlignCenter | Qt.AlignmentFlag.AlignRight)
        map_box = RandoComboBox(group)
        map_box.hidden_prefix = "Dungeon Maps"
        map_box.addItems((
            "Start With",
            "Own Dungeon",
            "Any Dungeon",
            "Anywhere"
        ))
        compass_label = QLabel("Compasses: ", group)
        compass_label.setFixedWidth(self.spacing)
        compass_label.setAlignment(Qt.AlignmentFlag.AlignCenter | Qt.AlignmentFlag.AlignRight)
        compass_box = RandoComboBox(group)
        compass_box.hidden_prefix = "Compasses"
        compass_box.addItems((
            "Start With",
            "Own Dungeon",
            "Any Dungeon",
            "Anywhere"
        ))
        beak_label = QLabel("Stone Beaks: ", group)
        beak_label.setFixedWidth(self.spacing)
        beak_label.setAlignment(Qt.AlignmentFlag.AlignCenter | Qt.AlignmentFlag.AlignRight)
        beak_box = RandoComboBox(group)
        beak_box.hidden_prefix = "Stone Beaks"
        beak_box.addItems((
            "Start With",
            "Own Dungeon",
            "Any Dungeon",
            "Anywhere"
        ))
        key_label = QLabel("Small Keys: ", group)
        key_label.setFixedWidth(self.spacing)
        key_label.setAlignment(Qt.AlignmentFlag.AlignCenter | Qt.AlignmentFlag.AlignRight)
        key_box = RandoComboBox(group)
        key_box.hidden_prefix = "Small Keys"
        key_box.addItems((
            "Start With",
            "Own Dungeon",
            "Any Dungeon",
            "Anywhere"
        ))
        bkey_label = QLabel("Nightmare Keys: ", group)
        bkey_label.setFixedWidth(self.spacing)
        bkey_label.setAlignment(Qt.AlignmentFlag.AlignCenter | Qt.AlignmentFlag.AlignRight)
        bkey_box = RandoComboBox(group)
        bkey_box.hidden_prefix = "Nightmare Keys"
        bkey_box.addItems((
            "Start With",
            "Own Dungeon",
            "Any Dungeon",
            "Anywhere"
        ))
        inst_label = QLabel("Shuffle Instruments: ", group)
        inst_label.setFixedWidth(self.spacing)
        inst_label.setAlignment(Qt.AlignmentFlag.AlignCenter | Qt.AlignmentFlag.AlignRight)
        inst_box = RandoComboBox(group)
        inst_box.hidden_prefix = "Shuffle Instruments"
        inst_box.addItems((
            "Vanilla",
            "Dungeon Rewards",
            "Own Dungeon",
            "Any Dungeon",
            "Anywhere"
        ))
        ovl = QVBoxLayout()
        ohl = QHBoxLayout()
        ohl.addWidget(map_label)
        ohl.addWidget(map_box)
        ohl.addSpacerItem(self.createHorizontalSpacer())
        ohl.addWidget(key_label)
        ohl.addWidget(key_box)
        ovl.addLayout(ohl)
        ohl = QHBoxLayout()
        ohl.addWidget(compass_label)
        ohl.addWidget(compass_box)
        ohl.addSpacerItem(self.createHorizontalSpacer())
        ohl.addWidget(bkey_label)
        ohl.addWidget(bkey_box)
        ovl.addLayout(ohl)
        ohl = QHBoxLayout()
        ohl.addWidget(beak_label)
        ohl.addWidget(beak_box)
        ohl.addSpacerItem(self.createHorizontalSpacer())
        ohl.addWidget(inst_label)
        ohl.addWidget(inst_box)
        ovl.addLayout(ohl)
        group.setLayout(ovl)
        vl.addWidget(group)

        minigames_group = QGroupBox('Minigames', tab)
        minigames_group.setAlignment(Qt.AlignmentFlag.AlignCenter)
        dampe_check = QCheckBox("Dampe", minigames_group)
        rapids_check = QCheckBox('Rapids', minigames_group)
        fishing_check = QCheckBox('Fishing', minigames_group)
        trendy_check = QCheckBox('Trendy Game', minigames_group)
        trendy_check.setEnabled(False)
        gvl = QVBoxLayout()
        hl = QHBoxLayout()
        hl.addWidget(dampe_check)
        hl.addSpacerItem(self.createHorizontalSpacer())
        hl.addWidget(rapids_check)
        gvl.addLayout(hl)
        hl = QHBoxLayout()
        hl.addWidget(fishing_check)
        hl.addSpacerItem(self.createHorizontalSpacer())
        hl.addWidget(trendy_check)
        gvl.addLayout(hl)
        minigames_group.setLayout(gvl)
        ghl = QHBoxLayout()
        ghl.addWidget(minigames_group)
        ghl.addSpacerItem(QSpacerItem(self.spacing, 1, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed))

        group = QGroupBox('Special', tab)
        group.setAlignment(Qt.AlignmentFlag.AlignCenter)
        blup_check = QCheckBox('Blue Rupees', group)
        owls_box = RandoComboBox(group)
        owls_box.addItems((
            'Owl Gifts:  None',
            'Owl Gifts:  Overworld',
            'Owl Gifts:  Dungeons',
            'Owl Gifts:  All'
        ))
        gvl = QVBoxLayout()
        gvl.addWidget(blup_check)
        gvl.addWidget(owls_box)
        group.setLayout(gvl)
        ghl.addWidget(group)
        vl.addLayout(ghl)

        tab.setLayout(vl)
        return tab


    def createSettingsAdvancedTab(self) -> QWidget:
        tab = QWidget()
        vl = QVBoxLayout()

        group = QGroupBox("Race Mode Settings", tab)
        group.setAlignment(Qt.AlignmentFlag.AlignCenter)
        race_check = QCheckBox('Race Mode', group)
        race_check.setEnabled(False)
        required_dungeons_box = RandoComboBox(group)
        required_dungeons_box.addItems((
            'Required Dungeons:  0',
            'Required Dungeons:  1',
            'Required Dungeons:  2',
            'Required Dungeons:  3',
            'Required Dungeons:  4',
            'Required Dungeons:  5',
            'Required Dungeons:  6',
            'Required Dungeons:  7',
            'Required Dungeons:  8',
            'Required Dungeons:  9',
        ))
        ghl = QHBoxLayout()
        ghl.addWidget(race_check)
        ghl.addSpacerItem(self.createHorizontalSpacer())
        ghl.addWidget(required_dungeons_box)
        ghl.addSpacerItem(self.createHorizontalSpacer())
        padding = QLabel("", group)
        padding.setFixedWidth(self.spacing)
        ghl.addWidget(padding)
        group.setLayout(ghl)
        vl.addWidget(group)

        group = QGroupBox("Hint Settings", tab)
        group.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ghl = QHBoxLayout()
        padding = QLabel("", group)
        padding.setFixedWidth(self.spacing)
        ghl.addWidget(padding)
        ghl.addSpacerItem(self.createHorizontalSpacer())
        hint_text = QLabel("Nothing here yet :P", group)
        ft = hint_text.font()
        ft.setPointSize(14)
        hint_text.setFont(ft)
        ghl.addWidget(hint_text)
        ghl.addSpacerItem(self.createHorizontalSpacer())
        padding = QLabel("", group)
        padding.setFixedWidth(self.spacing)
        ghl.addWidget(padding)
        group.setLayout(ghl)
        vl.addWidget(group)

        group = QGroupBox("Output Settings", tab)
        group.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ghl = QHBoxLayout()
        spoiler_check = QCheckBox('Create Spoiler Log', group)
        unrandomizer_check = QCheckBox('Unrandomizer Mode', group)
        unrandomizer_check.setEnabled(False)
        ghl.addWidget(spoiler_check)
        ghl.addSpacerItem(self.createHorizontalSpacer())
        ghl.addWidget(unrandomizer_check)
        ghl.addSpacerItem(self.createHorizontalSpacer())
        padding = QLabel("", group)
        padding.setFixedWidth(self.spacing)
        ghl.addWidget(padding)
        group.setLayout(ghl)
        vl.addWidget(group)

        tab.setLayout(vl)
        return tab


    def createSettingsWorldTab(self) -> QWidget:
        tab = QWidget()
        vl = QVBoxLayout()

        group = QGroupBox('Global', tab)
        group.setAlignment(Qt.AlignmentFlag.AlignCenter)
        enemy_check = QCheckBox('Randomize Enemies', group)
        enemy_sizes_check = QCheckBox('Randomize Enemy Sizes', group)
        chests_box = RandoComboBox(group)
        chests_box.addItems((
            'Chest Types:  Default',
            'Chest Types:  Size',
            'Chest Types:  Texture + Size'
        ))
        hl = QHBoxLayout()
        hl.addWidget(enemy_check)
        hl.addSpacerItem(self.createHorizontalSpacer())
        hl.addWidget(enemy_sizes_check)
        hl.addSpacerItem(self.createHorizontalSpacer())
        hl.addWidget(chests_box)
        group.setLayout(hl)
        vl.addWidget(group)

        group = QGroupBox('Overworld', tab)
        group.setAlignment(Qt.AlignmentFlag.AlignCenter)
        kanalet_check = QCheckBox('Open Kanalet', group)
        mabe_check = QCheckBox('Open Mabe', group)
        mamu_check = QCheckBox('Open Mamu', group)
        bridge_check = QCheckBox('Completed Bridge', group)
        d2_check = QCheckBox('Classic D2', group)
        dungeons_check = QCheckBox('Shuffled Dungeons', group)
        consumable_check = QCheckBox('Consumable Drops', group)
        hl = QHBoxLayout()
        hl.addWidget(kanalet_check)
        hl.addSpacerItem(self.createHorizontalSpacer())
        hl.addWidget(mabe_check)
        hl.addSpacerItem(self.createHorizontalSpacer())
        hl.addWidget(mamu_check)
        ovl = QVBoxLayout()
        ovl.addLayout(hl)
        hl = QHBoxLayout()
        hl.addWidget(bridge_check)
        hl.addSpacerItem(self.createHorizontalSpacer())
        hl.addWidget(d2_check)
        hl.addSpacerItem(self.createHorizontalSpacer())
        hl.addWidget(dungeons_check)
        ovl.addLayout(hl)
        hl = QHBoxLayout()
        hl.addWidget(consumable_check)
        hl.addSpacerItem(self.createHorizontalSpacer())
        ovl.addLayout(hl)
        group.setLayout(ovl)
        vl.addWidget(group)

        group = QGroupBox('Logic', tab)
        group.setAlignment(Qt.AlignmentFlag.AlignCenter)
        pets_check = QCheckBox('Bad Pets', group)
        fishing_check = QCheckBox('Fast Fishing', group)
        bombs_check = QCheckBox('Shuffled Bombs', group)
        book_check = QCheckBox('Free Book', group)
        stalfos_check = QCheckBox('Fast Stalfos', group)
        powder_check = QCheckBox('Shuffled Powder', group)
        stealing_box = RandoComboBox(group)
        stealing_box.addItems((
            'Stealing:  Standard',
            'Stealing:  Always',
            'Stealing:  Never'
        ))
        ovl = QVBoxLayout()
        hl = QHBoxLayout()
        hl.addWidget(pets_check)
        hl.addSpacerItem(self.createHorizontalSpacer())
        hl.addWidget(fishing_check)
        hl.addSpacerItem(self.createHorizontalSpacer())
        hl.addWidget(bombs_check)
        ovl.addLayout(hl)
        hl = QHBoxLayout()
        hl.addWidget(book_check)
        hl.addSpacerItem(self.createHorizontalSpacer())
        hl.addWidget(stalfos_check)
        hl.addSpacerItem(self.createHorizontalSpacer())
        hl.addWidget(powder_check)
        ovl.addLayout(hl)
        hl = QHBoxLayout()
        hl.addWidget(stealing_box)
        hl.addSpacerItem(self.createHorizontalSpacer())
        hl.addWidget(QLabel("", group))
        hl.addSpacerItem(self.createHorizontalSpacer())
        hl.addWidget(QLabel("", group))
        ovl.addLayout(hl)
        group.setLayout(ovl)
        vl.addWidget(group)

        tab.setLayout(vl)
        return tab


    def createSettingsGameplayTab(self) -> QWidget:
        tab = QWidget()
        vl = QVBoxLayout()

        group = QGroupBox('Speed Options', tab)
        group.setAlignment(Qt.AlignmentFlag.AlignCenter)
        boss_check = QCheckBox('Boss Cutscenes', group)
        song_check = QCheckBox('Song Cutscenes', group)
        move_check = QCheckBox('Movement Speed', group)
        chest_check = QCheckBox('Chest Animations', group)
        key_check = QCheckBox('Key Animations', group)
        item_check = QCheckBox('Item Get Animations', group)
        item_check.setEnabled(False)
        hl = QHBoxLayout()
        hl.addWidget(boss_check)
        hl.addSpacerItem(self.createHorizontalSpacer())
        hl.addWidget(song_check)
        hl.addSpacerItem(self.createHorizontalSpacer())
        hl.addWidget(move_check)
        ovl = QVBoxLayout()
        ovl.addLayout(hl)
        hl = QHBoxLayout()
        hl.addWidget(chest_check)
        hl.addSpacerItem(self.createHorizontalSpacer())
        hl.addWidget(key_check)
        hl.addSpacerItem(self.createHorizontalSpacer())
        hl.addWidget(item_check)
        ovl.addLayout(hl)
        group.setLayout(ovl)
        vl.addWidget(group)

        ghl = QHBoxLayout()

        group = QGroupBox('Item Pool', tab)
        group.setAlignment(Qt.AlignmentFlag.AlignCenter)
        pool_box = RandoComboBox(group)
        pool_box.addItems((
            'Item Pool:  Standard',
            'Item Pool:  Reduced',
            'Item Pool:  Plentiful'
        ))
        pool_box.setEnabled(False)
        trap_box = RandoComboBox(group)
        trap_box.addItems((
            'Traps:  None',
            'Traps:  Few',
            'Traps:  Many',
            'Traps:  Trapsanity'
        ))
        ovl = QVBoxLayout()
        ovl.addWidget(pool_box)
        ovl.addWidget(trap_box)
        group.setLayout(ovl)
        ghl.addWidget(group)
        vl.addLayout(ghl)

        group = QGroupBox("Difficulty", tab)
        group.setAlignment(Qt.AlignmentFlag.AlignCenter)
        nice_bombs_check = QCheckBox("Nice Bombs", group)
        nice_hookshot_check = QCheckBox("Nice Hookshot", group)
        nice_rod_check = QCheckBox("Nice Magic Rod", group)
        # super_check = QCheckBox('Super Weapons', group)
        damage_box = RandoComboBox(group)
        damage_box.addItems((
            'Damage:  None',
            'Damage:  Normal',
            'Damage:  OHKO'
        ))
        ovl = QVBoxLayout()
        ohl = QHBoxLayout()
        ohl.addWidget(nice_bombs_check)
        ohl.addWidget(nice_hookshot_check)
        ovl.addLayout(ohl)
        ohl = QHBoxLayout()
        ohl.addWidget(nice_rod_check)
        ohl.addWidget(damage_box)
        ovl.addLayout(ohl)
        group.setLayout(ovl)
        ghl.addSpacerItem(self.createHorizontalSpacer())
        ghl.addWidget(group)

        tab.setLayout(vl)
        return tab


    def createSettingsUserTab(self) -> QWidget:
        tab = QWidget()
        vl = QVBoxLayout()

        group = QGroupBox("Fun", tab)
        group.setAlignment(Qt.AlignmentFlag.AlignCenter)
        gvl = QVBoxLayout()
        ghl = QHBoxLayout()
        music_box = RandoComboBox(group)
        music_box.addItems((
            "Music:  Vanilla",
            "Music:  Shuffled",
            "Music:  Removed"
        ))
        sound_box = QCheckBox("Randomize Sound Effects", group)
        sound_box.setEnabled(False)
        text_check = QCheckBox("Randomize Text", group)
        env_check = QCheckBox("Randomize Environments")
        ghl.addWidget(music_box)
        ghl.addSpacerItem(self.createHorizontalSpacer())
        ghl.addWidget(sound_box)
        ghl.addSpacerItem(self.createHorizontalSpacer())
        ghl.addWidget(text_check)
        gvl.addLayout(ghl)
        ghl = QHBoxLayout()
        ghl.addWidget(env_check)
        ghl.addSpacerItem(self.createHorizontalSpacer())
        gvl.addLayout(ghl)
        group.setLayout(gvl)
        vl.addWidget(group)

        group = QGroupBox("Tweaks", tab)
        group.setAlignment(Qt.AlignmentFlag.AlignCenter)
        gvl = QVBoxLayout()
        ghl = QHBoxLayout()
        beep_check = QCheckBox("Disable Low Health Beep", group)
        beep_check.setEnabled(False)
        controls_check = QCheckBox("360 Movement", group)
        blur_check = QCheckBox("Blur Removal", group)
        text_check = QCheckBox("Instant Text", group)
        text_check.setEnabled(False)
        acorn_check = QCheckBox("Disable Guardian Acorn", group)
        acorn_check.setEnabled(False)
        power_check = QCheckBox("Disable Piece of Power", group)
        power_check.setEnabled(False)
        ghl.addWidget(blur_check)
        ghl.addSpacerItem(self.createHorizontalSpacer())
        ghl.addWidget(text_check)
        ghl.addSpacerItem(self.createHorizontalSpacer())
        ghl.addWidget(controls_check)
        gvl.addLayout(ghl)
        ghl = QHBoxLayout()
        ghl.addWidget(beep_check)
        ghl.addSpacerItem(self.createHorizontalSpacer())
        ghl.addWidget(acorn_check)
        ghl.addSpacerItem(self.createHorizontalSpacer())
        ghl.addWidget(power_check)
        gvl.addLayout(ghl)
        group.setLayout(gvl)
        vl.addWidget(group)

        tab.setLayout(vl)
        return tab


    ## ==> END ##


    def createStartingItemsTab(self) -> QWidget:
        tab = QWidget()
        hl = QHBoxLayout()

        label = QLabel('Randomized Items', tab)
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ft = label.font()
        ft.setPointSize(12)
        label.setFont(ft)
        list_widget = QListWidget(tab)
        list_widget.setObjectName('RandomItemsList')
        list_widget.setSelectionMode(QListWidget.SelectionMode.ExtendedSelection)
        vl = QVBoxLayout()
        vl.addWidget(label)
        vl.addWidget(list_widget)
        hl.addLayout(vl, 2)

        inst_box = RandoComboBox(tab)
        for i in range(9):
            inst_box.addItem(f'Starting Instruments:  {i}')
        right_button = QPushButton('->', tab)
        right_button.setFixedSize(right_button.size() * 3)
        right_button.clicked.connect(self.window.moveListItemsRight)
        button_font = right_button.font()
        button_font.setPointSize(14)
        right_button.setFont(button_font)
        left_button = QPushButton('<-', tab)
        left_button.setFixedSize(left_button.size() * 3)
        left_button.clicked.connect(self.window.moveListItemsLeft)
        left_button.setFont(button_font)
        rupee_box = QSpinBox(tab)
        rupee_box.setPrefix('Rupees:  ')
        rupee_box.setMinimum(0)
        rupee_box.setMaximum(9999)
        ft = rupee_box.font()
        ft.setPointSize(11)
        rupee_box.setFont(ft)
        heartc_box = QSpinBox(tab)
        heartc_box.setPrefix("Containers:  ")
        heartc_box.setMinimum(0)
        heartc_box.setMaximum(9)
        heartc_box.setFont(ft)
        heartp_box = QSpinBox(tab)
        heartp_box.setPrefix("Pieces:  ")
        heartp_box.setMinimum(0)
        heartp_box.setMaximum(30) # -2 because of 2 HPs in trendy that are currently vanilla
        heartp_box.setFont(ft)
        heart_text = QLabel("Starting hearts:  3", tab)
        heart_text.setObjectName("StartingHeartsText")
        heart_text.setFixedHeight(30)
        heart_text.setFont(ft)
        heart_text.setAlignment(Qt.AlignmentFlag.AlignBottom)
        vl = QVBoxLayout()
        padding = QLabel("", tab)
        padding.setFixedWidth(self.spacing)
        vl.addWidget(padding)
        vl.addSpacerItem(self.createVerticalSpacer())
        vl.addWidget(inst_box, 1)
        vl.addSpacerItem(self.createVerticalSpacer())
        vl.addWidget(right_button, 4)
        vl.addWidget(left_button, 4)
        vl.addSpacerItem(self.createVerticalSpacer())
        vl.addWidget(rupee_box, 1)
        vl.addSpacerItem(self.createVerticalSpacer())
        vl.addWidget(heart_text, 1)
        vl.addWidget(heartc_box, 1)
        vl.addWidget(heartp_box, 1)
        vl.addSpacerItem(self.createVerticalSpacer())
        hl.addLayout(vl, 1)

        label = QLabel('Starting Items', tab)
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ft = label.font()
        ft.setPointSize(12)
        label.setFont(ft)
        list_widget = QListWidget(tab)
        list_widget.setObjectName('StartingItemsList')
        list_widget.setSelectionMode(QListWidget.SelectionMode.ExtendedSelection)
        vl = QVBoxLayout()
        vl.addWidget(label)
        vl.addWidget(list_widget)
        hl.addLayout(vl, 2)

        tab.setLayout(hl)
        return tab


    def createLocationsTab(self) -> QWidget:
        tab = QWidget()
        hl = QHBoxLayout()

        label = QLabel('Included Locations', tab)
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ft = label.font()
        ft.setPointSize(12)
        label.setFont(ft)
        list_widget = QListWidget(tab)
        list_widget.setObjectName('IncludedLocationsList')
        list_widget.setSelectionMode(QListWidget.SelectionMode.ExtendedSelection)
        vl = QVBoxLayout()
        vl.addWidget(label)
        vl.addWidget(list_widget)
        hl.addLayout(vl, 2)

        right_button = QPushButton('->', tab)
        right_button.setFixedSize(right_button.size() * 3)
        right_button.clicked.connect(self.window.moveListItemsRight)
        button_font = right_button.font()
        button_font.setPointSize(14)
        right_button.setFont(button_font)
        left_button = QPushButton('<-', tab)
        left_button.setFixedSize(left_button.size() * 3)
        left_button.clicked.connect(self.window.moveListItemsLeft)
        left_button.setFont(button_font)
        vl = QVBoxLayout()
        padding = QLabel("", tab)
        padding.setFixedWidth(self.spacing)
        vl.addWidget(padding)
        vl.addSpacerItem(self.createVerticalSpacer())
        vl.addWidget(right_button, 4)
        vl.addWidget(left_button, 4)
        vl.addSpacerItem(self.createVerticalSpacer())
        hl.addLayout(vl, 1)

        label = QLabel('Excluded Locations', tab)
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ft = label.font()
        ft.setPointSize(12)
        label.setFont(ft)
        list_widget = QListWidget(tab)
        list_widget.setObjectName('ExcludedLocationsList')
        list_widget.setSelectionMode(QListWidget.SelectionMode.ExtendedSelection)
        vl = QVBoxLayout()
        vl.addWidget(label)
        vl.addWidget(list_widget)
        hl.addLayout(vl, 2)

        tab.setLayout(hl)
        return tab


    def createLogicTab(self) -> QWidget:
        tab = QWidget()
        hl = QHBoxLayout()

        label = QLabel('Included Tricks', tab)
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ft = label.font()
        ft.setPointSize(12)
        label.setFont(ft)
        list_widget = QListWidget(tab)
        list_widget.setObjectName('IncludedLogicList')
        list_widget.setSelectionMode(QListWidget.SelectionMode.ExtendedSelection)
        vl = QVBoxLayout()
        vl.addWidget(label)
        vl.addWidget(list_widget)
        hl.addLayout(vl, 2)

        logic_box = RandoComboBox(tab)
        logic_box.addItems((
            'Preset:  Basic',
            'Preset:  Advanced',
            'Preset:  Glitched',
            'Preset:  Hell',
            'Preset:  No Logic',
            'Preset:  Custom',
        ))
        right_button = QPushButton('->', tab)
        right_button.setFixedSize(right_button.size() * 3)
        right_button.clicked.connect(self.window.moveListItemsRight)
        button_font = right_button.font()
        button_font.setPointSize(14)
        right_button.setFont(button_font)
        left_button = QPushButton('<-', tab)
        left_button.setFixedSize(left_button.size() * 3)
        left_button.clicked.connect(self.window.moveListItemsLeft)
        left_button.setFont(button_font)
        vl = QVBoxLayout()
        padding = QLabel("", tab)
        padding.setFixedWidth(self.spacing)
        vl.addWidget(padding)
        vl.addSpacerItem(self.createVerticalSpacer())
        vl.addWidget(logic_box)
        vl.addSpacerItem(self.createVerticalSpacer())
        vl.addWidget(right_button, 4)
        vl.addWidget(left_button, 4)
        vl.addSpacerItem(self.createVerticalSpacer())
        vl.addSpacerItem(self.createVerticalSpacer())
        hl.addLayout(vl, 1)

        label = QLabel('Excluded Tricks', tab)
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ft = label.font()
        ft.setPointSize(12)
        label.setFont(ft)
        list_widget = QListWidget(tab)
        list_widget.setObjectName('ExcludedLogicList')
        list_widget.setSelectionMode(QListWidget.SelectionMode.ExtendedSelection)
        vl = QVBoxLayout()
        vl.addWidget(label)
        vl.addWidget(list_widget)
        hl.addLayout(vl, 2)

        tab.setLayout(hl)
        return tab


    def createHorizontalSpacer(self) -> QSpacerItem:
        return QSpacerItem(1, 30, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)


    def createVerticalSpacer(self) -> QSpacerItem:
        return QSpacerItem(1, 1, QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Expanding)


    ########################################################################
    ## START ==> MENU BAR ITEMS
    ########################################################################
    def setLightMode(self) -> None:
        """Sets the app theme to Light"""

        self.theme = str('light')
        self.window.setStyleSheet(LIGHT_STYLESHEET)
        self.setExplanationText()


    def setDarkMode(self) -> None:
        """Sets the app them to Dark"""

        self.theme = str('dark')
        self.window.setStyleSheet(DARK_STYLESHEET)
        self.setExplanationText()


    def setDiamondBlackMode(self) -> None:
        """Sets the app theme to Godot"""

        self.theme = str('diamond-black')
        self.window.setStyleSheet(DIAMONDBLACK_STYLESHEET)
        self.setExplanationText()


    def setExplanationText(self, text: str = '') -> None:
        if not text:
            text = "Hover over an option to see what it does"
        label = self.findLabel("ExplanationText")
        label.setText(text)

        match self.theme:
            case 'light':
                if text.startswith("Hover"):
                    label.setStyleSheet('color: rgb(80, 80, 80);')
                else:
                    label.setStyleSheet('color: black;')
            case _:
                if text.startswith("Hover"):
                    label.setStyleSheet('color: rgb(175, 175, 175);')
                else:
                    label.setStyleSheet('color: white;')


    def showChangelog(self) -> None:
        """Display new window listing the new features and bug fixes"""
        self.createMessageWindow("Changelog", CHANGE_LOG, with_scroll=True)


    def showUserError(self, msg) -> None:
        """Display new window to let the user know what went wrong - missing paths, bad logic, etc."""
        self.createMessageWindow("Error", msg)


    def showIssues(self) -> None:
        """Display new window listing the currently known issues"""
        self.createMessageWindow("Known Issues", KNOWN_ISSUES)


    def showTips(self) -> None:
        """Display new window listing helpful tips for the player"""
        self.createMessageWindow("Helpful Tips", HELPFUL_TIPS)


    def showAbout(self) -> None:
        """Display new window with information about the randomizer"""
        self.createMessageWindow(self.window.windowTitle(), ABOUT_INFO)


    def createMessageWindow(self, title: str, text: str, with_scroll: bool = False) -> None:
        """Creates a new QMessageBox with the given window title and text

        This also matches the current Light/Dark Mode"""

        box = RandoHelpWindow(title, text, with_scroll)

        match self.theme:
            case 'dark':
                box.setStyleSheet(box.styleSheet() + DARK_STYLESHEET)
            case 'diamond-black':
                box.setStyleSheet(box.styleSheet() + DIAMONDBLACK_STYLESHEET)
            case _:
                box.setStyleSheet(box.styleSheet() + LIGHT_STYLESHEET)

        box.exec()

    ## MENU BAR ITEMS <== END


    ########################################################################
    ## START ==> MAIN WINDOW CALLS
    ########################################################################
    def openFileBrowser(self, dir: str) -> str:
        return QFileDialog.getExistingDirectory(self.window, 'Select Folder', dir)


    def getCurrentTabName(self) -> str:
        tab_widget: QTabWidget = self.window.findChild(QTabWidget, 'MainTabWidget')
        return tab_widget.tabText(tab_widget.currentIndex())


    def findCheckBox(self, name: str) -> QCheckBox:
        check = self.window.findChild(QCheckBox, name)
        if check is None: # search by text if no name matches
            for c in self.window.findChildren(QCheckBox):
                if c.text() == name:
                    check = c
                    break
        return check


    def findComboBox(self, name: str) -> RandoComboBox:
        box = self.window.findChild(RandoComboBox, name)
        if box is None: # search by prefix if no name matches
            for b in self.window.findChildren(RandoComboBox):
                b: RandoComboBox
                if b.hidden_prefix == name:
                    box = b
                    break
                else:
                    if b.currentText().startswith(name):
                        box = b
                        break
        return box


    def findLabel(self, name: str) -> QLabel:
        return self.window.findChild(QLabel, name)


    def findLineEdit(self, name: str) -> QLineEdit:
        return self.window.findChild(QLineEdit, name)


    def findListWidget(self, name: str) -> QListWidget:
        return self.window.findChild(QListWidget, name)


    def findPushButton(self, name: str) -> QPushButton:
        return self.window.findChild(QPushButton, name)


    def findSpinBox(self, name: str) -> QSpinBox:
        box = self.window.findChild(QSpinBox, name)
        if box is None: # search by prefix if no name matches
            for b in self.window.findChildren(QSpinBox):
                if b.prefix().startswith(name):
                    box = b
                    break
        return box


    def findChild(self, name: str) -> QWidget:
        return self.window.findChild(QWidget, name)


    def getSettingsDict(self) -> dict:
        settings = {}

        for c in self.window.findChildren(QCheckBox):
            settings[c.text()] = c.isChecked()

        for r in self.window.findChildren(RandoComboBox):
            if r.hidden_prefix:
                settings[r.hidden_prefix] = r.currentText()
            else:
                k,v = r.currentText().split(':')
                settings[k.strip()] = v.strip()

        for s in self.window.findChildren(QSpinBox):
            k = s.prefix().split(':')[0]
            settings[k] = s.value()

        # combobox value is outputted as a string, convert to int if possible so it looks cleaner
        for k,v in settings.items():
            if str(v).isdigit():
                settings[k] = int(v)

        return settings


    def getSettingsWidgets(self) -> list:
        widgets = []
        exclusions = ()

        for c in self.window.findChildren(QCheckBox):
            if c.text() not in exclusions:
                widgets.append(c)
        for r in self.window.findChildren(RandoComboBox):
            widgets.append(r)
        for s in self.window.findChildren(QSpinBox):
            widgets.append(s)

        return widgets


    def setWidgetSetting(self, k, v) -> None:
        check = self.findCheckBox(k)
        if check is not None:
            check.setChecked(v)
            return

        box = self.findComboBox(k)
        if box is None:
            box = self.findComboBox(f"{k}:  ")
        if box is not None:
            items = [box.itemText(i) for i in range(box.count())]
            if box.hidden_prefix:
                text = str(v)
            else:
                text = f"{k}:  {v}"
            try:
                index = items.index(text)
            except ValueError:
                pass
            else:
                box.setCurrentIndex(index)

        box = self.findSpinBox(k)
        if box is not None:
            box.setValue(v)

    ## MAIN WINDOW CALLS <== END


    ########################################################################
    ## START ==> EVENT FILTERS
    ########################################################################
    def addOptionDescriptions(self) -> None:
        """Iterates through the settings and adds the descriptions from Info/Descriptions.yml"""

        for option in DESC_DEFS:
            option = option.replace('_', ' ')
            widget = self.findCheckBox(option)
            if widget is None:
                widget = self.findSpinBox(option)
                if widget is None:
                    widget = self.findComboBox(option)
            if widget is not None:
                widget.installEventFilter(self)


    def eventFilter(self, source: QWidget, event):
        match event.type():
            case QEvent.Type.HoverEnter:
                desc_entry = ""
                match source:
                    case QCheckBox():
                        desc_entry = source.text()
                    case QSpinBox():
                        desc_entry = source.prefix().split(':')[0]
                    case RandoComboBox():
                        if source.hidden_prefix:
                            desc_entry = source.hidden_prefix
                        else:
                            desc_entry = source.currentText().split(':')[0]
                if desc_entry:
                    desc_entry = desc_entry.replace(' ', '_')
                    self.setExplanationText(DESC_DEFS[desc_entry])
            case QEvent.Type.HoverLeave:
                self.setExplanationText()

        return QWidget.eventFilter(self, source, event)

    ## EVENT FILTERS <== END


    def setupSignals(self) -> None:
        """Connects all necessary widget signals to their respective functions"""

        # run specific signals first
        self.findLineEdit("SeedLine").textChanged.connect(self.window.updateSettingsString)
        self.findPushButton("CopyButton").clicked.connect(lambda x: self.window.clipboard.setText(self.findLineEdit("SettingsLine").text()))
        self.findPushButton("PasteButton").clicked.connect(self.window.pasteSettingsString)
        self.findPushButton("ResetButton").clicked.connect(self.window.applyDefaults)
        self.findPushButton("RandomSettingsButton").clicked.connect(self.window.randomizeSettings)
        self.findPushButton("RandomizeButton").clicked.connect(self.window.randomizeButton_Clicked)
        self.findComboBox("Seashell Mansion").currentIndexChanged.connect(self.window.updateSeashells)
        self.findComboBox("Owl Gifts").currentIndexChanged.connect(self.window.updateOwls)
        self.findSpinBox("Pieces:  ").valueChanged.connect(self.window.updateStartingHeartsText)
        self.findSpinBox("Containers:  ").valueChanged.connect(self.window.updateStartingHeartsText)
        self.findCheckBox("Race Mode").clicked.connect(self.window.toggleRaceMode)

        # update settings string afterwards
        for check in self.window.findChildren(QCheckBox):
            check.clicked.connect(lambda checked=False, cb=check: self.window.checkClicked(cb))
            check.clicked.connect(self.window.updateSettingsString)

        for box in self.window.findChildren(QSpinBox):
            box.valueChanged.connect(self.window.updateSettingsString)

        for box in self.window.findChildren(RandoComboBox):
            box.currentIndexChanged.connect(self.window.updateSettingsString)
