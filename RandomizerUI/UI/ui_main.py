from PySide6.QtCore import Qt, QEvent, QObject
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
        window.setWindowTitle(f"Link's Awakening Switch Randomizer v{APP_VERSION}")
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
        # tab_widget.addTab(self.createPatchesTab(), 'Patches')
        tab_widget.addTab(self.createCosmeticsTab(), 'Cosmetics')
        tab_widget.currentChanged.connect(self.window.tabChanged)
        vl.addWidget(tab_widget, 5)

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
        tab_widget.addTab(self.createSettingsWorldTab(), 'World Settings')
        tab_widget.addTab(self.createSettingsGameplayTab(), 'Gameplay Settings')
        vl.addWidget(tab_widget)

        label = QLabel(tab)
        label.setObjectName('ExplanationText')
        label.setText('Hover over an option to see what it does')
        label.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        label.setFixedHeight(50)
        vl.addWidget(label)

        line = QLineEdit(tab)
        line.setObjectName('SettingsLineEdit')
        vl.addWidget(line)

        hl = QHBoxLayout()
        button = QPushButton('Copy Settings', tab)
        button.setObjectName('CopyButton')
        hl.addWidget(button)
        button = QPushButton('Paste Settings', tab)
        button.setObjectName('PasteButton')
        hl.addWidget(button)
        button = QPushButton('Reset Settings', tab)
        button.setObjectName('ResetButton')
        hl.addWidget(button)
        button = QPushButton('Random Settings', tab)
        button.setObjectName('RandomSettingsButton')
        hl.addWidget(button)
        hl.addSpacerItem(QSpacerItem(1, 1, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum))
        button = QPushButton('Randomize', tab)
        button.setObjectName('RandomizeButton')
        hl.addWidget(button)
        vl.addLayout(hl)

        for c in tab.findChildren(QCheckBox):
            c.setFixedWidth(self.spacing)
        for c in tab.findChildren(RandoComboBox):
            c.setFixedWidth(self.spacing)

        tab.setLayout(vl)
        return tab


    def createSettingsMainTab(self) -> QWidget:
        tab = QWidget()
        vl = QVBoxLayout()

        group = QGroupBox('Items', tab)
        group.setAlignment(Qt.AlignmentFlag.AlignCenter)
        chests_check = QCheckBox('Chests', group)
        chests_check.setObjectName('ChestsCheck')
        gifts_check = QCheckBox('Free Gifts', group)
        gifts_check.setObjectName('GiftsCheck')
        trade_check = QCheckBox('Trade Quest', group)
        trade_check.setObjectName('TradeCheck')
        leaves_check = QCheckBox('Golden Leaves', group)
        leaves_check.setObjectName('LeavesCheck')
        hearts_check = QCheckBox('Heart Pieces', group)
        hearts_check.setObjectName('HeartsCheck')
        shells_check = QCheckBox('Seashells', group)
        shells_check.setObjectName('ShellsCheck')
        misc_check = QCheckBox('Miscellaneous', group)
        misc_check.setObjectName('MiscCheck')
        mansion_box = RandoComboBox(group)
        mansion_box.setObjectName('MansionBox')
        mansion_box.addItems((
            'Seashell Mansion:  0',
            'Seashell Mansion:  5',
            'Seashell Mansion:  15',
            'Seashell Mansion:  30',
            'Seashell Mansion:  40',
            'Seashell Mansion:  50'
        ))
        shop_check = QCheckBox('Shop', group)
        shop_check.setObjectName('ShopCheck')
        boss_check = QCheckBox('Boss Drops', group)
        boss_check.setObjectName('BossCheck')
        inst_check = QCheckBox('Instruments', group)
        inst_check.setObjectName('InstrumentsCheck')
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
        hl.addWidget(inst_check)
        hl.addSpacerItem(self.createHorizontalSpacer())
        filler = QLabel(group)
        filler.setFixedWidth(self.spacing)
        hl.addWidget(filler)
        gvl.addLayout(hl)
        group.setLayout(gvl)
        vl.addWidget(group)

        group = QGroupBox('Special', tab)
        group.setAlignment(Qt.AlignmentFlag.AlignCenter)
        blup_check = QCheckBox('Blue Rupees', group)
        blup_check.setObjectName('RupeesCheck')
        owls_box = RandoComboBox(group)
        owls_box.setObjectName('OwlsBox')
        owls_box.addItems((
            'Owl Gifts:  None',
            'Owl Gifts:  Overworld',
            'Owl Gifts:  Dungeons',
            'Owl Gifts:  All'
        ))
        hl = QHBoxLayout()
        hl.addWidget(blup_check)
        hl.addSpacerItem(self.createHorizontalSpacer())
        hl.addWidget(owls_box)
        hl.addSpacerItem(self.createHorizontalSpacer())
        filler = QLabel(group)
        filler.setFixedWidth(self.spacing)
        hl.addWidget(filler)
        group.setLayout(hl)
        vl.addWidget(group)

        minigames_group = QGroupBox('Minigames', tab)
        minigames_group.setAlignment(Qt.AlignmentFlag.AlignCenter)
        dampe_check = QCheckBox(u"Damp\u00e9", minigames_group)
        dampe_check.setObjectName('DampeCheck')
        rapids_check = QCheckBox('Rapids', minigames_group)
        rapids_check.setObjectName('RapidsCheck')
        fishing_check = QCheckBox('Fishing', minigames_group)
        fishing_check.setObjectName('FishingCheck')
        trendy_check = QCheckBox('Trendy Game', minigames_group)
        trendy_check.setObjectName('TrendyCheck')
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
        ghl.addWidget(minigames_group, 1)

        ghl.addSpacerItem(QSpacerItem(self.spacing, 1, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed))

        output_group = QGroupBox('Output Settings', tab)
        output_group.setAlignment(Qt.AlignmentFlag.AlignCenter)
        spoiler_check = QCheckBox('Create Spoiler Log', output_group)
        spoiler_check.setObjectName('SpoilerCheck')
        race_check = QCheckBox('Race Mode', output_group)
        race_check.setObjectName('RaceCheck')
        unrandomizer_check = QCheckBox('Unrandomizer Mode', output_group)
        unrandomizer_check.setObjectName('UnrandomCheck')
        platform_box = RandoComboBox(output_group)
        platform_box.setObjectName('PlatformBox')
        platform_box.addItems((
            'Platform:  Console',
            'Platform:  Emulator'
        ))
        ovl = QVBoxLayout()
        hl = QHBoxLayout()
        hl.addWidget(spoiler_check)
        hl.addSpacerItem(self.createHorizontalSpacer())
        hl.addWidget(race_check)
        ovl.addLayout(hl)
        hl = QHBoxLayout()
        hl.addWidget(unrandomizer_check)
        hl.addSpacerItem(self.createHorizontalSpacer())
        hl.addWidget(platform_box)
        ovl.addLayout(hl)
        output_group.setLayout(ovl)
        ghl.addWidget(output_group, 1)
        vl.addLayout(ghl)

        tab.setLayout(vl)
        return tab


    def createSettingsWorldTab(self) -> QWidget:
        tab = QWidget()
        vl = QVBoxLayout()

        group = QGroupBox('Global', tab)
        group.setAlignment(Qt.AlignmentFlag.AlignCenter)
        enemy_check = QCheckBox('Randomize Enemies', group)
        enemy_check.setObjectName('EnemyCheck')
        enemy_sizes_check = QCheckBox('Randomize Enemy Sizes', group)
        enemy_sizes_check.setObjectName('EnemySizesCheck')
        chests_box = RandoComboBox(group)
        chests_box.setObjectName('ChestTypeBox')
        chests_box.addItems((
            'Chests:  Default',
            'Chests:  Size',
            'Chests:  Texture + Size'
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
        kanalet_check.setObjectName('KanaletCheck')
        mabe_check = QCheckBox('Open Mabe', group)
        mabe_check.setObjectName('MabeCheck')
        mamu_check = QCheckBox('Open Mamu', group)
        mamu_check.setObjectName('MamuCheck')
        bridge_check = QCheckBox('Completed Bridge', group)
        bridge_check.setObjectName('BridgeCheck')
        d2_check = QCheckBox('Classic D2', group)
        d2_check.setObjectName('D2Check')
        dungeons_check = QCheckBox('Shuffled Dungeons', group)
        dungeons_check.setObjectName('DungeonsCheck')
        consumable_check = QCheckBox('Consumable Drops', group)
        consumable_check.setObjectName('ConsumableCheck')
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
        pets_check.setObjectName('PetsCheck')
        fishing_check = QCheckBox('Fast Fishing', group)
        fishing_check.setObjectName('FastFishingCheck')
        bombs_check = QCheckBox('Shuffled Bombs', group)
        bombs_check.setObjectName('BombsCheck')
        book_check = QCheckBox('Free Book', group)
        book_check.setObjectName('BookCheck')
        stalfos_check = QCheckBox('Fast Stalfos', group)
        stalfos_check.setObjectName('StalfosCheck')
        powder_check = QCheckBox('Shuffled Powder', group)
        powder_check.setObjectName('PowderCheck')
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
        boss_check.setObjectName('BossAnimCheck')
        song_check = QCheckBox('Song Cutscenes', group)
        song_check.setObjectName('SongAnimCheck')
        move_check = QCheckBox('Movement Speed', group)
        move_check.setObjectName('MoveSpeedCheck')
        chest_check = QCheckBox('Chest Animations', group)
        chest_check.setObjectName('ChestAnimCheck')
        key_check = QCheckBox('Key Animations', group)
        key_check.setObjectName('KeyAnimCheck')
        item_check = QCheckBox('Item Get Animations', group)
        item_check.setObjectName('ItemAnimCheck')
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
        dungeons_box = RandoComboBox(group)
        dungeons_box.setObjectName('DungeonItemsBox')
        dungeons_box.addItems((
            'Dungeon Items:  Standard',
            'Dungeon Items:  Keysanity',
            'Dungeon Items:  Keysy'
        ))
        pool_box = RandoComboBox(group)
        pool_box.setObjectName('ItemPoolBox')
        pool_box.addItems((
            'Item Pool:  Standard',
            'Item Pool:  Reduced',
            'Item Pool:  Plentiful'
        ))
        trap_box = RandoComboBox(group)
        trap_box.setObjectName('TrapBox')
        trap_box.addItems((
            'Traps:  None',
            'Traps:  Few',
            'Traps:  Many',
            'Traps:  Trapsanity'
        ))
        ovl = QVBoxLayout()
        ovl.addWidget(dungeons_box)
        ovl.addWidget(pool_box)
        ovl.addWidget(trap_box)
        group.setLayout(ovl)
        ghl.addWidget(group)
        vl.addLayout(ghl)

        group = QGroupBox('Difficulty', tab)
        group.setAlignment(Qt.AlignmentFlag.AlignCenter)
        damage_box = RandoComboBox(group)
        damage_box.setObjectName('DamageBox')
        damage_box.addItems((
            'Damage:  Easy',
            'Damage:  Standard',
            'Damage:  Hero',
            'Damage:  OHKO'
        ))
        start_box = QSpinBox(tab)
        start_box.setObjectName('StartHeartBox')
        start_box.setPrefix('Starting Hearts:  ')
        start_box.setMinimum(1)
        start_box.setMaximum(20)
        max_box = QSpinBox(tab)
        max_box.setObjectName('MaxHeartBox')
        max_box.setPrefix('Max Hearts:  ')
        max_box.setMinimum(1)
        max_box.setMaximum(20)
        ovl = QVBoxLayout()
        ovl.addWidget(damage_box)
        ovl.addWidget(start_box)
        ovl.addWidget(max_box)
        group.setLayout(ovl)
        ghl.addSpacerItem(self.createHorizontalSpacer())
        ghl.addWidget(group)

        group = QGroupBox('Other', tab)
        group.setAlignment(Qt.AlignmentFlag.AlignCenter)
        controls_box = RandoComboBox(group)
        controls_box.setObjectName('ControlBox')
        controls_box.addItems((
            'Controls:  Standard',
            'Controls:  DPAD',
            'Controls:  360 Movement'
        ))
        stealing_box = RandoComboBox(group)
        stealing_box.setObjectName('StealingBox')
        stealing_box.addItems((
            'Stealing:  Standard',
            'Stealing:  Always',
            'Stealing:  Never'
        ))
        super_check = QCheckBox('Super Weapons', group)
        super_check.setObjectName('SuperWeaponsCheck')
        ovl = QVBoxLayout()
        ovl.addWidget(controls_box)
        ovl.addWidget(stealing_box)
        ovl.addWidget(super_check)
        group.setLayout(ovl)
        ghl.addSpacerItem(self.createHorizontalSpacer())
        ghl.addWidget(group)

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
        vl = QVBoxLayout()
        vl.addWidget(label)
        vl.addWidget(list_widget)
        hl.addLayout(vl, 2)

        inst_box = RandoComboBox(tab)
        inst_box.setObjectName('InstrumentStartBox')
        for i in range(9):
            inst_box.addItem(f'Starting Instruments:  {i}')
        items_box = RandoComboBox(tab)
        items_box.setObjectName('DungeonStartItemsBox')
        items_box.addItems((
            'Dungeon Items:  None',
            'Dungeon Items:  Beaks',
            'Dungeon Items:  MC',
            'Dungeon Items:  MCB'
        ))
        right_button = QPushButton('->', tab)
        right_button.setFixedSize(right_button.size() * 3)
        right_button.clicked.connect(self.window.moveListItemsRight)
        left_button = QPushButton('<-', tab)
        left_button.setFixedSize(left_button.size() * 3)
        left_button.clicked.connect(self.window.moveListItemsLeft)
        rupee_box = QSpinBox(tab)
        rupee_box.setObjectName('RupeeBox')
        rupee_box.setPrefix('Rupees:  ')
        rupee_box.setMinimum(0)
        rupee_box.setMaximum(9999)
        rupee_box.setFixedHeight(rupee_box.height() * 2)
        ft = rupee_box.font()
        ft.setPointSize(11)
        rupee_box.setFont(ft)
        vl = QVBoxLayout()
        vl.addSpacerItem(self.createVerticalSpacer())
        vl.addWidget(inst_box, 1)
        vl.addSpacerItem(self.createHorizontalSpacer())
        vl.addWidget(items_box, 1)
        vl.addSpacerItem(self.createVerticalSpacer())
        vl.addWidget(right_button, 4)
        vl.addSpacerItem(self.createHorizontalSpacer())
        vl.addWidget(left_button, 4)
        vl.addSpacerItem(self.createVerticalSpacer())
        vl.addWidget(rupee_box, 2)
        vl.addSpacerItem(self.createVerticalSpacer())
        hl.addLayout(vl, 1)

        label = QLabel('Starting Items', tab)
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ft = label.font()
        ft.setPointSize(12)
        label.setFont(ft)
        list_widget = QListWidget(tab)
        list_widget.setObjectName('StartingItemsList')
        vl = QVBoxLayout()
        vl.addWidget(label)
        vl.addWidget(list_widget)
        hl.addLayout(vl, 2)

        tab.setLayout(hl)
        return tab


    def createLocationsTab(self) -> QWidget:
        tab = QWidget()
        hl = QHBoxLayout()

        label = QLabel('Included', tab)
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ft = label.font()
        ft.setPointSize(12)
        label.setFont(ft)
        list_widget = QListWidget(tab)
        list_widget.setObjectName('IncludedLocationsList')
        vl = QVBoxLayout()
        vl.addWidget(label)
        vl.addWidget(list_widget)
        hl.addLayout(vl, 2)

        right_button = QPushButton('->', tab)
        right_button.setFixedSize(right_button.size() * 3)
        right_button.clicked.connect(self.window.moveListItemsRight)
        left_button = QPushButton('<-', tab)
        left_button.setFixedSize(left_button.size() * 3)
        left_button.clicked.connect(self.window.moveListItemsLeft)
        vl = QVBoxLayout()
        vl.addSpacerItem(self.createVerticalSpacer())
        vl.addSpacerItem(self.createHorizontalSpacer())
        vl.addSpacerItem(self.createHorizontalSpacer())
        vl.addSpacerItem(self.createHorizontalSpacer())
        vl.addSpacerItem(self.createVerticalSpacer())
        vl.addWidget(right_button, 4)
        vl.addSpacerItem(self.createHorizontalSpacer())
        vl.addWidget(left_button, 4)
        vl.addSpacerItem(self.createVerticalSpacer())
        vl.addSpacerItem(self.createHorizontalSpacer())
        vl.addSpacerItem(self.createHorizontalSpacer())
        vl.addSpacerItem(self.createHorizontalSpacer())
        vl.addSpacerItem(self.createVerticalSpacer())
        hl.addLayout(vl, 1)

        label = QLabel('Excluded', tab)
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ft = label.font()
        ft.setPointSize(12)
        label.setFont(ft)
        list_widget = QListWidget(tab)
        list_widget.setObjectName('ExcludedLocationsList')
        vl = QVBoxLayout()
        vl.addWidget(label)
        vl.addWidget(list_widget)
        hl.addLayout(vl, 2)

        tab.setLayout(hl)
        return tab


    def createLogicTab(self) -> QWidget:
        tab = QWidget()
        hl = QHBoxLayout()

        label = QLabel('Included', tab)
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ft = label.font()
        ft.setPointSize(12)
        label.setFont(ft)
        list_widget = QListWidget(tab)
        list_widget.setObjectName('IncludedLogicList')
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
            'Preset:  Custom',
            'NO LOGIC'
        ))
        logic_box.setObjectName('LogicBox')
        right_button = QPushButton('->', tab)
        right_button.setFixedSize(right_button.size() * 3)
        right_button.clicked.connect(self.window.moveListItemsRight)
        left_button = QPushButton('<-', tab)
        left_button.setFixedSize(left_button.size() * 3)
        left_button.clicked.connect(self.window.moveListItemsLeft)
        vl = QVBoxLayout()
        vl.addSpacerItem(self.createVerticalSpacer())
        vl.addSpacerItem(self.createHorizontalSpacer())
        vl.addWidget(logic_box)
        vl.addSpacerItem(self.createHorizontalSpacer())
        vl.addSpacerItem(self.createVerticalSpacer())
        vl.addWidget(right_button, 4)
        vl.addSpacerItem(self.createHorizontalSpacer())
        vl.addWidget(left_button, 4)
        vl.addSpacerItem(self.createVerticalSpacer())
        vl.addSpacerItem(self.createHorizontalSpacer())
        vl.addSpacerItem(self.createHorizontalSpacer())
        vl.addSpacerItem(self.createHorizontalSpacer())
        vl.addSpacerItem(self.createVerticalSpacer())
        hl.addLayout(vl, 1)

        label = QLabel('Excluded', tab)
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ft = label.font()
        ft.setPointSize(12)
        label.setFont(ft)
        list_widget = QListWidget(tab)
        list_widget.setObjectName('ExcludedLogicList')
        vl = QVBoxLayout()
        vl.addWidget(label)
        vl.addWidget(list_widget)
        hl.addLayout(vl, 2)

        tab.setLayout(hl)
        return tab


    def createPatchesTab(self) -> QWidget:
        tab = QWidget()
        return tab


    def createCosmeticsTab(self) -> QWidget:
        tab = QWidget()
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
        self.createMessageWindow("What's New", CHANGE_LOG)


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


    def createMessageWindow(self, title, text) -> None:
        """Creates a new QMessageBox with the given window title and text

        This also matches the current Light/Dark Mode"""

        box = QMessageBox()
        box.setWindowTitle(title)
        box.setText(text)

        match self.theme:
            case 'dark':
                box.setStyleSheet(DARK_STYLESHEET)
            case 'diamond-black':
                box.setStyleSheet(DIAMONDBLACK_STYLESHEET)
            case _:
                box.setStyleSheet(LIGHT_STYLESHEET)

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
        return self.window.findChild(QCheckBox, name)


    def findComboBox(self, name: str) -> RandoComboBox:
        return self.window.findChild(RandoComboBox, name)


    def findLabel(self, name: str) -> QLabel:
        return self.window.findChild(QLabel, name)


    def findLineEdit(self, name: str) -> QLineEdit:
        return self.window.findChild(QLineEdit, name)


    def findListWidget(self, name: str) -> QListWidget:
        return self.window.findChild(QListWidget, name)


    def findPushButton(self, name: str) -> QPushButton:
        return self.window.findChild(QPushButton, name)


    def findSpinBox(self, name: str) -> QSpinBox:
        return self.window.findChild(QSpinBox, name)


    def findChild(self, name: str) -> QWidget:
        return self.window.findChild(QWidget, name)

    ## MAIN WINDOW CALLS <== END



    ########################################################################
    ## START ==> EVENT FILTERS
    ########################################################################
    def addOptionDescriptions(self) -> None:
        """Iterates through the settings and adds the descriptions from Info/Descriptions.yml"""

        for option in DESC_DEFS:
            widget = self.findChild(option)
            if widget is None:
                continue
            widget.installEventFilter(self)


    def eventFilter(self, source: QWidget, event):
        match event.type():
            case QEvent.Type.HoverEnter:
                self.window.current_option = source.objectName()
                self.setExplanationText(DESC_DEFS[source.objectName()])
            case QEvent.Type.HoverLeave:
                self.setExplanationText()

        return QWidget.eventFilter(self, source, event)


    ## EVENT FILTERS <== END
