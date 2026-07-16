import oead


class FlagManager:
    def __init__(self, mod_generator):
        sheet = mod_generator.file_manager.readFile("GlobalFlags.gsheet")
        self.parseFlags(sheet)
        self.addCustomFlags()
        sheet["values"] = oead.gsheet.StructArray()
        for k,v in self.flags.items():
            sheet["values"].append({"symbol": k, "index": v})
        mod_generator.file_manager.writeFile("GlobalFlags.gsheet", sheet)


    def parseFlags(self, sheet) -> None:
        self.flags = {}
        self.index = 0
        for flag in sheet["values"]:
            self.index = flag["index"]
            self.flags[flag["symbol"]] = self.index


    def addCustomFlags(self) -> None:
        self.addFlag("SwordFoundFlag")
        self.addFlag("ShieldFoundFlag")
        self.addFlag("BraceletFoundFlag")
        self.addFlag("LensFoundFlag")
        self.addFlag("RedTunicFoundFlag")
        self.addFlag("BlueTunicFoundFlag")
        self.addFlag("GoriyaItemGetFlag")
        self.addFlag("MamuItemGetFlag")
        self.addFlag("ManboItemGetFlag")
        self.addFlag("BeachMiscItemGetFlag")
        self.addFlag("WoodsMiscItemGetFlag")
        self.addFlag("PotholeItemGetFlag")
        self.addFlag("DreamShrineItemGetFlag")
        self.addFlag("RoosterCaveItemGetFlag")
        self.addFlag("MermaidCaveItemGetFlag")
        self.addFlag("BombsFoundFlag")
        self.addFlag("RoosterFoundFlag")
        self.addFlag("BowWowFoundFlag")

        self.addFlag('AnimalVillageHeartGet')
        self.addFlag('AnimalVillageCaveHeartGet')
        self.addFlag('TaltalEntranceBlocksHeartGet')
        self.addFlag('NorthWastelandHeartGet')
        self.addFlag('DesertCaveHeartGet')
        self.addFlag('GraveyardCaveHeartGet')
        self.addFlag('MabeWellHeartGet')
        self.addFlag('UkukuCaveWestHeartGet')
        self.addFlag('UkukuCaveEastHeartGet')
        self.addFlag('BayPassageHeartGet')
        self.addFlag('RiverCrossingHeartGet')
        self.addFlag('RapidsWestHeartGet')
        self.addFlag('RapidsAscentHeartGet')
        self.addFlag('KanaletMoatHeartGet')
        self.addFlag('SouthBayHeartGet')
        self.addFlag('TaltalCrossingHeartGet')
        self.addFlag('TaltalEastHeartGet')
        self.addFlag('TaltalWestHeartGet')
        self.addFlag('TurtleRockHeartGet')
        self.addFlag('PotholeHeartGet')
        self.addFlag('WoodsCrossingHeartGet')
        self.addFlag('WoodsNorthCaveHeartGet')
        self.addFlag('DiamondIslandHeartGet')

        self.addFlag('TailCaveInstrumentGet')
        self.addFlag('BottleGrottoInstrumentGet')
        self.addFlag('KeyCavernInstrumentGet')
        self.addFlag('AnglersTunnelInstrumentGet')
        self.addFlag('CatfishsMawInstrumentGet')
        self.addFlag('FaceShrineInstrumentGet')
        self.addFlag('EaglesTowerInstrumentGet')
        self.addFlag('TurtleRockInstrumentGet')

        self.addFlag('TradeYoshiDollGet')
        self.addFlag('TradeRibbonGet')
        self.addFlag('TradeDogFoodGet')
        self.addFlag('TradeBananasGet')
        self.addFlag('TradeStickGet')
        self.addFlag('TradeHoneycombGet')
        self.addFlag('TradePineappleGet')
        self.addFlag('TradeHibiscusGet')
        self.addFlag('TradeLetterGet')
        self.addFlag('TradeBroomGet')
        self.addFlag('TradeFishingHookGet')
        self.addFlag('TradeNecklaceGet')
        self.addFlag('TradeMermaidsScaleGet')

        self.addFlag('KikiGone')

        self.addFlag('PrizeGet1')
        self.addFlag('PrizeGet2')
        self.addFlag('PrizeGet3')
        self.addFlag('PrizeGet4')
        self.addFlag('PrizeGet5')
        self.addFlag('PrizeGet6')

        # self.addFlag('Bottle2Get') # shouldnt need this now
        self.addFlag('FishingBottleGet')

        self.addFlag('owl-statue-below-D8')
        self.addFlag('owl-statue-pothole')
        self.addFlag('owl-statue-above-cave')
        self.addFlag('owl-statue-moblin-cave')
        self.addFlag('owl-statue-south-bay')
        self.addFlag('owl-statue-desert')
        self.addFlag('owl-statue-maze')
        self.addFlag('owl-statue-taltal-east')
        self.addFlag('owl-statue-rapids')

        self.addFlag('D1-owl-statue-spinies')
        self.addFlag('D1-owl-statue-3-of-a-kind')
        self.addFlag('D1-owl-statue-long-hallway')

        self.addFlag('D2-owl-statue-first-switch')
        self.addFlag('D2-owl-statue-push-puzzle')
        self.addFlag('D2-owl-statue-past-hinox')

        self.addFlag('D3-owl-statue-basement-north')
        self.addFlag('D3-owl-statue-arrow')
        self.addFlag('D3-owl-statue-northwest')

        self.addFlag('D4-owl-statue')

        self.addFlag('D5-owl-statue-triple-stalfos')
        self.addFlag('D5-owl-statue-before-boss')

        self.addFlag('D6-owl-statue-ledge')
        self.addFlag('D6-owl-statue-southeast')
        self.addFlag('D6-owl-statue-canal')

        self.addFlag('D7-owl-statue-ball')
        self.addFlag('D7-owl-statue-kirbys')
        self.addFlag('D7-owl-statue-3-of-a-kind-south')

        self.addFlag('D8-owl-statue-above-smasher')
        self.addFlag('D8-owl-statue-below-gibdos')
        self.addFlag('D8-owl-statue-eye-statue')

        self.addFlag('D0-owl-statue-nine-switches')
        self.addFlag('D0-owl-statue-first-switches')
        self.addFlag('D0-owl-statue-before-mini-boss')

        self.addFlag('KeyGetField06I')
        self.addFlag('KeyGetField06K')
        self.addFlag('KeyGetKanalet02A')
        self.addFlag('KeyGetKanalet01C')
        self.addFlag('KeyGetKanalet01D')

        self.addFlag('FlippersFound')

        self.addFlag('Dampe1')
        self.addFlag('DampeHeart')
        self.addFlag('Dampe2')
        self.addFlag('DampeBottle')
        self.addFlag('DampeFinal')

        self.addFlag('ShopShovelSteal')
        # self.addFlag('ShopShovelGet')
        self.addFlag('ShopBowSteal')
        # self.addFlag('ShopBowGet')
        self.addFlag('ShopHeartSteal')
        self.addFlag('ShopHeartGet')

        # flags for hidden seashells turned into drops
        self.addFlag("HeightsHoleGet")
        self.addFlag("BridgeHoleGet")
        self.addFlag("BeachBonkTreeGet")
        self.addFlag("TailCaveBonkTreeGet")
        self.addFlag("UkukuBonkTreeGet")
        self.addFlag("MabeBushGet")
        self.addFlag("PondIslandBushGet")
        self.addFlag("CoastIslandBushGet")
        self.addFlag("BayBushGet")
        self.addFlag("MansionBushGet")
        self.addFlag("MoblinCaveRockGet")
        self.addFlag("DesertSouthRockGet")
        self.addFlag("RockMazeRockGet")
        self.addFlag("PlainsRockGet")
        self.addFlag("TaltalWestRockGet")
        self.addFlag("TaltalEastRockGet")
        self.addFlag("GhostHousePotGet")

        # flags for static seashells
        self.addFlag("KanaletSunkenShellGet")
        self.addFlag("TaltalSunkenShellGet")
        self.addFlag("SouthBayDigShellGet")
        self.addFlag("BeachDigShellGet")
        self.addFlag("WastelandDigShellGet")
        self.addFlag("DesertDigShellGet")
        self.addFlag("GhostGraveDigShellGet")
        self.addFlag("DoghouseDigShellGet")
        self.addFlag("GopongaDigShellGet")
        self.addFlag("AboveCaveDigShellGet")
        self.addFlag("AboveD3DigShellGet")
        self.addFlag("UnderSkullDigShellGet")
        self.addFlag("RapidsEastDigShellGet")
        self.addFlag("TaltalWestDigShellGet")
        self.addFlag("WoodsWestDigShellGet")
        self.addFlag("WoodsEastDigShellGet")


    def editNextUnusedFlag(self, flag_name: str) -> bool:
        unused_names = [k for k,v in self.flags.items() if "unused" in k]
        if len(unused_names) == 0:
            return False
        self.flags[flag_name] = self.flags.pop(unused_names[0])
        return True


    def addFlag(self, flag_name: str) -> None:
        result = self.editNextUnusedFlag(flag_name)
        if not result:
            self.index += 1
            self.flags[flag_name] = self.index
