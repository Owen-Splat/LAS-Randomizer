class GlobalFlags:
    def __init__(self, sheet: dict, start_index: int):
        self.sheet = sheet
        self.index = start_index
        self.flags = {}
    

    def addFlag(self, name):
        self.sheet['values'].append({'symbol': name, 'index': self.index})
        self.flags[name] = self.index
        self.index += 1
    
    
    def give_flags(self):
        return self.sheet, self.flags



def makeFlags(sheet):
    """Appends new flags to the GlobalFlags datasheet to use for Heart Pieces, Instruments, Trade Items, and Companions"""
    
    global_flags = GlobalFlags(sheet, start_index=1119)

    global_flags.addFlag('AnimalVillageHeartGet')
    global_flags.addFlag('AnimalVillageCaveHeartGet')
    global_flags.addFlag('TaltalEntranceBlocksHeartGet')
    global_flags.addFlag('NorthWastelandHeartGet')
    global_flags.addFlag('DesertCaveHeartGet')
    global_flags.addFlag('GraveyardCaveHeartGet')
    global_flags.addFlag('MabeWellHeartGet')
    global_flags.addFlag('UkukuCaveWestHeartGet')
    global_flags.addFlag('UkukuCaveEastHeartGet')
    global_flags.addFlag('BayPassageHeartGet')
    global_flags.addFlag('RiverCrossingHeartGet')
    global_flags.addFlag('RapidsWestHeartGet')
    global_flags.addFlag('RapidsAscentHeartGet')
    global_flags.addFlag('KanaletMoatHeartGet')
    global_flags.addFlag('SouthBayHeartGet')
    global_flags.addFlag('TaltalCrossingHeartGet')
    global_flags.addFlag('TaltalEastHeartGet')
    global_flags.addFlag('TaltalWestHeartGet')
    global_flags.addFlag('TurtleRockHeartGet')
    global_flags.addFlag('PotholeHeartGet')
    global_flags.addFlag('WoodsCrossingHeartGet')
    global_flags.addFlag('WoodsNorthCaveHeartGet')
    global_flags.addFlag('DiamondIslandHeartGet')

    global_flags.addFlag('TailCaveInstrumentGet')
    global_flags.addFlag('BottleGrottoInstrumentGet')
    global_flags.addFlag('KeyCavernInstrumentGet')
    global_flags.addFlag('AnglersTunnelInstrumentGet')
    global_flags.addFlag('CatfishsMawInstrumentGet')
    global_flags.addFlag('FaceShrineInstrumentGet')
    global_flags.addFlag('EaglesTowerInstrumentGet')
    global_flags.addFlag('TurtleRockInstrumentGet')

    global_flags.addFlag('TradeYoshiDollGet')
    global_flags.addFlag('TradeRibbonGet')
    global_flags.addFlag('TradeDogFoodGet')
    global_flags.addFlag('TradeBananasGet')
    global_flags.addFlag('TradeStickGet')
    global_flags.addFlag('TradeHoneycombGet')
    global_flags.addFlag('TradePineappleGet')
    global_flags.addFlag('TradeHibiscusGet')
    global_flags.addFlag('TradeLetterGet')
    global_flags.addFlag('TradeBroomGet')
    global_flags.addFlag('TradeFishingHookGet')
    global_flags.addFlag('TradeNecklaceGet')
    global_flags.addFlag('TradeMermaidsScaleGet')

    global_flags.addFlag('KikiGone')

    global_flags.addFlag('PotholeKeySpawn')

    global_flags.addFlag('PrizeGet1')
    global_flags.addFlag('PrizeGet2')
    global_flags.addFlag('PrizeGet3')
    global_flags.addFlag('PrizeGet4')
    global_flags.addFlag('PrizeGet5')
    global_flags.addFlag('PrizeGet6')

    global_flags.addFlag('Bottle2Get')
    global_flags.addFlag('FishingBottleGet')

    global_flags.addFlag('owl-statue-below-D8')
    global_flags.addFlag('owl-statue-pothole')
    global_flags.addFlag('owl-statue-above-cave')
    global_flags.addFlag('owl-statue-moblin-cave')
    global_flags.addFlag('owl-statue-south-bay')
    global_flags.addFlag('owl-statue-desert')
    global_flags.addFlag('owl-statue-maze')
    global_flags.addFlag('owl-statue-taltal-east')
    global_flags.addFlag('owl-statue-rapids')

    global_flags.addFlag('D1-owl-statue-spinies')
    global_flags.addFlag('D1-owl-statue-3-of-a-kind')
    global_flags.addFlag('D1-owl-statue-long-hallway')

    global_flags.addFlag('D2-owl-statue-first-switch')
    global_flags.addFlag('D2-owl-statue-push-puzzle')
    global_flags.addFlag('D2-owl-statue-past-hinox')

    global_flags.addFlag('D3-owl-statue-basement-north')
    global_flags.addFlag('D3-owl-statue-arrow')
    global_flags.addFlag('D3-owl-statue-northwest')

    global_flags.addFlag('D4-owl-statue')

    global_flags.addFlag('D5-owl-statue-triple-stalfos')
    global_flags.addFlag('D5-owl-statue-before-boss')

    global_flags.addFlag('D6-owl-statue-ledge')
    global_flags.addFlag('D6-owl-statue-southeast')
    global_flags.addFlag('D6-owl-statue-canal')

    global_flags.addFlag('D7-owl-statue-ball')
    global_flags.addFlag('D7-owl-statue-kirbys')
    global_flags.addFlag('D7-owl-statue-3-of-a-kind-south')

    global_flags.addFlag('D8-owl-statue-above-smasher')
    global_flags.addFlag('D8-owl-statue-below-gibdos')
    global_flags.addFlag('D8-owl-statue-eye-statue')

    global_flags.addFlag('D0-owl-statue-nine-switches')
    global_flags.addFlag('D0-owl-statue-first-switches')
    global_flags.addFlag('D0-owl-statue-before-mini-boss')

    global_flags.addFlag('KeyGetField06I')
    global_flags.addFlag('KeyGetField06K')
    global_flags.addFlag('KeyGetKanalet02A')
    global_flags.addFlag('KeyGetKanalet01C')
    global_flags.addFlag('KeyGetKanalet01D')

    global_flags.addFlag('FlippersFound')

    global_flags.addFlag('Dampe1')
    global_flags.addFlag('DampeHeart')
    global_flags.addFlag('Dampe2')
    global_flags.addFlag('DampeBottle')
    global_flags.addFlag('DampeFinal')

    # global_flags.addFlag('ShopShovelSteal')
    # global_flags.addFlag('ShopShovelGet')
    # global_flags.addFlag('ShopBowSteal')
    # global_flags.addFlag('ShopBowGet')
    # global_flags.addFlag('ShopHeartSteal')
    # global_flags.addFlag('ShopHeartGet')

    return global_flags.give_flags()
