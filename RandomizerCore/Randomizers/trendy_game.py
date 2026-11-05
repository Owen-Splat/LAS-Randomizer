

class TrendyGameRandomizer:
    """Handles placing items in Trendy Game. Includes six physical prizes and the final reward"""

    def __init__(self, mod_generator) -> None:
        self.parent = mod_generator
        if self.parent.thread_active: self.trendyChanges()
        if self.parent.thread_active and self.parent.settings['Trendy Game']:
            from RandomizerCore.Randomizers.standalone_trendy import stage, DevTrendyRewards
            rewards = DevTrendyRewards(self.parent)
            stage(rewards)
            rewards.save_flags()


    def trendyChanges(self):
        flow = self.parent.file_manager.readFile('GameShopOwner.bfevfl')
        self.parent.item_get_manager.get(flow.flowchart, 'trendy-prize-final', 'Event112', 'Event239', True)
        self.parent.file_manager.writeFile('GameShopOwner.bfevfl', flow)
