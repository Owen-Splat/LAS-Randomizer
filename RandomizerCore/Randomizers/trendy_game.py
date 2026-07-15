

class TrendyGameRandomizer:
    """Handles placing items in Trendy Game. Current just the final prize"""

    def __init__(self, mod_generator) -> None:
        self.parent = mod_generator
        if self.parent.thread_active: self.trendyChanges()


    def trendyChanges(self):
        flow = self.parent.file_manager.readFile('GameShopOwner.bfevfl')
        self.parent.item_get_manager.get(flow.flowchart, 'trendy-prize-final', 'Event112', 'Event239', True)
        self.parent.file_manager.writeFile('GameShopOwner.bfevfl', flow)
