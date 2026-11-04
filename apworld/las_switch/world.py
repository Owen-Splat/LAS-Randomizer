import json
from pathlib import Path

from BaseClasses import Item, ItemClassification, Location, Region, Tutorial
from worlds.AutoWorld import World, WebWorld

from .core.data import GAME, VERSION, CATALOG, ITEM_IDS, LOCATION_IDS, ITEMS, active_locations, pool, CATEGORY_NAMES
from .core.logic import Logic
from .core.seed import make_manifest
from .options import LASOptions
from .core.configuration import defaults,validate,TOGGLES,CHOICES,DUNGEONS,selected_locations,item_pool


class LASItem(Item):
    game = GAME


class LASLocation(Location):
    game = GAME


class LASWeb(WebWorld):
    tutorials = [Tutorial("Experimental setup", "Install the LAS Switch world and client.", "English",
                          "setup_en.md", "setup/en", ["LAS Switch integration contributors"])]


class LASWorld(World):
    """Experimental Link's Awakening Switch world. Native game hooks are required to play."""
    game = GAME
    web = LASWeb()
    options_dataclass = LASOptions
    item_name_to_id = ITEM_IDS
    location_name_to_id = LOCATION_IDS
    required_client_version = (0, 6, 7)

    def generate_early(self):
        self.profile = self.options.check_profile.current_key
        self.categories=sorted(name for name in CATEGORY_NAMES if getattr(self.options,name).value) if self.profile=='configured' else None
        self.settings=defaults()
        self.settings.update({key:bool(getattr(self.options,key).value) for key in TOGGLES})
        self.settings.update({key:getattr(self.options,key).current_key for key in CHOICES})
        self.settings.update(seashell_mansion=self.options.seashell_mansion.value,
                             owl_gifts=self.options.owl_gifts.current_key,
                             starting_items=dict(self.options.starting_items.value),
                             randomized_items=sorted(self.options.randomized_items.value))
        validate(self.settings)
        if self.options.start_inventory.value:
            raise ValueError('Use starting_items for LAS quantities; generic start_inventory is not supported alongside it')
        destinations=list(DUNGEONS)
        if self.settings['shuffled_dungeons']:self.random.shuffle(destinations)
        self.entrances=dict(zip(DUNGEONS,destinations))
        self.logic = Logic(self.profile,self.categories,self.settings,self.entrances)
        self.active = selected_locations(self.profile,self.categories,self.settings)
        self.pool_names,self.locked_items=item_pool(self.active,self.settings,self.random)
        if not self.active:raise ValueError('Enable at least one check category')

    def create_regions(self):
        menu = Region("Menu", self.player, self.multiworld)
        game = Region("Koholint Island", self.player, self.multiworld)
        self.multiworld.regions.extend((menu, game))
        menu.connect(game)
        for name in self.active:
            location = LASLocation(self.player, name, LOCATION_IDS[name], game)
            location.access_rule = lambda state, name=name: self.logic.can_reach(state.prog_items[self.player], name)
            game.locations.append(location)

    def create_item(self, name):
        # All non-junk capabilities are progression until a finer sound classification is proven.
        definition = ITEMS[name]
        classification = ItemClassification.filler if definition["type"] == "junk" else ItemClassification.progression
        if name.startswith(("key-", "nightmare-key-")):
            classification = ItemClassification.progression
        if name.startswith('stone-beak-D') and 'owl_gifts' in (self.categories or ()):
            classification = ItemClassification.progression
        if name.endswith('-trap'):
            classification = ItemClassification.trap
        if (name=='bomb' and self.settings['shuffled_bombs']) or (name=='powder' and self.settings['shuffled_powder']):
            classification=ItemClassification.progression
        return LASItem(name, classification, ITEM_IDS[name], self.player)

    def create_items(self):
        for location,item in self.locked_items.items():
            self.multiworld.get_location(location,self.player).place_locked_item(self.create_item(item))
        for name,count in self.settings['starting_items'].items():
            for _ in range(count):self.multiworld.push_precollected(self.create_item(name))
        self.multiworld.itempool.extend(self.create_item(name) for name in self.pool_names)

    def set_rules(self):
        self.multiworld.completion_condition[self.player] = lambda state: self.logic.can_reach(
            state.prog_items[self.player], "kill-nightmare")

    def get_filler_item_name(self):
        return "rupee-50"

    def identity(self):
        return {"seed": self.multiworld.seed_name, "slot": self.player,
                "slot_name": self.multiworld.player_name[self.player]}

    def fill_slot_data(self):
        return {"schema_version": 2, "world_version": VERSION, "identity": self.identity(),
                "source_digest": CATALOG["source_digest"], "profile": self.profile,
                "location_ids": {name: LOCATION_IDS[name] for name in self.active},
                "native_bridge_required": True, "location_categories":self.categories,
                "player_settings":self.settings,"dungeon_entrances":self.entrances}

    def generate_output(self, output_directory):
        placements = []
        for name in self.active:
            location = self.multiworld.get_location(name, self.player)
            item = location.item
            if item is None or item.code is None:
                raise ValueError(f"Missing network item at {name}")
            placements.append({"location": name, "location_id": location.address,
                               "recipient_slot": item.player, "item_id": item.code,
                               "item_name": item.name, "item_game": item.game})
        hints=[]
        for location in sorted(self.multiworld.get_filled_locations(),key=lambda loc:(loc.player,loc.address if isinstance(loc.address,int) else -1)):
            item=location.item
            if not isinstance(location.address,int) or not item or not isinstance(item.code,int):continue
            if location.player!=self.player and item.player!=self.player:continue
            hints.append({'index':len(hints),'finding_player':location.player,'location_id':location.address,
                          'recipient_slot':item.player,'item_id':item.code,'item_name':item.name,'item_game':item.game,
                          'location_name':location.name,'finding_name':self.multiworld.player_name[location.player],
                          'recipient_name':self.multiworld.player_name[item.player]})
        manifest = make_manifest(self.identity(), self.profile, placements,self.categories,self.settings,self.entrances,
                                 {str(p):name for p,name in self.multiworld.player_name.items()},hints)
        path = Path(output_directory) / (self.multiworld.get_out_file_name_base(self.player) + ".lasap")
        path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
