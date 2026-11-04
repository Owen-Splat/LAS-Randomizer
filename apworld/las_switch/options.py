from dataclasses import dataclass
from Options import Choice, PerGameCommonOptions, Accessibility, Toggle, DefaultOnToggle, OptionDict, OptionSet
from .core.data import ITEMS


class CheckProfile(Choice):
    """Standard retains the original 228-check test profile.
    Configured uses the individual category switches below.
    """
    display_name = "Check Profile"
    option_standard = 0
    option_configured = 1
    default = 1


class ExperimentalAccessibility(Accessibility):
    """Accessibility policy applied by Archipelago to the corrected LAS logic."""
    default = 2


class SeashellMansion(Choice):
    """Highest mansion reward tier included as an AP check. Zero leaves all mansion rewards vanilla."""
    option_0=0
    option_5=5
    option_15=15
    option_30=30
    option_40=40
    option_50=50
    alias_true=50
    alias_false=0
    default=50


class OwlGifts(Choice):
    """Choose which owl statues give randomized items. Dungeon owls require their Stone Beak."""
    option_none=0
    option_overworld=1
    option_dungeons=2
    option_all=3
    alias_true=3
    alias_false=0
    default=0


class ChestAppearance(Choice):
    """Use original chests, item-dependent sizes, or item-dependent textures and sizes."""
    option_default=0
    option_size=1
    option_texture_and_size=2
    default=0


class Stealing(Choice):
    """Normal requires a sword to steal; always removes that requirement; never disables stealing."""
    option_normal=0
    option_always=1
    option_never=2
    default=0


class Traps(Choice):
    """Replace eligible shuffled filler with animated traps. Insanity replaces all eligible small rupees and medicine."""
    option_none=0
    option_few=1
    option_several=2
    option_many=3
    option_insanity=4
    alias_trapsanity=4
    default=0


class StartingItems(OptionDict):
    """LAS item names and quantities, e.g. sword: 1. Items are removed from the shuffled pool and delivered by AP once."""
    display_name='Starting Items'
    default={}


class RandomizedItems(OptionSet):
    """Whitelist of LAS item types to shuffle. Unlisted items remain vanilla and their locations are outside AP."""
    display_name='Randomized Items'
    valid_keys=frozenset(ITEMS)
    default=frozenset(ITEMS)


@dataclass
class LASOptions(PerGameCommonOptions):
    accessibility: ExperimentalAccessibility
    check_profile: CheckProfile
    chests: DefaultOnToggle
    golden_leaves: DefaultOnToggle
    miscellaneous: DefaultOnToggle
    seashell_mansion: SeashellMansion
    free_gifts: DefaultOnToggle
    heart_pieces: DefaultOnToggle
    trade_quest: DefaultOnToggle
    dampe: DefaultOnToggle
    rapids: DefaultOnToggle
    fishing: DefaultOnToggle
    trendy_game: DefaultOnToggle
    seashells: DefaultOnToggle
    blupsanity: Toggle
    boss_drops: DefaultOnToggle
    instruments: DefaultOnToggle
    owl_gifts: OwlGifts
    shop: DefaultOnToggle
    randomize_enemies: Toggle
    randomize_enemy_sizes: Toggle
    chest_appearance: ChestAppearance
    open_kanalet: DefaultOnToggle
    open_mabe: Toggle
    open_mamu: DefaultOnToggle
    completed_bridge: DefaultOnToggle
    classic_d2: Toggle
    shuffled_dungeons: Toggle
    extra_consumable_drop: DefaultOnToggle
    bad_pets: Toggle
    free_book: DefaultOnToggle
    fast_fishing: Toggle
    fast_stalfos: Toggle
    unlocked_bombs: DefaultOnToggle
    shuffled_bombs: Toggle
    shuffled_powder: Toggle
    blur_removal: Toggle
    randomize_music: Toggle
    nice_bombs: Toggle
    nice_magic_rod: Toggle
    sword_beam_with_lv1: Toggle
    fast_boss_cutscenes: Toggle
    fast_song_cutscenes: Toggle
    fast_chest_animations: Toggle
    fast_key_animations: Toggle
    one_hit_ko: Toggle
    fast_stealing: Toggle
    stealing: Stealing
    traps: Traps
    death_link: Toggle
    starting_items: StartingItems
    randomized_items: RandomizedItems

