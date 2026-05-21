from RandomizerCore.Fixes.Events.skeletal_guard import SkeletalGuardEventFixes
from RandomizerCore.Fixes.Events.windfishs_egg import WindFishsEggEventFixes
from RandomizerCore.Fixes.Events.player_start import PlayerStartEventFixes
from RandomizerCore.Fixes.Events.prize_common import PrizeCommonEventFixes
from RandomizerCore.Fixes.Events.madam_meow import MadamMeowMeowEventFixes
from RandomizerCore.Fixes.Events.tunic_swap import TunicSwapper
from RandomizerCore.Fixes.Events.common import CommonEventFixes
from RandomizerCore.Fixes.Events.item import ItemEventFixes


class EventFixes:
    """Make changes to events that should be in every seed, regardless of item placements"""

    def __init__(self, mod_generator) -> None:
        if mod_generator.thread_active: PlayerStartEventFixes(mod_generator)
        if mod_generator.thread_active: ItemEventFixes(mod_generator)
        if mod_generator.thread_active: MadamMeowMeowEventFixes(mod_generator)
        if mod_generator.thread_active: WindFishsEggEventFixes(mod_generator)
        if mod_generator.thread_active: SkeletalGuardEventFixes(mod_generator)
        if mod_generator.thread_active: CommonEventFixes(mod_generator)
        if mod_generator.thread_active: PrizeCommonEventFixes(mod_generator)
        if mod_generator.thread_active: TunicSwapper(mod_generator)
