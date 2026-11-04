"""LAS Switch AP world and Launcher component. Core tools also work without AP."""
from importlib.util import find_spec

__version__ = "0.3.0"


def run_client(*args):
    from .client import launch
    try:
        launch(list(args))
    except Exception as exc:
        from Utils import messagebox
        messagebox("LAS Switch Client", str(exc), error=True)
        raise


def launch_client(*args):
    from worlds.LauncherComponents import launch_subprocess
    launch_subprocess(run_client, name="LAS Switch Client", args=args)


if find_spec("BaseClasses") is not None:
    from .world import LASWorld
    from worlds.LauncherComponents import Component, Type, components, SuffixIdentifier
    if not any(component.display_name == "LAS Switch Client" for component in components):
        components.append(Component("LAS Switch Client", func=launch_client, component_type=Type.CLIENT,
                                    game_name="Link's Awakening (Switch)",
                                    file_identifier=SuffixIdentifier(".lasap")))
