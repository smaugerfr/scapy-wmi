"""
Scapy WMI definitions
"""

import importlib
import importlib.machinery
import pathlib

__version__ = "0.0.4"


def scapy_ext(plg):
    plg.config("Scapy WMI Client", __version__)
    for lay in pathlib.Path(__file__).parent.glob("*.py"):
        print(lay)
        if lay.name == "__init__.py":
            continue
        plg.register(
            name=lay.name[:-3],
            mode=plg.MODE.LAYERS,
            path=lay.absolute(),
        )

    for lay in pathlib.Path(__file__).parent.joinpath("msrpce").glob("*.py"):
        print(lay)
        if lay.name == "__init__.py":
            continue
        plg.register(
            name="msrpce." + lay.name[:-3],
            mode=plg.MODE.LAYERS,
            path=lay.absolute(),
        )
    
    for lay in pathlib.Path(__file__).parent.joinpath("msrpce/raw").glob("*.py"):
        print(lay)
        if lay.name == "__init__.py":
            continue
        print("registering "+"msrpce.raw." + lay.name[:-3])
        plg.register(
            name="msrpce.raw." + lay.name[:-3],
            mode=plg.MODE.LAYERS,
            path=lay.absolute(),
        )