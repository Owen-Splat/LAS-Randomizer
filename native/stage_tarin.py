"""Stage the original LAS randomizer's first-gift edit for a fresh-save hook test."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

MARKER=0x4C415300
ORIGINAL_SHA="95b42cf2e12500108dda0d2b3a13e5438f9626b3f76dacdd9bcfc30c075abb5b"

def stage(source,romfs,mod,catalog):
    metadata=json.loads((mod.parent/"probe_report.json").read_text())
    if metadata.get("check_label")!="tarin" or not metadata.get("isolated_sentinel_suppression_test"):
        raise ValueError("Tarin staging requires the Tarin-labelled sentinel test module")
    relative=Path("region_common/event/Tarin.bfevfl")
    original=romfs/relative;destination=mod/"romfs"/relative
    if destination.exists():raise ValueError("Choose a new Tarin test output")
    raw=original.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=ORIGINAL_SHA:raise ValueError("Original Tarin flow differs from inspected clean input")
    sys.path.insert(0,str(source.resolve()))
    from RandomizerCore.Tools import event_tools
    from RandomizerCore.Randomizers import tarin
    data=json.loads(catalog.read_text())
    items={name:row["definition"] for name,row in data["items"].items()}
    # HookShot uses a plain Inventory.AddItemByKey, preserving the sentinel index.
    # Progressive swords/shields discard their input index in the original helper,
    # and event rupees bypass the inventory hook, so neither is a valid marker.
    placements={"tarin":"hookshot","indexes":{"tarin":MARKER},"starting-items":[]}
    flow=event_tools.readFlow(original)
    tarin.makeEventChanges(flow.flowchart,placements,{"starting-rupees":0},items)
    destination.parent.mkdir(parents=True,exist_ok=True)
    event_tools.writeFlow(destination,flow)
    reread=event_tools.readFlow(destination)
    matches=[]
    for event in reread.flowchart.events:
        params=getattr(event.data,"params",None)
        if params and params.data.get("index")==MARKER:
            matches.append((event.name,params.data.get("itemKey")))
    if len(matches)!=1 or matches[0][1]!="HookShot":
        raise ValueError("Tarin marker did not survive event-flow serialization")
    report=dict(check="tarin",marker=hex(MARKER),placeholder_item="HookShot",
                original_sha256=ORIGINAL_SHA,patched_sha256=hashlib.sha256(destination.read_bytes()).hexdigest(),
                event=matches[0][0],fresh_save_required=True,live_check_verified=False,
                note="The displayed placeholder must not enter inventory. This is not an AP delivery.")
    (mod/"tarin_probe.json").write_text(json.dumps(report,indent=2))
    return report

if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("source","romfs","mod","catalog"):p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args()
    print(json.dumps(stage(a.source,a.romfs,a.mod,a.catalog),indent=2))
