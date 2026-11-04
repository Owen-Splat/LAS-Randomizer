"""Compile and audit physical check markers for the original LAS generator.

This is an intermediate native build input, not a playable backend declaration.
The AP placements remain authoritative and are never shuffled here.
"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path

MARKER_BASE = 0x4C410000
MAX_CHECKS = 352


def compile_plan(contract):
    result = deepcopy(contract)
    actions = sorted(result['native_config']['actions'], key=lambda row: row['location_id'])
    if len(actions) > MAX_CHECKS:
        raise ValueError('Check set exceeds native persistent bit capacity')
    if len({r['location_id'] for r in actions})!=len(actions) or len({r['location'] for r in actions})!=len(actions):
        raise ValueError('Duplicate managed check')
    checks = []
    for ordinal, row in enumerate(actions):
        marker = MARKER_BASE + ordinal
        name = row['location']
        # A plain AddItemByKey preserves index. Progressive and rupee event
        # helpers can discard/bypass it, so use the validated HookShot path.
        result['placements'][name] = 'hookshot'
        result['placements']['indexes'][name] = marker
        checks.append({'ordinal': ordinal, 'marker': marker,
                       'location': name, 'location_id': row['location_id'],
                       'subtype': row['subtype']})
    plan = {'schema_version': 1, 'marker_base': MARKER_BASE,
            'manifest_digest': result['native_config']['manifest']['manifest_digest'],
            'placeholder': 'HookShot', 'checks': checks,
            'live_coverage_verified': False}
    plan['digest'] = hashlib.sha256(json.dumps(plan, sort_keys=True,
                                             separators=(',', ':')).encode()).hexdigest()
    result['native_check_plan'] = plan
    result['mode'] = 'native_markers_development'
    from native_display import prepare
    return prepare(result)


def audit_markers(mod, plan, display_plan=None):
    """Read serialized outputs, not generator intentions, to prove marker survival."""
    from RandomizerCore.Tools import event_tools
    from RandomizerCore.Tools.leb import Room
    mod = Path(mod)
    expected = {row['marker']: row for row in plan['checks']}
    expected_keys={row['marker']:row['key'] for row in display_plan['displays']} if display_plan else {}
    found = {marker: [] for marker in expected}
    unknown = []

    def record(marker, key, path, context, role='item_reference'):
        if type(marker) is not int or not MARKER_BASE <= marker < MARKER_BASE + 0x10000:
            return
        entry = {'file': path.relative_to(mod).as_posix(), 'context': context, 'item_key': key,'role':role}
        if marker not in expected:
            unknown.append({'marker': marker, **entry})
        else:
            found[marker].append(entry)

    for path in sorted((mod / 'romfs').rglob('*.leb')):
        for actor in Room(path.read_bytes()).actors:
            if actor.type == 0xF7:
                key = actor.parameters[1]
                if isinstance(key, bytes): key = key.decode('utf-8')
                record(actor.parameters[2], key, path, f'chest:{actor.key:016X}')
    for path in sorted((mod / 'romfs').rglob('*.bfevfl')):
        flow = event_tools.readFlow(path)
        for event in flow.flowchart.events:
            params = getattr(event.data, 'params', None)
            if params:
                inventory=(hasattr(event.data,'actor_action') and event.data.actor.v.identifier.name=='Inventory' and
                           event.data.actor_action.v.v=='AddItemByKey')
                for field in ('index', 'itemIndex'):
                    record(params.data.get(field), params.data.get('itemKey'), path,
                           event.name + ':' + field,'inventory_marker' if inventory else 'item_reference')
    checks = [{**row, 'occurrences': found[marker]}
              for marker, row in expected.items()]
    missing = [row['location'] for row in checks if not row['occurrences']]
    wrong_keys = [row['location'] for row in checks
                  if any(o['item_key'] != ('HookShot' if o['role']=='inventory_marker' else expected_keys.get(row['marker'],'HookShot'))
                         for o in row['occurrences'])]
    return {'schema_version': 1, 'plan_digest': plan['digest'], 'checks': checks,
            'managed_count': len(checks), 'serialized_count': len(checks) - len(missing),
            'missing': missing, 'wrong_item_keys': wrong_keys, 'unknown_markers': unknown,
            'serialized_coverage_complete': not (missing or wrong_keys or unknown),
            'live_coverage_verified': False}
