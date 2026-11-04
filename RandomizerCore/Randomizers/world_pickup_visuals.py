"""Select assigned shell graphics without replacing the original pickup actor."""
from pathlib import Path
import json
from RandomizerCore.Tools import oead_tools as sheet_tools

def stage(worker, sources):
    npc_sheet = worker.readFile('Npc.gsheet')
    clean_romfs_folder = Path(worker.rom_path)
    original_npcs = sheet_tools.readSheet(clean_romfs_folder / 'region_common/datasheets/Npc.gsheet')
    original_shell = next((source_row for source_row in original_npcs['values'] if source_row['symbol'] == 'ItemSecretSeashell'))
    completed_visuals = []
    stock_fallbacks = []
    for source in sources:
        # Only shell actors use this visual adapter.
        if source['item'] != 22:
            continue
        item_definition = worker.item_defs[worker.placements[source['location']]]
        model_path, model_name = (item_definition.get('model-path'), item_definition.get('model-name'))
        if not model_path or not model_name or worker.placements[source['location']].endswith('-trap'):
            model_path, model_name = ('ItemRupeeGreen.bfres', 'RupeeGreen')
        target_npc = next((source_row for source_row in original_npcs['values'] if source_row['graphics']['path'] == model_path and source_row['graphics']['model'] == model_name), None)
        if target_npc is None:
            stock_fallbacks.append({'location': source['location'], 'reason': 'Unknown model definition; stock visual retained'})
            continue
        # Keep the stock visual if the required resources are unavailable.
        resources_exist = True
        for folder, resource_name in (('actor', model_path), ('tailor', target_npc['graphics']['drsb'])):
            if resource_name and (Path(resource_name).name != resource_name or not (clean_romfs_folder / 'region_common' / folder / resource_name).is_file()):
                resources_exist = False
        if not resources_exist:
            stock_fallbacks.append({'location': source['location'], 'reason': 'Missing graphics resource; stock visual retained'})
            continue
        visual_key = f'LAS_WorldShell_{source['index']}'
        if any((source_row['symbol'] == visual_key for source_row in npc_sheet['values'])):
            raise ValueError('Duplicate shell graphics definition')
        # Copy the shell behavior and change only its graphics resources.
        shell_visual = sheet_tools.parseStruct(original_shell)
        shell_visual['symbol'] = visual_key
        for field in ('path', 'model', 'drsb'):
            shell_visual['graphics'][field] = target_npc['graphics'][field]
        npc_sheet['values'].append(sheet_tools.dictToStruct(shell_visual))
        source.update(world_npc=visual_key, model_path=model_path, model_name=model_name, drsb=target_npc['graphics']['drsb'])
        completed_visuals.append({field_name: source[field_name] for field_name in ('location', 'item', 'index', 'world_npc', 'model_path', 'model_name')})
    worker.writeFile('Npc.gsheet', npc_sheet)
    report = {'checks': completed_visuals, 'stock_fallbacks': stock_fallbacks, 'original_actors_preserved': True, 'heart_piece_visuals_changed': False, 'standalone_gameplay_verified': False}
    (Path(worker.romfs_dir).parent / 'world-pickup-visuals.json').write_text(json.dumps(report, indent=2))
    return report
