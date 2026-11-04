"""Protocol capability proofs required before a candidate becomes a beta mod."""
CAPABILITY_TESTS={
    'atomic_delivery_v1':{'test_native_receipt_core_commit_duplicate_and_rollback',
                          'test_fresh_slot_binds_before_first_check_but_completed_vanilla_save_does_not',
                          'test_native_bridge_accepts_one_valid_receipt_and_rejects_wrong_or_unsupported_grants',
                          'test_reentrant_save_during_grant_serializes_complete_previous_receipt',
                          'test_event_receipts_wait_for_completion_and_reject_duplicate_effects'},
    'persistent_checks_v1':{'test_native_state_all_check_bits_and_wrong_version',
                            'test_managed_all_markers_commit_correct_bits_without_inventory_effect',
                            'test_server_check_sync_is_bounded_atomic_and_does_not_advance_receipts',
                            'test_save_checksum_matches_real_game_crc_routine'},
    'reward_suppression_v1':{'test_display_only_ids_never_reach_inventory_even_without_a_marker',
                             'test_managed_wrong_identity_and_unknown_markers_do_not_change_state'},
    'victory_v1':{'test_native_victory_reads_inspected_ending_flag_only_for_bound_save'},
    'indexed_rewards_v1':{'test_real_inner_indexed_allocations_preserve_existing_vanilla_bits',
                          'test_unmanaged_vanilla_collectible_indexes_are_reserved'},
    'progressive_rewards_v1':{'test_real_inner_game_equipment_and_progressive_storage'},
    'dungeon_rewards_v1':{'test_dungeon_receipts_target_all_nine_records_and_match_real_game_fields'},
}
CAPABILITIES=tuple(sorted(CAPABILITY_TESTS))

def verified_capabilities(passed,success):
    passed=set(passed)
    return sorted(name for name,tests in CAPABILITY_TESTS.items() if success and tests<=passed)
