/*
 * Copyright 2023 Capypara and the SkyTemple Contributors
 *
 * This file is part of SkyTemple.
 *
 * SkyTemple is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * SkyTemple is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with SkyTemple.  If not, see <https://www.gnu.org/licenses/>.
 */

use crate::alloc_table::{EmulatorMemAllocType, EmulatorMemTable, EmulatorMemTableEntry};
use crate::display_buffer::*;
use crate::eos_debug::*;
use crate::event_queue::*;
use crate::input::*;
use crate::language::*;
use crate::memory::*;
use crate::system::*;
use crate::{SCREEN_HEIGHT, SCREEN_HEIGHT_BOTH, SCREEN_PIXEL_SIZE, SCREEN_WIDTH};
use log::{debug, info};
use pyo3::prelude::*;
use pyo3::Python;

#[pymodule]
fn skytemple_ssb_emulator(py: Python, module: &PyModule) -> PyResult<()> {
    // TODO: Performance of acquiring the GIL for logs?
    // should probably revamp logging in SkyTemple / Ssb Debugger itself instead
    // (configure debug logging only for development and then make sure pyo3_log
    // caches the log levels so it doesn't take the GIL if debug logging is disabled for
    // debug logs.
    pyo3_log::init();
    debug!("Loading skytemple_ssb_emulator...");

    module.add("SCREEN_WIDTH", SCREEN_WIDTH)?;
    module.add("SCREEN_HEIGHT", SCREEN_HEIGHT)?;
    module.add("SCREEN_HEIGHT_BOTH", SCREEN_HEIGHT_BOTH)?;
    module.add("SCREEN_PIXEL_SIZE", SCREEN_PIXEL_SIZE)?;

    module.add_class::<EmulatorMemAllocType>()?;
    module.add_class::<EmulatorMemTableEntry>()?;
    module.add_class::<EmulatorMemTable>()?;
    module.add_class::<Language>()?;
    module.add_class::<EmulatorLogType>()?;
    module.add_class::<BreakpointStateType>()?;
    module.add_class::<BreakpointState>()?;

    let emulator_keys = PyModule::new(py, "EmulatorKeys")?;
    emulator_keys.add(
        "__doc__",
        "DS key identifiers. NB_KEYS contains the total number of keys.",
    )?;
    emulator_keys.add("NB_KEYS", NB_KEYS)?;
    emulator_keys.add("KEY_NONE", EmulatorKeys::None as u8)?;
    emulator_keys.add("KEY_A", EmulatorKeys::A as u8)?;
    emulator_keys.add("KEY_B", EmulatorKeys::B as u8)?;
    emulator_keys.add("KEY_SELECT", EmulatorKeys::Select as u8)?;
    emulator_keys.add("KEY_START", EmulatorKeys::Start as u8)?;
    emulator_keys.add("KEY_RIGHT", EmulatorKeys::Right as u8)?;
    emulator_keys.add("KEY_LEFT", EmulatorKeys::Left as u8)?;
    emulator_keys.add("KEY_UP", EmulatorKeys::Up as u8)?;
    emulator_keys.add("KEY_DOWN", EmulatorKeys::Down as u8)?;
    emulator_keys.add("KEY_R", EmulatorKeys::R as u8)?;
    emulator_keys.add("KEY_L", EmulatorKeys::L as u8)?;
    emulator_keys.add("KEY_X", EmulatorKeys::X as u8)?;
    emulator_keys.add("KEY_Y", EmulatorKeys::Y as u8)?;
    emulator_keys.add("KEY_DEBUG", EmulatorKeys::Debug as u8)?;
    emulator_keys.add("KEY_BOOST", EmulatorKeys::Boost as u8)?;
    emulator_keys.add("KEY_LID", EmulatorKeys::Lid as u8)?;
    emulator_keys.add("NO_KEY_SET", NO_KEY_SET)?;
    module.add_submodule(emulator_keys)?;

    module.add_function(wrap_pyfunction!(emulator_is_initialized, module)?)?;
    module.add_function(wrap_pyfunction!(emulator_start, module)?)?;
    module.add_function(wrap_pyfunction!(emulator_reset, module)?)?;
    module.add_function(wrap_pyfunction!(emulator_pause, module)?)?;
    module.add_function(wrap_pyfunction!(emulator_resume, module)?)?;
    module.add_function(wrap_pyfunction!(emulator_shutdown, module)?)?;
    module.add_function(wrap_pyfunction!(emulator_open_rom, module)?)?;
    module.add_function(wrap_pyfunction!(emulator_set_language, module)?)?;
    module.add_function(wrap_pyfunction!(emulator_is_running, module)?)?;
    module.add_function(wrap_pyfunction!(emulator_volume_set, module)?)?;
    module.add_function(wrap_pyfunction!(emulator_savestate_save_file, module)?)?;
    module.add_function(wrap_pyfunction!(emulator_savestate_load_file, module)?)?;
    module.add_function(wrap_pyfunction!(emulator_display_buffer_as_rgbx, module)?)?;
    module.add_function(wrap_pyfunction!(emulator_tick, module)?)?;
    module.add_function(wrap_pyfunction!(emulator_unpress_all_keys, module)?)?;
    module.add_function(wrap_pyfunction!(emulator_joy_init, module)?)?;
    module.add_function(wrap_pyfunction!(emulator_set_boost, module)?)?;
    module.add_function(wrap_pyfunction!(emulator_read_mem, module)?)?;
    module.add_function(wrap_pyfunction!(emulator_read_mem_from_ptr, module)?)?;
    module.add_function(wrap_pyfunction!(
        emulator_read_mem_from_ptr_with_validity_check,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(emulator_poll, module)?)?;
    module.add_function(wrap_pyfunction!(emulator_wait_one_cycle, module)?)?;
    module.add_function(wrap_pyfunction!(emulator_load_controls, module)?)?;
    module.add_function(wrap_pyfunction!(emulator_get_kbcfg, module)?)?;
    module.add_function(wrap_pyfunction!(emulator_get_jscfg, module)?)?;
    module.add_function(wrap_pyfunction!(emulator_set_kbcfg, module)?)?;
    module.add_function(wrap_pyfunction!(emulator_set_jscfg, module)?)?;
    module.add_function(wrap_pyfunction!(emulator_keymask, module)?)?;
    module.add_function(wrap_pyfunction!(emulator_keypad_add_key, module)?)?;
    module.add_function(wrap_pyfunction!(emulator_keypad_rm_key, module)?)?;
    module.add_function(wrap_pyfunction!(emulator_touch_set_pos, module)?)?;
    module.add_function(wrap_pyfunction!(emulator_touch_release, module)?)?;
    module.add_function(wrap_pyfunction!(emulator_supports_joystick, module)?)?;
    module.add_function(wrap_pyfunction!(emulator_get_joy_number_connected, module)?)?;
    module.add_function(wrap_pyfunction!(emulator_joy_get_set_key, module)?)?;
    module.add_function(wrap_pyfunction!(emulator_get_key_names, module)?)?;
    module.add_function(wrap_pyfunction!(
        emulator_register_script_variable_set,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        emulator_unregister_script_variable_set,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(emulator_sync_tables, module)?)?;
    module.add_function(wrap_pyfunction!(emulator_register_script_debug, module)?)?;
    module.add_function(wrap_pyfunction!(emulator_unregister_script_debug, module)?)?;
    module.add_function(wrap_pyfunction!(emulator_register_debug_print, module)?)?;
    module.add_function(wrap_pyfunction!(emulator_unregister_debug_print, module)?)?;
    module.add_function(wrap_pyfunction!(emulator_register_debug_flag, module)?)?;
    module.add_function(wrap_pyfunction!(emulator_unregister_debug_flag, module)?)?;
    module.add_function(wrap_pyfunction!(emulator_register_exec_ground, module)?)?;
    module.add_function(wrap_pyfunction!(emulator_register_ssb_load, module)?)?;
    module.add_function(wrap_pyfunction!(emulator_unregister_ssb_load, module)?)?;
    module.add_function(wrap_pyfunction!(emulator_register_ssx_load, module)?)?;
    module.add_function(wrap_pyfunction!(emulator_unregister_ssx_load, module)?)?;
    module.add_function(wrap_pyfunction!(emulator_register_talk_load, module)?)?;
    module.add_function(wrap_pyfunction!(emulator_unregister_talk_load, module)?)?;
    module.add_function(wrap_pyfunction!(
        emulator_register_unionall_load_addr_change,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        emulator_unregister_unionall_load_addr_change,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(emulator_unionall_load_address, module)?)?;
    module.add_function(wrap_pyfunction!(
        emulator_unionall_load_address_update,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(emulator_write_game_variable, module)?)?;
    module.add_function(wrap_pyfunction!(emulator_set_debug_mode, module)?)?;
    module.add_function(wrap_pyfunction!(emulator_set_debug_flag_1, module)?)?;
    module.add_function(wrap_pyfunction!(emulator_set_debug_flag_2, module)?)?;
    module.add_function(wrap_pyfunction!(emulator_set_debug_dungeon_skip, module)?)?;
    module.add_function(wrap_pyfunction!(emulator_sync_vars, module)?)?;
    module.add_function(wrap_pyfunction!(emulator_sync_local_vars, module)?)?;
    module.add_function(wrap_pyfunction!(
        emulator_debug_init_breakpoint_manager,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        emulator_debug_set_loaded_ssb_breakable,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        emulator_debug_breakpoints_disabled_get,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        emulator_debug_breakpoints_disabled_set,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(emulator_debug_breakpoints_resync, module)?)?;
    module.add_function(wrap_pyfunction!(emulator_debug_breakpoint_add, module)?)?;
    module.add_function(wrap_pyfunction!(emulator_debug_breakpoint_remove, module)?)?;
    module.add_function(wrap_pyfunction!(
        emulator_breakpoints_get_saved_in_ram_for,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        emulator_debug_register_breakpoint_callbacks,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        emulator_breakpoints_set_loaded_ssb_files,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        emulator_breakpoints_set_load_ssb_for,
        module
    )?)?;

    info!("Loaded skytemple_ssb_emulator.");

    Ok(())
}
