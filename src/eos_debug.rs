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

use crate::pycallbacks::*;
use crate::script_runtime::ScriptRuntime;
use crate::state::{
    command_channel_blocking_send, command_channel_send, DebugCommand, EmulatorCommand, BOOST_MODE,
    BREAK, BREAKPOINT_MANAGER, ERR_EMU_INIT, UNIONALL_LOAD_ADDRESS,
};
use crate::stbytes::StBytes;
use log::debug;
use pyo3::exceptions::{PyIOError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PySequence;
use pyo3::AsPyPointer;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::fs::read_to_string;
use std::path::PathBuf;
use std::sync::atomic::Ordering;

#[pyclass(module = "ssb_emulator")]
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EmulatorLogType {
    Printfs,
    DebugPrint,
}

#[pyclass(module = "ssb_emulator")]
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BreakpointStateType {
    // INITIAL STATE: The breakpoint is being stopped at.
    Stopped = 0,
    // FINAL STATES: What happened / what to do next? - See the corresponding methods of BreakpointState.
    FailHard = 1,
    Resume = 2,
    StepOver = 3,
    StepInto = 4,
    StepOut = 5,
    StepNext = 6,
    // Manually step to an opcode offset of the SSB file currently stopped for.
    StepManual = 10,
}

#[pyfunction]
/// Enable or disable boost mode. In this mode some debugging hooks may not be executed to improve
/// emulator performance.
pub fn emulator_set_boost(state: bool) {
    dbg_trace!("emulator_set_boost - {state}");
    BOOST_MODE.store(state, Ordering::Relaxed)
}

#[pyfunction]
#[pyo3(signature = (save_script_value_addr, save_script_value_at_index_addr, hook) )]
/// Register a hook to call when a script variable was set. Replaces the previously registered hook.
/// The hook is called asynchronously by polling `emulator_poll` on the receiving thread.
pub fn emulator_register_script_variable_set(
    save_script_value_addr: Option<&PySequence>,
    save_script_value_at_index_addr: Option<&PySequence>,
    hook: PyObject,
) -> PyResult<()> {
    dbg_trace!("emulator_register_script_variable_set");
    command_channel_send(EmulatorCommand::Debug(
        DebugCommand::RegisterScriptVariableSet {
            save_script_value_addr: read_hook_addr(save_script_value_addr)?,
            save_script_value_at_index_addr: read_hook_addr(save_script_value_at_index_addr)?,
            hook: DebugRegisterScriptVariableSetCallback(hook),
        },
    ));
    Ok(())
}

#[pyfunction]
/// Unregister all potentially previously registered hooks for setting script variables.
pub fn emulator_unregister_script_variable_set() {
    dbg_trace!("emulator_unregister_script_variable_set");
    command_channel_send(EmulatorCommand::Debug(
        DebugCommand::UnregisterScriptVariableSet,
    ))
}

#[pyfunction]
#[pyo3(signature = (func_that_calls_command_parsing_addr, hook) )]
/// Registers the debugger. The debugger will break depending on the state of the breakpoints currently
/// configured.
///
/// Also register a hook to process script engine debugging events. Replaces the previously registered hooks.
/// The hooks are called asynchronously by polling `emulator_poll` on the receiving thread.
pub fn emulator_register_script_debug(
    func_that_calls_command_parsing_addr: Option<&PySequence>,
    hook: PyObject,
) -> PyResult<()> {
    dbg_trace!("emulator_register_script_debug");
    command_channel_send(EmulatorCommand::Debug(DebugCommand::RegisterScriptDebug {
        func_that_calls_command_parsing_addr: read_hook_addr(func_that_calls_command_parsing_addr)?,
        hook: DebugRegisterScriptDebugCallback(hook),
    }));
    Ok(())
}

#[pyfunction]
/// Unregister all potentially previously registered hooks for processing script debugging events.
pub fn emulator_unregister_script_debug() {
    dbg_trace!("emulator_unregister_script_debug");
    command_channel_send(EmulatorCommand::Debug(DebugCommand::UnregisterScriptDebug))
}

#[pyfunction]
#[pyo3(signature = (printf_r0_functions_addr, printf_r1_functions_addr, script_hook_addr, hook) )]
/// Register a hook to process debug print logging. Replaces the previously registered hook.
/// The hook is called asynchronously by polling `emulator_poll` on the receiving thread.
///
/// The messaged passed to the hook may already be preformatted for display in the UI.
///
/// # printf hooks
/// `printf_r0_functions_addr` will be hooked into and will read registers for printf starting at r0,
/// `printf_r1_functions_addr` will also be hooked into but start reading at r1.
///
/// # script debug log hook
/// `script_hook_addr` must be 0x3C40 bytes into the `ScriptCommandParsing` function of the game. This hook
/// processes `debug_Print` and related script opcodes.
pub fn emulator_register_debug_print(
    printf_r0_functions_addr: Option<&PySequence>,
    printf_r1_functions_addr: Option<&PySequence>,
    script_hook_addr: Option<&PySequence>,
    // def _(type: EmulatorLogType, msg: str)
    hook: PyObject,
) -> PyResult<()> {
    dbg_trace!("emulator_register_debug_print");
    command_channel_send(EmulatorCommand::Debug(DebugCommand::RegisterDebugPrint {
        printf_r0_functions_addr: read_hook_addr(printf_r0_functions_addr)?,
        printf_r1_functions_addr: read_hook_addr(printf_r1_functions_addr)?,
        script_hook_addr: read_hook_addr(script_hook_addr)?,
        hook: DebugRegisterDebugPrintCallback(hook),
    }));
    Ok(())
}

#[pyfunction]
/// Unregister all potentially previously registered hooks for processing debug print logging.
pub fn emulator_unregister_debug_print() {
    dbg_trace!("emulator_unregister_debug_print");
    command_channel_send(EmulatorCommand::Debug(DebugCommand::UnregisterDebugPrint))
}

#[pyfunction]
#[pyo3(signature = (
    get_debug_flag_1_addr,
    get_debug_flag_2_addr,
    set_debug_flag_1_addr,
    set_debug_flag_2_addr,
    script_get_debug_mode_addr,
    hook
) )]
/// Register an internal hook to the game's functions to retrieve debug flag values to instead
/// return the flags
/// set by `emulator_set_debug_flag_1` and `emulator_set_debug_flag_2`.
///
/// These values are also overwritten, and reported back to the `hook_debug_flag` when they are
/// set by the game.
///
/// Additionally, hooks the script engine function
/// responsible to determine if script debugging is enabled and returns the value set by
/// `emulator_set_debug_mode`.
pub fn emulator_register_debug_flag(
    get_debug_flag_1_addr: Option<&PySequence>,
    get_debug_flag_2_addr: Option<&PySequence>,
    set_debug_flag_1_addr: Option<&PySequence>,
    set_debug_flag_2_addr: Option<&PySequence>,
    script_get_debug_mode_addr: Option<&PySequence>,
    hook: PyObject,
) -> PyResult<()> {
    dbg_trace!("emulator_register_debug_flag");
    command_channel_send(EmulatorCommand::Debug(DebugCommand::RegisterDebugFlag {
        get_debug_flag_1_addr: read_hook_addr(get_debug_flag_1_addr)?,
        get_debug_flag_2_addr: read_hook_addr(get_debug_flag_2_addr)?,
        set_debug_flag_1_addr: read_hook_addr(set_debug_flag_1_addr)?,
        set_debug_flag_2_addr: read_hook_addr(set_debug_flag_2_addr)?,
        script_get_debug_mode_addr: read_hook_addr(script_get_debug_mode_addr)?,
        hook: DebugRegisterDebugFlagCallback(hook),
    }));
    Ok(())
}

#[pyfunction]
/// Unregister all potentially previously registered hooks for processing debug flags.
pub fn emulator_unregister_debug_flag() {
    dbg_trace!("emulator_unregister_debug_flag");
    command_channel_send(EmulatorCommand::Debug(DebugCommand::UnregisterDebugFlag))
}

#[pyfunction]
/// Register a hook to run when the given address is executed. If the hook is None,
/// it is unregistered.
///
/// The hook is not called should overlay 11 not be loaded.
pub fn emulator_register_exec_ground(addr: u32, hook: Option<PyObject>) {
    dbg_trace!("emulator_register_exec_ground");
    command_channel_send(EmulatorCommand::Debug(DebugCommand::RegisterExecGround {
        addr,
        hook: hook.map(DebugRegisterExecGroundCallback),
    }))
}

#[pyfunction]
#[pyo3(signature = (ssb_load_addrs, hook) )]
/// Register a hook to run, whenever an SSB file is loaded.
///
/// The hook is not called should overlay 11 not be loaded.
pub fn emulator_register_ssb_load(
    ssb_load_addrs: Option<&PySequence>,
    // def _(name: str)
    hook: PyObject,
) -> PyResult<()> {
    dbg_trace!("emulator_register_ssb_load");
    command_channel_send(EmulatorCommand::Debug(DebugCommand::RegisterSsbLoad {
        ssb_load_addrs: read_hook_addr(ssb_load_addrs)?,
        hook: DebugRegisterSsbLoadCallback(hook),
    }));
    Ok(())
}

#[pyfunction]
/// Unregister SSB load hook.
pub fn emulator_unregister_ssb_load() {
    dbg_trace!("emulator_unregister_ssb_load");
    command_channel_send(EmulatorCommand::Debug(DebugCommand::UnregisterSsbLoad))
}

#[pyfunction]
#[pyo3(signature = (ssx_load_addrs, hook) )]
/// Register a hook to run, whenever an SSx file is loaded.
///
/// The hook is not called should overlay 11 not be loaded.
pub fn emulator_register_ssx_load(
    ssx_load_addrs: Option<&PySequence>,
    hook: PyObject,
) -> PyResult<()> {
    dbg_trace!("emulator_register_ssx_load");
    command_channel_send(EmulatorCommand::Debug(DebugCommand::RegisterSsxLoad {
        ssx_load_addrs: read_hook_addr(ssx_load_addrs)?,
        hook: DebugRegisterSsxLoadCallback(hook),
    }));
    Ok(())
}

#[pyfunction]
/// Unregister SSx load hook.
pub fn emulator_unregister_ssx_load() {
    dbg_trace!("emulator_unregister_ssx_load");
    command_channel_send(EmulatorCommand::Debug(DebugCommand::UnregisterSsxLoad))
}

#[pyfunction]
#[pyo3(signature = (talk_load_addrs, hook) )]
/// Register a hook to run, whenever a talk SSx file is loaded.
///
/// The hook is not called should overlay 11 not be loaded.
pub fn emulator_register_talk_load(
    talk_load_addrs: Option<&PySequence>,
    hook: PyObject,
) -> PyResult<()> {
    dbg_trace!("emulator_register_talk_load");
    command_channel_send(EmulatorCommand::Debug(DebugCommand::RegisterTalkLoad {
        talk_load_addrs: read_hook_addr(talk_load_addrs)?,
        hook: DebugRegisterTalkLoadCallback(hook),
    }));
    Ok(())
}

#[pyfunction]
/// Unregister SSx talk load hook.
pub fn emulator_unregister_talk_load() {
    dbg_trace!("emulator_unregister_talk_load");
    command_channel_send(EmulatorCommand::Debug(DebugCommand::UnregisterTalkLoad))
}

#[pyfunction]
/// Registers a hook for watching the unionall pointer. This allows retreiving it at any time via
/// [`emulator_unionall_load_address`].
pub fn emulator_register_unionall_load_addr_change(unionall_pointer: u32) {
    dbg_trace!("emulator_register_unionall_load_addr_change");
    command_channel_send(EmulatorCommand::Debug(
        DebugCommand::RegisterUnionallLoadAddrChange(unionall_pointer),
    ))
}

#[pyfunction]
/// Unregister unionall update watcher. The address returned will now no longer match the game
/// state.
pub fn emulator_unregister_unionall_load_addr_change() {
    dbg_trace!("emulator_unregister_unionall_load_addr_change");
    command_channel_send(EmulatorCommand::Debug(
        DebugCommand::UnregisterUnionallLoadAddrChange,
    ))
}

#[pyfunction]
/// Returns the address unionall is loaded at currently. May return 0 if not determinable.
pub fn emulator_unionall_load_address() -> u32 {
    dbg_trace!("emulator_unionall_load_address");
    UNIONALL_LOAD_ADDRESS.load(Ordering::Acquire)
}

#[pyfunction]
/// Fetches the current unionall load address from the emulator into the cache.
/// This requires `emulator_register_unionall_load_addr_change` to be called before.
pub fn emulator_unionall_load_address_update() {
    dbg_trace!("emulator_unionall_load_address_update");
    command_channel_blocking_send(EmulatorCommand::Debug(
        DebugCommand::UnionallLoadAddressUpdate,
    ))
}

#[pyfunction]
/// Queues writing the game variable to the game.
/// This is done at latest the next time the emulator's memory is ready to be written to.
pub fn emulator_write_game_variable(var_id: u32, var_offset: u32, value: i32) {
    dbg_trace!("emulator_write_game_variable - {var_id} - {var_offset} - {value}");
    command_channel_send(EmulatorCommand::Debug(DebugCommand::WriteGameVariable {
        var_id,
        var_offset,
        value,
    }))
}

#[pyfunction]
/// Queues writing the debug mode state.
/// This is done at latest the next time the emulator's memory is ready to be written to.
pub fn emulator_set_debug_mode(value: bool) {
    dbg_trace!("emulator_set_debug_mode - {value}");
    command_channel_send(EmulatorCommand::Debug(DebugCommand::SetDebugMode(value)));
}

#[pyfunction]
/// Queues writing a bit of debug flag 1.
/// This is done at latest the next time the emulator's memory is ready to be written to.
pub fn emulator_set_debug_flag_1(bit: usize, value: bool) {
    dbg_trace!("emulator_set_debug_flag_1 - {bit} - {value}");
    command_channel_send(EmulatorCommand::Debug(DebugCommand::SetDebugFlag1(
        bit, value,
    )));
}

#[pyfunction]
/// Queues writing a bit of debug flag 2.
/// This is done at latest the next time the emulator's memory is ready to be written to.
pub fn emulator_set_debug_flag_2(bit: usize, value: bool) {
    dbg_trace!("emulator_set_debug_flag_2 - {bit} - {value}");
    command_channel_send(EmulatorCommand::Debug(DebugCommand::SetDebugFlag2(
        bit, value,
    )));
}

#[pyfunction]
/// Enables or disables the automatic skip of dungeon floors when inside of dungeons.
pub fn emulator_set_debug_dungeon_skip(addr_of_ptr_to_dungeon_struct: u32, value: bool) {
    dbg_trace!("emulator_set_debug_dungeon_skip - {addr_of_ptr_to_dungeon_struct} - {value}");
    command_channel_send(EmulatorCommand::Debug(DebugCommand::SetDungeonSkip(
        addr_of_ptr_to_dungeon_struct,
        value,
    )));
}

#[pyfunction]
/// Retrieve the values of global variable values from the emulator and passes
/// them to the callback when ready and [`emulator_poll`] is called.
pub fn emulator_sync_vars(cb: PyObject) {
    dbg_trace!("emulator_sync_vars");
    command_channel_send(EmulatorCommand::Debug(DebugCommand::SyncGlobalVars(
        DebugSyncGlobalVarsCallback(cb),
    )));
}

#[pyfunction]
/// Retrieve the values of local variable values from the emulator and passes
/// them to the callback when ready and [`emulator_poll`] is called.
pub fn emulator_sync_local_vars(addr_of_pnt_to_breaked_for_entity: u32, cb: PyObject) {
    dbg_trace!("emulator_sync_local_vars");
    command_channel_send(EmulatorCommand::Debug(DebugCommand::SyncLocalVars(
        addr_of_pnt_to_breaked_for_entity,
        DebugSyncLocalVarsCallback(cb),
    )));
}

#[pyfunction]
/// Synchronize and retrieve and return the memory allocation tables and pass
/// them to the callback when ready and [`emulator_poll`] is called.
pub fn emulator_sync_tables(addr_mem_alloc_table: u32, cb: PyObject) {
    dbg_trace!("addr_mem_alloc_table");
    command_channel_send(EmulatorCommand::Debug(DebugCommand::SyncMemTables(
        addr_mem_alloc_table,
        DebugSyncMemTablesCallback(cb),
    )));
}

#[derive(Debug, Clone, PartialEq, Copy)]
pub enum ScriptTargetType {
    Generic = 1,
    Actor = 3,
    Object = 4,
    Performer = 5,
    Coroutine = 9,
    Invalid = -1,
}

#[derive(Debug, Clone)]
pub struct BreakpointInfo {
    pub opcode_offset: Option<u32>,
    pub is_in_unionall: Option<bool>,
    pub script_target_type: ScriptTargetType,
    pub script_target_slot: u32,
}

impl BreakpointInfo {
    fn matches(&self, other: &Self) -> bool {
        if self.script_target_type != other.script_target_type {
            return false;
        }
        if self.script_target_slot != other.script_target_slot {
            return false;
        }
        if self.is_in_unionall.is_some() && self.is_in_unionall != other.is_in_unionall {
            return false;
        }
        if self.opcode_offset.is_some() && self.opcode_offset != other.opcode_offset {
            return false;
        }
        true
    }
}

pub const MAX_SSX: usize = 3;
pub const TALK_HANGER_OFFSET: usize = 3;
pub const MAX_SSB: usize = MAX_SSX + TALK_HANGER_OFFSET;

pub struct BreakpointManager {
    breakpoints_json_path: PathBuf,
    pub(crate) breakpoints_disabled: bool,
    pub(crate) force_break: bool,
    pub(crate) breakpoints_disabled_for_tick: Option<u64>,
    /// This temporary breakpoint is set by the debugger while stepping
    temporary_breakpoints: Vec<BreakpointInfo>,
    breakpoint_mapping: HashMap<String, HashSet<u32>>,
    new_breakpoint_mapping: HashMap<String, HashSet<u32>>,
    callbacks_add: Vec<BreakpointChangeCallback>,
    callbacks_remove: Vec<BreakpointChangeCallback>,
    ssb_breakable: HashMap<String, bool>,
    /// Loaded SSB files per hanger.
    /// This is to be kept in sync with ssb-debugger GroundEngineState._loaded_ssb_files.
    pub(crate) loaded_ssb_files: [Option<String>; MAX_SSB + 1],
    /// The hanger currently active, that the next SSB will be loaded for.
    /// This is to be kept in sync with ssb-debugger GroundEngineState._load_ssb_for.
    pub(crate) load_ssb_for: Option<u8>,
}

impl BreakpointManager {
    fn new(breakpoints_json_filename: &str) -> Self {
        dbg_trace!("BreakpointManager::new - {breakpoints_json_filename}");
        let breakpoints_json_path = PathBuf::from(breakpoints_json_filename);

        let breakpoint_mapping: HashMap<String, HashSet<u32>> = {
            if breakpoints_json_path.exists() {
                read_to_string(&breakpoints_json_path)
                    .map(|content| serde_json::from_str(&content).unwrap_or_default())
                    .unwrap_or_default()
            } else {
                Default::default()
            }
        };

        Self {
            breakpoints_json_path,
            breakpoints_disabled: false,
            force_break: false,
            breakpoints_disabled_for_tick: None,
            temporary_breakpoints: vec![],
            breakpoint_mapping,
            new_breakpoint_mapping: Default::default(),
            callbacks_add: vec![],
            callbacks_remove: vec![],
            ssb_breakable: Default::default(),
            loaded_ssb_files: [None, None, None, None, None, None, None],
            load_ssb_for: None,
        }
    }

    fn register_callbacks(
        &mut self,
        on_breakpoint_added: BreakpointChangeCallback,
        on_breakpoint_removed: BreakpointChangeCallback,
    ) {
        dbg_trace!("BreakpointManager::register_callbacks");
        self.callbacks_add.push(on_breakpoint_added);
        self.callbacks_remove.push(on_breakpoint_removed);
    }

    fn set_loaded_ssb_breakable(&mut self, ssb_filename: &str, value: bool) {
        dbg_trace!("BreakpointManager::set_loaded_ssb_breakable - {ssb_filename} - {value}");
        self.ssb_breakable.insert(ssb_filename.to_string(), value);
    }

    fn resync(&mut self, ssb_filename: &str, b_points: &PySequence, ssb: &PyAny) -> PyResult<()> {
        dbg_trace!("BreakpointManager::resync - {ssb_filename}");
        debug!("{ssb_filename}: Breakpoint resync");
        let ram_state_up_to_date = ssb.getattr("ram_state_up_to_date")?.extract()?;
        let ssb_filename = ssb_filename.to_string();

        let collected_b_points = b_points
            .iter()?
            .map(|v| v.and_then(|vv| vv.extract()))
            .collect::<PyResult<HashSet<u32>>>()?;

        let mapping_to_write_to_file = {
            if ram_state_up_to_date {
                // We can just update.
                self.breakpoint_mapping
                    .insert(ssb_filename, collected_b_points);
                Cow::Borrowed(&self.breakpoint_mapping)
            } else {
                // We need to use a temporary mapping for now!
                self.new_breakpoint_mapping
                    .insert(ssb_filename.clone(), collected_b_points.clone());
                ssb.call_method1(
                    "register_reload_event_manager",
                    (BreakPointManagerPyWaitForSsbUpdateCallback,),
                )?;
                let mut mapping_to_write_to_file_out = self.breakpoint_mapping.clone();
                mapping_to_write_to_file_out.insert(ssb_filename, collected_b_points);
                Cow::Owned(mapping_to_write_to_file_out)
            }
        };

        // TODO: A breakpoint update in another file will just override this again...
        //       we should probably keep track of two full sets of the state (current ROM / current RAM)
        fs::write(
            &self.breakpoints_json_path,
            serde_json::to_string(&mapping_to_write_to_file)
                .map_err(|_v| PyIOError::new_err("Failed to write to breakpoints file."))?,
        )
        .map_err(|_v| PyIOError::new_err("Failed to write to breakpoints file."))?;

        Ok(())
    }

    fn wait_for_ssb_update(&mut self, ssb: &PyAny) -> PyResult<()> {
        dbg_trace!("BreakpointManager::wait_for_ssb_update");
        let ssb_filename: &str = ssb.getattr("filename")?.extract()?;
        debug!("got ssb update for {ssb_filename}");
        if self.new_breakpoint_mapping.contains_key(ssb_filename) {
            if let Some(v) = self.new_breakpoint_mapping.remove(ssb_filename) {
                self.breakpoint_mapping.insert(ssb_filename.to_string(), v);
            }
            self.save_mapping()?;
        }
        Ok(())
    }

    fn add(&mut self, py: Python, ssb_filename: &str, opcode_offset: u32) -> PyResult<()> {
        dbg_trace!("BreakpointManager::add - {ssb_filename} - {opcode_offset}");
        debug!("{ssb_filename}: Breakpoint add: {opcode_offset}");
        let entry = self
            .breakpoint_mapping
            .entry(ssb_filename.to_string())
            .or_default();
        if entry.contains(&opcode_offset) {
            return Ok(());
        }
        entry.insert(opcode_offset);
        self.save_mapping()?;
        for cb in &self.callbacks_add {
            // SAFETY NOTE: This is not pub, so it's only callable from this module. In this module it's
            // only exposed through the emulator_* python functions, which only support calling from main
            // thread. As long as that is done, everything is safe and we can call the callbacks now.
            cb.0.call1(py, (ssb_filename, opcode_offset))?;
        }
        Ok(())
    }

    fn remove(&mut self, py: Python, ssb_filename: &str, opcode_offset: u32) -> PyResult<()> {
        dbg_trace!("BreakpointManager::remove - {ssb_filename} - {opcode_offset}");
        debug!("{ssb_filename}: Breakpoint remove: {opcode_offset}");
        if let Some(entry) = self.breakpoint_mapping.get_mut(ssb_filename) {
            if entry.remove(&opcode_offset) {
                self.save_mapping()?;
                for cb in &self.callbacks_remove {
                    // SAFETY NOTE: See add.
                    cb.0.call1(py, (ssb_filename, opcode_offset))?;
                }
            }
        }
        Ok(())
    }

    /// Return the breakpoints that are saved in RAM for fn. These might be the tempoary breakpoints we stored!
    fn get_saved_in_ram_for(&mut self, ssb_filename: &str) -> Vec<u32> {
        dbg_trace!("BreakpointManager::get_saved_in_ram_for - {ssb_filename}");
        let mut buffer = Vec::with_capacity(50);
        if let Some(ops) = self.new_breakpoint_mapping.get(ssb_filename) {
            for opoff in ops {
                buffer.push(*opoff);
            }
        }
        if let Some(ops) = self.breakpoint_mapping.get(ssb_filename) {
            for opoff in ops {
                buffer.push(*opoff);
            }
        }
        buffer
    }

    /// Checks if the breakpoint is in the active mapping or is the temporary breakpoint.
    /// script_target_* are only relevant for checking the temporary breakpoint.
    pub(crate) fn has(&self, filename: &str, info: &BreakpointInfo) -> bool {
        dbg_trace!("BreakpointManager::has - {filename}");
        for tbp in &self.temporary_breakpoints {
            if tbp.matches(info) {
                return true;
            }
        }
        if !self.breakpoint_mapping.contains_key(filename) {
            return false;
        }
        if !self.ssb_breakable.get(filename).unwrap_or(&true) {
            return false;
        }
        if let Some(opoff) = info.opcode_offset {
            if let Some(brks) = self.breakpoint_mapping.get(filename) {
                return brks.contains(&opoff);
            }
        }
        false
    }

    pub(crate) fn reset_temporary(&mut self) {
        dbg_trace!("BreakpointManager::reset_temporary");
        debug!("Reset temporary");
        self.temporary_breakpoints = vec![];
    }

    /// Set a temporary breakpoint.
    ///
    /// For the info:
    /// - is_in_unionall is optional:
    ///   - If None, will break at any opcode for the script target
    ///   - If True, will only break in unionall
    ///   - If False, will not break in unionall, but all other scripts.
    /// - opcode_addr is also optional, if set will only break at this opcode addr. Please note,
    ///   that is_in_unionall is still checked in that case.
    ///
    /// See has.
    pub(crate) fn add_temporary(&mut self, info: BreakpointInfo) {
        dbg_trace!("BreakpointManager::add_temporary");
        debug!("Set temporary: {info:?}");
        self.temporary_breakpoints.push(info);
    }

    fn save_mapping(&self) -> PyResult<()> {
        fs::write(
            &self.breakpoints_json_path,
            serde_json::to_string(&self.breakpoint_mapping)
                .map_err(|_v| PyIOError::new_err("Failed to write to breakpoints file."))?,
        )
        .map_err(|_v| PyIOError::new_err("Failed to write to breakpoints file."))
    }
}

#[pyclass]
struct BreakPointManagerPyWaitForSsbUpdateCallback;

#[pymethods]
impl BreakPointManagerPyWaitForSsbUpdateCallback {
    fn __call__(&self, ssb: &PyAny) -> PyResult<()> {
        BREAKPOINT_MANAGER
            .lock()
            .unwrap()
            .as_mut()
            .expect(ERR_EMU_INIT)
            .wait_for_ssb_update(ssb)
    }
}

#[pyfunction]
/// (Re)-initializes the debug breakpoint manager.
pub fn emulator_debug_init_breakpoint_manager(breakpoints_json_filename: &str) {
    dbg_trace!("emulator_debug_init_breakpoint_manager");
    *BREAKPOINT_MANAGER.lock().unwrap() = Some(BreakpointManager::new(breakpoints_json_filename));
}

#[pyfunction]
/// Change whether the SSB file identified by the given name can currently be breaked in.
/// A file is not debuggable, if an old state is loaded in RAM and old breakpoint mappings are not available.
///
/// Defaults to true for all files.
pub fn emulator_debug_set_loaded_ssb_breakable(ssb_filename: &str, value: bool) {
    dbg_trace!("emulator_debug_set_loaded_ssb_breakable - {ssb_filename} - {value}");
    BREAKPOINT_MANAGER
        .lock()
        .unwrap()
        .as_mut()
        .expect(ERR_EMU_INIT)
        .set_loaded_ssb_breakable(ssb_filename, value)
}

#[pyfunction]
/// Whether halting at breakpoints is currently globally disabled.
pub fn emulator_debug_breakpoints_disabled_get() -> bool {
    dbg_trace!("emulator_debug_breakpoints_disabled_get");
    BREAKPOINT_MANAGER
        .lock()
        .unwrap()
        .as_ref()
        .expect(ERR_EMU_INIT)
        .breakpoints_disabled
}

#[pyfunction]
/// Set whether halting at breakpoints is currently globally disabled.
pub fn emulator_debug_breakpoints_disabled_set(value: bool) {
    dbg_trace!("emulator_debug_breakpoints_disabled_set");
    BREAKPOINT_MANAGER
        .lock()
        .unwrap()
        .as_mut()
        .expect(ERR_EMU_INIT)
        .breakpoints_disabled = value;
}

#[pyfunction]
/// Re-synchronize breakpoints for the given ssb file.
///         
/// This is triggered, after a ssb file was saved.
/// If the file is still open in the ground engine, the new state is written to file and
/// a temporary dict, but is not used yet. The Breakpoint register registers itself as a
/// callback for that SSB file and waits until it is no longer loaded in the ground engine.
/// If the file is not open in the ground engine, the changes are applied immediately.
///
/// Callbacks for adding are NOT called as for emulator_debug_breakpoint_add.
pub fn emulator_debug_breakpoints_resync(
    ssb_filename: &str,
    b_points: &PySequence,
    ssb_loaded_file: &PyAny,
) -> PyResult<()> {
    dbg_trace!("emulator_debug_breakpoints_resync - {ssb_filename}");
    BREAKPOINT_MANAGER
        .lock()
        .unwrap()
        .as_mut()
        .expect(ERR_EMU_INIT)
        .resync(ssb_filename, b_points, ssb_loaded_file)
}

#[pyfunction]
/// Add a breakpoint for the given ssb file.
pub fn emulator_debug_breakpoint_add(
    py: Python,
    ssb_filename: &str,
    opcode_offset: u32,
) -> PyResult<()> {
    dbg_trace!("emulator_debug_breakpoint_add - {ssb_filename} - {opcode_offset}");
    BREAKPOINT_MANAGER
        .lock()
        .unwrap()
        .as_mut()
        .expect(ERR_EMU_INIT)
        .add(py, ssb_filename, opcode_offset)
}

#[pyfunction]
/// Remove a breakpoint for the given ssb file, if it exists. Otherwise do nothing.
pub fn emulator_debug_breakpoint_remove(
    py: Python,
    ssb_filename: &str,
    opcode_offset: u32,
) -> PyResult<()> {
    dbg_trace!("emulator_debug_breakpoint_remove - {ssb_filename} - {opcode_offset}");
    BREAKPOINT_MANAGER
        .lock()
        .unwrap()
        .as_mut()
        .expect(ERR_EMU_INIT)
        .remove(py, ssb_filename, opcode_offset)
}

#[pyfunction]
/// Returns all breakpoints currently stored for the given ssb file in RAM.
pub fn emulator_breakpoints_get_saved_in_ram_for(ssb_filename: &str) -> Vec<u32> {
    dbg_trace!("emulator_breakpoints_get_saved_in_ram_for - {ssb_filename}");
    BREAKPOINT_MANAGER
        .lock()
        .unwrap()
        .as_mut()
        .expect(ERR_EMU_INIT)
        .get_saved_in_ram_for(ssb_filename)
}

#[pyfunction]
/// Register callbacks to call when breakpoints are added or removed.
/// The callbacks may be called when calling emulator_poll, or directly when
/// emulator_debug_breakpoint_add or emulator_debug_breakpoint_remove are called.
pub fn emulator_debug_register_breakpoint_callbacks(
    on_breakpoint_added: PyObject,
    on_breakpoint_removed: PyObject,
) {
    dbg_trace!("emulator_debug_register_breakpoint_callbacks");
    BREAKPOINT_MANAGER
        .lock()
        .unwrap()
        .as_mut()
        .expect(ERR_EMU_INIT)
        .register_callbacks(
            BreakpointChangeCallback(on_breakpoint_added),
            BreakpointChangeCallback(on_breakpoint_removed),
        )
}

#[pyfunction]
/// Set the loaded SSB files for all 7 hangers. This is needed when loading save states,
/// resetting the ROM etc.
pub fn emulator_breakpoints_set_loaded_ssb_files(
    hanger0: Option<&str>,
    hanger1: Option<&str>,
    hanger2: Option<&str>,
    hanger3: Option<&str>,
    hanger4: Option<&str>,
    hanger5: Option<&str>,
    hanger6: Option<&str>,
) {
    dbg_trace!("emulator_breakpoints_set_loaded_ssb_files");
    BREAKPOINT_MANAGER
        .lock()
        .unwrap()
        .as_mut()
        .expect(ERR_EMU_INIT)
        .loaded_ssb_files = [
        hanger0.map(ToString::to_string),
        hanger1.map(ToString::to_string),
        hanger2.map(ToString::to_string),
        hanger3.map(ToString::to_string),
        hanger4.map(ToString::to_string),
        hanger5.map(ToString::to_string),
        hanger6.map(ToString::to_string),
    ]
}

#[pyfunction]
/// Set the hanger that an SSB will be loaded for next. This is needed when loading save states, resetting the ROM etc.
pub fn emulator_breakpoints_set_load_ssb_for(hanger_id: Option<u8>) {
    dbg_trace!("emulator_breakpoints_set_load_ssb_for - {hanger_id:?}");
    BREAKPOINT_MANAGER
        .lock()
        .unwrap()
        .as_mut()
        .expect(ERR_EMU_INIT)
        .load_ssb_for = hanger_id
}

#[derive(Debug)]
#[pyclass]
/// The current state of the stepping mechanism of the debugger.
/// If is_stopped(), the code execution of the emulator thread is currently on hold.
///
/// The object may optionally have a file state object, which describes more about the debugger state
/// for this breakpoint (eg. which source file is breaked in, if breaked on macro call)
///
/// These objects are not reusable. They can not transition back to the initial STOPPED state.
pub struct BreakpointState {
    #[pyo3(get, set)]
    file_state: Option<PyObject>,
    #[pyo3(get)]
    state: BreakpointStateType,
    #[pyo3(get)]
    script_runtime_struct_addr: u32,
    #[pyo3(get)]
    script_runtime_struct_mem: StBytes<'static>,
    #[pyo3(get)]
    script_target_slot_id: u32,
    #[pyo3(get)]
    local_vars_values: Vec<i32>,
    #[pyo3(get)]
    current_opcode: u32,
    #[pyo3(get)]
    hanger_id: u8,
    release_hooks: Vec<BreakpointStateReleaseCallback>,
    manual_step_opcode_offset: Option<u32>,
}

impl BreakpointState {
    /// Creates a new breakpoint state.
    /// NOTE: This also sets the global break resume info to stopped.
    pub(crate) fn new(
        srs: &ScriptRuntime,
        srs_addr: u32,
        script_target_slot_id: u32,
        local_vars_values: Vec<i32>,
    ) -> Self {
        dbg_trace!("BreakpointState::new - {script_target_slot_id}");
        let break_signal = BREAK.clone();
        let (break_mutex, _) = &*break_signal;
        let mut state_now = break_mutex
            .lock()
            .expect("Breakpoint controller panicked, bailing!");
        *state_now = BreakpointResumeInfo {
            state: BreakpointStateType::Stopped,
            manual_step_opcode_offset: None,
        };

        Self {
            file_state: None,
            state: BreakpointStateType::Stopped,
            script_target_slot_id,
            current_opcode: srs.current_opcode_addr_relative,
            hanger_id: srs.hanger_ssb,
            release_hooks: vec![],
            manual_step_opcode_offset: None,
            script_runtime_struct_addr: srs_addr,
            script_runtime_struct_mem: StBytes(Cow::Owned(srs.clone().into_inner())),
            local_vars_values,
        }
    }
}

#[pymethods]
impl BreakpointState {
    /// Called when polling the emulator after the debugging break has been released.
    pub fn add_release_hook(&mut self, hook: PyObject) {
        dbg_trace!("BreakpointState::add_release_hook");
        self.release_hooks
            .push(BreakpointStateReleaseCallback(hook));
    }

    pub fn is_stopped(&self) -> bool {
        dbg_trace!("BreakpointState::is_stopped");
        self.state == BreakpointStateType::Stopped
    }

    /// Immediately abort debugging and don't break again it this tick.
    pub fn fail_hard(slf: &PyCell<Self>) -> PyResult<()> {
        dbg_trace!("BreakpointState::fail_hard");
        let mut slfbrw = slf.borrow_mut();
        slfbrw.state = BreakpointStateType::FailHard;
        Self::wakeup(slfbrw)
    }

    /// Resume normal code execution.
    pub fn resume(slf: &PyCell<Self>) -> PyResult<()> {
        dbg_trace!("BreakpointState::resume");
        let mut slfbrw = slf.borrow_mut();
        slfbrw.state = BreakpointStateType::Resume;
        Self::wakeup(slfbrw)
    }

    /// Step into the current call (if it's a call that creates a call stack), otherwise same as
    /// step over.
    pub fn step_into(slf: &PyCell<Self>) -> PyResult<()> {
        dbg_trace!("BreakpointState::step_into");
        let mut slfbrw = slf.borrow_mut();
        slfbrw.state = BreakpointStateType::StepInto;
        Self::wakeup(slfbrw)
    }

    /// Step over the current call (remain in the current script file + skip debugging any calls
    /// to subroutines).
    pub fn step_over(slf: &PyCell<Self>) -> PyResult<()> {
        dbg_trace!("BreakpointState::step_over");
        let mut slfbrw = slf.borrow_mut();
        slfbrw.state = BreakpointStateType::StepOver;
        Self::wakeup(slfbrw)
    }

    /// Step out of the current routine, if there's a call stack, otherwise same as resume.
    pub fn step_out(slf: &PyCell<Self>) -> PyResult<()> {
        dbg_trace!("BreakpointState::step_out");
        let mut slfbrw = slf.borrow_mut();
        slfbrw.state = BreakpointStateType::StepOut;
        Self::wakeup(slfbrw)
    }

    /// Break at the next opcode, even if it's for a different script target.
    pub fn step_next(slf: &PyCell<Self>) -> PyResult<()> {
        dbg_trace!("BreakpointState::step_next");
        let mut slfbrw = slf.borrow_mut();
        slfbrw.state = BreakpointStateType::StepNext;
        Self::wakeup(slfbrw)
    }

    /// Transition to the StepManual state and set the opcode to halt at.
    pub fn step_manual(slf: &PyCell<Self>, opcode_offset: u32) -> PyResult<()> {
        dbg_trace!("BreakpointState::step_manual - {opcode_offset}");
        let mut slfbrw = slf.borrow_mut();
        slfbrw.state = BreakpointStateType::StepManual;
        slfbrw.manual_step_opcode_offset = Some(opcode_offset);
        Self::wakeup(slfbrw)
    }

    /// Transition to the specified state. Can not transition to Stopped.
    pub fn transition(slf: &PyCell<Self>, state_type: BreakpointStateType) -> PyResult<()> {
        dbg_trace!("BreakpointState::transition");
        let mut slfbrw = slf.borrow_mut();
        if state_type == BreakpointStateType::Stopped {
            return Err(PyValueError::new_err(
                "Can not transition breakpoint state to stopped.",
            ));
        }
        slfbrw.state = state_type;
        Self::wakeup(slfbrw)
    }

    pub fn wakeup(slfbrw: PyRefMut<BreakpointState>) -> PyResult<()> {
        dbg_trace!("BreakpointState::wakeup");
        debug!("Breakpoint State: Waking up");
        // Wakeup debugger
        let break_signal = BREAK.clone();
        let (break_mutex, break_cv) = &*break_signal;
        let mut lock = break_mutex
            .lock()
            .expect("Emulator panicked while holding break state.");
        *lock = BreakpointResumeInfo {
            state: slfbrw.state,
            manual_step_opcode_offset: slfbrw.manual_step_opcode_offset,
        };
        break_cv.notify_one();

        // Wakeup hooks
        let hooks = slfbrw.release_hooks.clone();
        let py = slfbrw.py();
        let slfpy = PyRefMut::as_ptr(&slfbrw);
        for hook in hooks {
            // SAFETY: This should be good because we are not accessing slfbrw anymore,
            //         however I'm probably missing a higher-level way to do this tbh.
            unsafe {
                hook.0
                    .call1(py, (PyObject::from_borrowed_ptr(py, slfpy),))?;
            }
        }
        Ok(())
    }
}

pub struct BreakpointResumeInfo {
    pub state: BreakpointStateType,
    pub manual_step_opcode_offset: Option<u32>,
}

fn read_hook_addr(addrs: Option<&PySequence>) -> PyResult<Vec<u32>> {
    let mapped = addrs
        .map(|seq| {
            seq.iter()?
                .map(|v| v.and_then(|vv| vv.extract()))
                .collect::<PyResult<Vec<u32>>>()
        })
        .transpose()?
        .unwrap_or_default();
    if mapped.is_empty() {
        Err(PyValueError::new_err(
            "Emulator is missing addresses for a debug hook.",
        ))
    } else {
        Ok(mapped)
    }
}
