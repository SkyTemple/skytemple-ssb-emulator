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
use crate::state::{
    command_channel_blocking_send, command_channel_send, DebugCommand, EmulatorCommand, BOOST_MODE,
    UNIONALL_LOAD_ADDRESS,
};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PySequence;
use std::sync::atomic::Ordering;

#[pyclass(module = "ssb_emulator")]
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EmulatorLogType {
    Printfs,
    DebugPrint,
}

#[pyfunction]
/// Enable or disable boost mode. In this mode some debugging hooks may not be executed to improve
/// emulator performance.
pub fn emulator_set_boost(state: bool) {
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
    command_channel_send(EmulatorCommand::Debug(
        DebugCommand::UnregisterScriptVariableSet,
    ))
}

#[pyfunction]
#[pyo3(signature = (func_that_calls_command_parsing_addr, hook_start, hook_end) )]
/// Register hooks to process script engine debugging events. Replaces the previously registered
/// hooks.
/// The hook is called asynchronously by polling `emulator_poll` on the receiving thread.
pub fn emulator_register_script_debug(
    func_that_calls_command_parsing_addr: Option<&PySequence>,
    hook_start: PyObject,
    hook_end: PyObject,
) -> PyResult<()> {
    command_channel_send(EmulatorCommand::Debug(DebugCommand::RegisterScriptDebug {
        func_that_calls_command_parsing_addr: read_hook_addr(func_that_calls_command_parsing_addr)?,
        hook_start: DebugRegisterScriptDebugStartCallback(hook_start),
        hook_end: DebugRegisterScriptDebugEndCallback(hook_end),
    }));
    Ok(())
}

#[pyfunction]
/// Unregister all potentially previously registered hooks for processing script debugging events.
pub fn emulator_unregister_script_debug() {
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
    command_channel_send(EmulatorCommand::Debug(DebugCommand::RegisterDebugFlag {
        get_debug_flag_1_addr: read_hook_addr(get_debug_flag_1_addr)?,
        get_debug_flag_2_addr: read_hook_addr(get_debug_flag_2_addr)?,
        set_debug_flag_1_addr: read_hook_addr(set_debug_flag_1_addr)?,
        set_debug_flag_2_addr: read_hook_addr(set_debug_flag_2_addr)?,
        script_get_debug_mode_addr: read_hook_addr(script_get_debug_mode_addr)?,
        hook: DebugRegisterDebugFlagCallback(hook),
    }));
    Ok(())
    //     TODO
    //         self.register_exec(arm9.functions.GetDebugFlag1.absolute_address, self.hook__get_debug_flag_get_input)
    //         self.register_exec(arm9.functions.GetDebugFlag2.absolute_address, self.hook__get_debug_flag_get_input)
    //         self.register_exec(arm9.functions.GetDebugFlag1.absolute_address+0x4, self.hook__get_debug_flag_1)
    //         self.register_exec(arm9.functions.GetDebugFlag2.absolute_address+0x4, self.hook__get_debug_flag_2)
    //         self.register_exec(arm9.functions.SetDebugFlag1.absolute_address, self.hook__set_debug_flag_1)
    //         self.register_exec(arm9.functions.SetDebugFlag2.absolute_address, self.hook__set_debug_flag_2)
    //
    //
    //
    //     @synchronized(debugger_state_lock)
    //     def hook__get_debug_flag_get_input(self, address, size):
    //         self._debug_flag_temp_input = self.emu_thread.emu.memory.register_arm9.r0
    //
    //     @synchronized(debugger_state_lock)
    //     def hook__get_debug_flag_1(self, address, size):
    //         self.emu_thread.emu.memory.register_arm9.r0 = self._debug_flags_1[self._debug_flag_temp_input]
    //
    //     @synchronized(debugger_state_lock)
    //     def hook__get_debug_flag_2(self, address, size):
    //         self.emu_thread.emu.memory.register_arm9.r0 = self._debug_flags_2[self._debug_flag_temp_input]
    //
    //     @synchronized(debugger_state_lock)
    //     def hook__set_debug_flag_1(self, address, size):
    //         flag_id = self.emu_thread.emu.memory.register_arm9.r0
    //         value = self.emu_thread.emu.memory.register_arm9.r1
    //         threadsafe_gtk_nonblocking(lambda: self.parent.set_check_debug_flag_1(flag_id, value))
    //
    //     @synchronized(debugger_state_lock)
    //     def hook__set_debug_flag_2(self, address, size):
    //         flag_id = self.emu_thread.emu.memory.register_arm9.r0
    //         value = self.emu_thread.emu.memory.register_arm9.r1
    //         threadsafe_gtk_nonblocking(lambda: self.parent.set_check_debug_flag_2(flag_id, value))
    //     """
}

#[pyfunction]
/// Unregister all potentially previously registered hooks for processing debug flags.
pub fn emulator_unregister_debug_flag() {
    command_channel_send(EmulatorCommand::Debug(DebugCommand::UnregisterDebugFlag))
}

#[pyfunction]
/// Register a hook to run when the given address is executed. If the hook is None,
/// it is unregistered.
///
/// The hook is not called should overlay 11 not be loaded.
pub fn emulator_register_exec_ground(addr: u32, hook: Option<PyObject>) {
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
    command_channel_send(EmulatorCommand::Debug(DebugCommand::RegisterSsbLoad {
        ssb_load_addrs: read_hook_addr(ssb_load_addrs)?,
        hook: DebugRegisterSsbLoadCallback(hook),
    }));
    Ok(())
}

#[pyfunction]
/// Unregister SSB load hook.
pub fn emulator_unregister_ssb_load() {
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
    command_channel_send(EmulatorCommand::Debug(DebugCommand::RegisterSsxLoad {
        ssx_load_addrs: read_hook_addr(ssx_load_addrs)?,
        hook: DebugRegisterSsxLoadCallback(hook),
    }));
    Ok(())
}

#[pyfunction]
/// Unregister SSx load hook.
pub fn emulator_unregister_ssx_load() {
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
    command_channel_send(EmulatorCommand::Debug(DebugCommand::RegisterTalkLoad {
        talk_load_addrs: read_hook_addr(talk_load_addrs)?,
        hook: DebugRegisterTalkLoadCallback(hook),
    }));
    Ok(())
}

#[pyfunction]
/// Unregister SSx talk load hook.
pub fn emulator_unregister_talk_load() {
    command_channel_send(EmulatorCommand::Debug(DebugCommand::UnregisterTalkLoad))
}

#[pyfunction]
/// Registers a hook for watching the unionall pointer. This allows retreiving it at any time via
/// [`emulator_unionall_load_address`].
pub fn emulator_register_unionall_load_addr_change(unionall_pointer: u32) {
    command_channel_send(EmulatorCommand::Debug(
        DebugCommand::RegisterUnionallLoadAddrChange(unionall_pointer),
    ))
}

#[pyfunction]
/// Unregister unionall update watcher. The address returned will now no longer match the game
/// state.
pub fn emulator_unregister_unionall_load_addr_change() {
    command_channel_send(EmulatorCommand::Debug(
        DebugCommand::UnregisterUnionallLoadAddrChange,
    ))
}

#[pyfunction]
/// Returns the address unionall is loaded at currently. May return 0 if not determinable.
pub fn emulator_unionall_load_address() -> u32 {
    UNIONALL_LOAD_ADDRESS.load(Ordering::Acquire)
}

#[pyfunction]
/// Fetches the current unionall load address from the emulator into the cache.
/// This requires `emulator_register_unionall_load_addr_change` to be called before.
pub fn emulator_unionall_load_address_update() {
    command_channel_blocking_send(EmulatorCommand::Debug(
        DebugCommand::UnionallLoadAddressUpdate,
    ))
}

#[pyfunction]
/// Queues writing the game variable to the game.
/// This is done at latest the next time the emulator's memory is ready to be written to.
pub fn emulator_write_game_variable(var_id: u32, var_offset: u32, value: u32) {
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
    command_channel_send(EmulatorCommand::Debug(DebugCommand::SetDebugMode(value)));
}

#[pyfunction]
/// Queues writing a bit of debug flag 1.
/// This is done at latest the next time the emulator's memory is ready to be written to.
pub fn emulator_set_debug_flag_1(bit: i32, value: bool) {
    command_channel_send(EmulatorCommand::Debug(DebugCommand::SetDebugFlag1(
        bit, value,
    )));
}

#[pyfunction]
/// Queues writing a bit of debug flag 2.
/// This is done at latest the next time the emulator's memory is ready to be written to.
pub fn emulator_set_debug_flag_2(bit: i32, value: bool) {
    command_channel_send(EmulatorCommand::Debug(DebugCommand::SetDebugFlag2(
        bit, value,
    )));
}

#[pyfunction]
/// Retrieve the values of global variable values from the emulator and passes
/// them to the callback when ready and [`emulator_poll`] is called.
pub fn emulator_sync_vars(cb: PyObject) {
    command_channel_send(EmulatorCommand::Debug(DebugCommand::SyncGlobalVars(
        DebugSyncGlobalVarsCallback(cb),
    )));
}

#[pyfunction]
/// Retrieve the values of local variable values from the emulator and passes
/// them to the callback when ready and [`emulator_poll`] is called.
pub fn emulator_sync_local_vars(addr_of_pnt_to_breaked_for_entity: u32, cb: PyObject) {
    command_channel_send(EmulatorCommand::Debug(DebugCommand::SyncLocalVars(
        addr_of_pnt_to_breaked_for_entity,
        DebugSyncLocalVarsCallback(cb),
    )));
}

#[pyfunction]
/// Synchronize and retrieve and return the memory allocation tables and pass
/// them to the callback when ready and [`emulator_poll`] is called.
pub fn emulator_sync_tables(cb: PyObject) {
    command_channel_send(EmulatorCommand::Debug(DebugCommand::SyncMemTables(
        DebugSyncMemTablesCallback(cb),
    )));
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
