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

use crate::state::{
    command_channel_blocking_send, EmulatorCommand, HookExecute, ERR_EMU_INIT, HOOK_CHANNEL_RECEIVE,
};
use crate::stbytes::StBytes;
use pyo3::prelude::*;
use std::borrow::Cow;

#[pyfunction]
/// Polls new emulator events from the emulator thread and runs all pending hooks.
/// All pending hook functions will be run blocking on the thread calling emulator_poll.
pub fn emulator_poll(py: Python, error_consumer: PyObject) -> PyResult<()> {
    HOOK_CHANNEL_RECEIVE.with(|receiver_cell| {
        let receiver_opt = receiver_cell.borrow();
        let receiver = receiver_opt.as_ref().expect(ERR_EMU_INIT);
        for event in receiver.try_iter() {
            match event {
                HookExecute::Error(err_msg) => {
                    error_consumer.call(py, (err_msg,), None)?;
                }
                HookExecute::ReadMemResult(val, cb) => {
                    cb.0.call(py, (StBytes(Cow::Owned(val)),), None)?;
                }
                HookExecute::JoyGetNumberConnected(val, cb) => {
                    cb.0.call(py, (val,), None)?;
                }
                HookExecute::DebugScriptVariableSet(cb, var_id, var_offset, var_value) => {
                    cb.0.call(py, (var_id, var_offset, var_value), None)?;
                }
                HookExecute::DebugScriptDebug {
                    cb,
                    breakpoint_state,
                    script_target_slot_id,
                    current_opcode,
                    script_runtime_struct_mem,
                } => {
                    cb.0.call(
                        py,
                        (
                            breakpoint_state,
                            script_runtime_struct_mem,
                            script_target_slot_id,
                            current_opcode,
                        ),
                        None,
                    )?;
                }
                HookExecute::DebugSsbLoad(cb, name) => {
                    cb.0.call(py, (name,), None)?;
                }
                HookExecute::DebugSsxLoad(cb, hanger, name) => {
                    cb.0.call(py, (hanger, name), None)?;
                }
                HookExecute::DebugTalkLoad(cb, hanger) => {
                    cb.0.call(py, (hanger,), None)?;
                }
                HookExecute::DebugPrint(cb, ty, msg) => {
                    cb.0.call(py, (ty, msg), None)?;
                }
                HookExecute::DebugSetFlag(cb, var_id, flag_id, value) => {
                    cb.0.call(py, (var_id, flag_id, value), None)?;
                }
            }
        }
        Ok(())
    })
}

#[pyfunction]
/// Waits until the emulator has completed the currently processing frame and all queued-up commands
/// previous to this call.
pub fn emulator_wait_one_cycle() {
    command_channel_blocking_send(EmulatorCommand::NoOp)
}
