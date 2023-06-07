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

use pyo3::PyObject;

#[derive(Debug, Clone)]
/// Python callable with signature def _(mem: bytes).
pub struct ReadMemCallback(pub PyObject);

#[derive(Debug, Clone)]
/// Python callable with signature def _(number: int).
pub struct JoyGetNumberConnectedCallback(pub PyObject);

#[derive(Debug, Clone)]
/// Python callable with signature def _(keycode: int).
pub struct JoyGetSetKeyCallback(pub PyObject);

#[derive(Debug, Clone)]
/// Python callable with signature def _(var_id: int, var_offset: int, value: int).
pub struct DebugRegisterScriptVariableSetCallback(pub PyObject);

#[derive(Debug, Clone)]
/// Python callable with signature def _(break_state: Optional[BreakpointState], script_runtime_struct_mem: bytes, script_target_slot_id: u32, current_opcode: u32).
pub struct DebugRegisterScriptDebugCallback(pub PyObject);

#[derive(Debug, Clone)]
/// Python callable with signature def _(type: EmulatorLogType, msg: str).
pub struct DebugRegisterDebugPrintCallback(pub PyObject);

#[derive(Debug, Clone)]
/// Python callable with signature def _(var_id: int, flag_id: int, value: int).
pub struct DebugRegisterDebugFlagCallback(pub PyObject);

#[derive(Debug, Clone)]
/// Python callable with signature def _().
pub struct DebugRegisterExecGroundCallback(pub PyObject);

#[derive(Debug, Clone)]
/// Python callable with signature def _(name: str).
pub struct DebugRegisterSsbLoadCallback(pub PyObject);

#[derive(Debug, Clone)]
/// Python callable with signature def _(hanger: int, name: str).
pub struct DebugRegisterSsxLoadCallback(pub PyObject);

#[derive(Debug, Clone)]
/// Python callable with signature def _(hanger: int).
pub struct DebugRegisterTalkLoadCallback(pub PyObject);

#[derive(Debug, Clone)]
/// Python callable with signature def _(vars: Mapping[int, Sequence[int]]).
pub struct DebugSyncGlobalVarsCallback(pub PyObject);

#[derive(Debug, Clone)]
/// Python callable with signature def _(vars: Sequence[int]).
pub struct DebugSyncLocalVarsCallback(pub PyObject);

#[derive(Debug, Clone)]
/// Python callable with signature def _(tables: Sequence[EmulatorMemTable]).
pub struct DebugSyncMemTablesCallback(pub PyObject);

#[derive(Debug, Clone)]
/// Python callable with signature def _(ssb_filename: str, opcode_offset: int).
pub struct BreakpointChangeCallback(pub PyObject);

#[derive(Debug, Clone)]
/// Python callable with signature def _(state: BreakpointState).
pub struct BreakpointStateReleaseCallback(pub PyObject);

#[derive(Debug, Clone)]
/// Python callable with signature def _(content: bytes).
pub struct EmulatorMemTableEntryCallback(pub PyObject);
