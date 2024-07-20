/*
 * Copyright 2023-2024 Capypara and the SkyTemple Contributors
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

macro_rules! def_callback {
    ($name:ident, $doc:literal) => {
        #[derive(Debug)]
        #[doc = $doc]
        pub struct $name(pub PyObject);
        impl $name {
            #[allow(unused)]
            #[inline(always)]
            pub fn clone_ref(&self, py: ::pyo3::Python) -> Self {
                Self(self.0.clone_ref(py))
            }
        }
    };
}

def_callback!(
    ReadMemCallback,
    "Python callable with signature def _(mem: bytes)."
);

def_callback!(
    JoyGetNumberConnectedCallback,
    "Python callable with signature def _(number: int)."
);

def_callback!(
    JoyGetSetKeyCallback,
    "Python callable with signature def _(keycode: int)."
);

def_callback!(
    DebugRegisterScriptVariableSetCallback,
    "Python callable with signature def _(var_id: int, var_offset: int, value: int)."
);

def_callback!(DebugRegisterScriptDebugCallback, "Python callable with signature def _(break_state: Optional[BreakpointState], script_runtime_struct_mem: bytes, script_target_slot_id: u32, current_opcode: u32).");

def_callback!(
    DebugRegisterDebugPrintCallback,
    "Python callable with signature def _(type: EmulatorLogType, msg: str)."
);

def_callback!(
    DebugRegisterDebugFlagCallback,
    "Python callable with signature def _(var_id: int, flag_id: int, value: int)."
);

def_callback!(
    DebugRegisterExecGroundCallback,
    "Python callable with signature def _()."
);

def_callback!(
    DebugRegisterSsbLoadCallback,
    "Python callable with signature def _(name: str)."
);

def_callback!(
    DebugRegisterSsxLoadCallback,
    "Python callable with signature def _(hanger: int, name: str)."
);

def_callback!(
    DebugRegisterTalkLoadCallback,
    "Python callable with signature def _(hanger: int)."
);

def_callback!(
    DebugSyncGlobalVarsCallback,
    "Python callable with signature def _(vars: Mapping[int, Sequence[int]])."
);

def_callback!(
    DebugSyncLocalVarsCallback,
    "Python callable with signature def _(vars: Sequence[int])."
);

def_callback!(
    DebugSyncMemTablesCallback,
    "Python callable with signature def _(tables: Sequence[EmulatorMemTable])."
);

def_callback!(
    BreakpointChangeCallback,
    "Python callable with signature def _(ssb_filename: str, opcode_offset: int)."
);

def_callback!(
    BreakpointStateReleaseCallback,
    "Python callable with signature def _(state: BreakpointState)."
);

def_callback!(
    EmulatorMemTableEntryCallback,
    "Python callable with signature def _(content: bytes)."
);
