//! Rust implementation of ssb-debugger ScriptRuntimeStruct.
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

use crate::eos_debug::{ScriptTargetType, MAX_SSB};
use byteorder::{LittleEndian, ReadBytesExt};

/// State of the script engine for a hanger.
#[derive(Debug, Clone)]
pub struct ScriptRuntime {
    buffer: Vec<u8>,
    pub(crate) ptr_to_self: u32,
    pub(crate) hanger_ssb: u8,
    pub(crate) current_opcode_addr: u32,
    pub(crate) current_opcode_addr_relative: u32,
    pub(crate) script_target_type: ScriptTargetType,
    pub(crate) script_target_address: u32,
    pub(crate) is_in_unionall: bool,
    pub(crate) has_call_stack: bool,
    pub(crate) call_stack_current_opcode_addr_relative: u32,
    pub(crate) start_addr_str_table: u32,
}

impl ScriptRuntime {
    /// This is not the actual size, increase this if we need to read more!
    pub const SIZE: u32 = 0x34;

    pub fn new(ptr_to_self: u32, buffer: Vec<u8>, unionall_load_addr: u32) -> Self {
        let start_addr_routine_infos = (&buffer[0x14..]).read_u32::<LittleEndian>().unwrap();
        let is_in_unionall =
            unionall_load_addr != 0 && start_addr_routine_infos == unionall_load_addr;
        let mut hanger_ssb = if is_in_unionall {
            0
        } else {
            (&buffer[0x10..]).read_i16::<LittleEndian>().unwrap()
        };
        if hanger_ssb < 0 || hanger_ssb > MAX_SSB as i16 {
            hanger_ssb = 0;
        }
        let hanger_ssb = hanger_ssb as u8;
        let current_opcode_addr = (&buffer[0x1c..]).read_u32::<LittleEndian>().unwrap();
        let current_opcode_addr_relative =
            (current_opcode_addr.wrapping_sub(start_addr_routine_infos)) / 2;
        let script_target_type_raw = (&buffer[0x08..]).read_u32::<LittleEndian>().unwrap();
        let script_target_type = match script_target_type_raw {
            1 => ScriptTargetType::Generic,
            3 => ScriptTargetType::Actor,
            4 => ScriptTargetType::Object,
            5 => ScriptTargetType::Performer,
            9 => ScriptTargetType::Coroutine,
            _ => ScriptTargetType::Invalid,
        };
        let script_target_address = (&buffer[0x04..]).read_u32::<LittleEndian>().unwrap();
        let has_call_stack = (&buffer[0x2c..]).read_u32::<LittleEndian>().unwrap() > 0;
        let call_stack_start_addr_routine_infos =
            (&buffer[0x24..]).read_u32::<LittleEndian>().unwrap();
        let call_stack_current_opcode_addr = (&buffer[0x2c..]).read_u32::<LittleEndian>().unwrap();
        let call_stack_current_opcode_addr_relative =
            (call_stack_current_opcode_addr.wrapping_sub(call_stack_start_addr_routine_infos)) / 2;
        let start_addr_str_table = (&buffer[0x20..]).read_u32::<LittleEndian>().unwrap();
        Self {
            ptr_to_self,
            buffer,
            hanger_ssb,
            current_opcode_addr,
            current_opcode_addr_relative,
            script_target_type,
            script_target_address,
            has_call_stack,
            is_in_unionall,
            call_stack_current_opcode_addr_relative,
            start_addr_str_table,
        }
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.buffer
    }
}
