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

use crate::script_runtime::ScriptRuntime;
use log::warn;
use rs_desmume::mem::{IndexMove, IndexSet};
use rs_desmume::DeSmuME;
use skytemple_rust::st_script_var_table::{
    ScriptVariableDefinition, ScriptVariableTables, ScriptVariableType,
};

#[derive(Debug)]
pub struct GameVariablesValueAddresses {
    pub values: u32,
    pub game_state_values: u32,
    pub language_info_data: u32,
    pub game_mode: u32,
    pub debug_special_episode_number: u32,
    pub notify_note: u32,
}

pub struct GameVariableManipulator {
    defs: ScriptVariableTables,
    value_addrs: GameVariablesValueAddresses,
}

const START_OFFSET_LOCAL_VARIABLES: u32 = 108;

// TODO: Currently DeSmuME specific.
#[allow(clippy::if_same_then_else)]
impl GameVariableManipulator {
    pub fn new(defs: ScriptVariableTables, value_addrs: GameVariablesValueAddresses) -> Self {
        Self { defs, value_addrs }
    }

    /// Returns the info of the game variable passed in from the script info object and
    /// its current value from memory.
    ///
    /// Partial reimplementation of
    /// GetScriptVariableValue,
    /// GetScriptVariableValueWithOffset and
    /// GetScriptVariableInfoAndPtr
    pub fn read<'a>(
        &'a self,
        emu: &DeSmuME,
        var_id: u16,
        read_offset: u16,
        srs: &ScriptRuntime,
    ) -> (&'a str, i32) {
        let Some((var, is_local)) = self.get_var(var_id) else {
            warn!("Could not determine correct value for variable {var_id}. Probably corruption.");
            return ("?", -1);
        };
        let value_ptr = self.get_value_ptr(is_local, var, Some(srs)).unwrap();
        let value = match var.data.r#type {
            ScriptVariableType::None => 0,
            ScriptVariableType::Bit => {
                let offs = var.data.bitshift + read_offset;
                let value_raw = emu
                    .memory()
                    .u8()
                    .index_move(value_ptr + ((offs as u32) >> 3)); // offset by higher 13 bits [removes the bit]
                let val_offs = 1 << (offs & 7); // offset by lower three bits
                if value_raw & val_offs > 0 {
                    1
                } else {
                    0
                }
            }
            ScriptVariableType::String => {
                // This is for this purpose the same as reading an u8.
                emu.memory().u8().index_move(value_ptr + read_offset as u32) as i32
            }
            ScriptVariableType::U8 => {
                emu.memory().u8().index_move(value_ptr + read_offset as u32) as i32
            }
            ScriptVariableType::I8 => {
                emu.memory().i8().index_move(value_ptr + read_offset as u32) as i32
            }
            ScriptVariableType::U16 => {
                emu.memory()
                    .u16()
                    .index_move(value_ptr + (read_offset as u32 * 2)) as i32
            }
            ScriptVariableType::I16 => {
                emu.memory()
                    .i16()
                    .index_move(value_ptr + (read_offset as u32 * 2)) as i32
            }
            ScriptVariableType::U32 => {
                emu.memory()
                    .u32()
                    .index_move(value_ptr + (read_offset as u32 * 4)) as i32
            }
            ScriptVariableType::I32 => emu
                .memory()
                .i32()
                .index_move(value_ptr + (read_offset as u32 * 4)),
            ScriptVariableType::Special => {
                // Special cases (offset is ignored for these)
                if var_id == 0x3A {
                    // FRIEND_SUM
                    1
                } else if var_id == 0x3B {
                    // UNIT_SUM
                    // Possibly unused but definitely relatively complicated,
                    // so not implemented for now.
                    0
                } else if var_id == 0x3C {
                    // CARRY_GOLD
                    let misc_data_begin = emu
                        .memory()
                        .u32()
                        .index_move(self.value_addrs.game_state_values);
                    // Possibly who the money belongs to? Main team, Special episode team, etc.
                    let some_sort_of_offset = emu.memory().u8().index_move(misc_data_begin + 0x388);
                    let address_carry_gold =
                        misc_data_begin + (some_sort_of_offset as u32 * 4) + 0x1394;
                    emu.memory().u32().index_move(address_carry_gold) as i32
                } else if var_id == 0x3D {
                    // BANK_GOLD
                    let misc_data_begin = emu
                        .memory()
                        .u32()
                        .index_move(self.value_addrs.game_state_values);
                    let address_bank_gold = misc_data_begin + 0x13a0;
                    emu.memory().u32().index_move(address_bank_gold) as i32
                } else if var_id == 0x47 {
                    // LANGUAGE_TYPE
                    emu.memory()
                        .i8()
                        .index_move(self.value_addrs.language_info_data + 1)
                        as i32
                } else if var_id == 0x48 {
                    // GAME_MODE
                    emu.memory().u8().index_move(self.value_addrs.game_mode) as i32
                } else if var_id == 0x49 {
                    // EXECUTE_SPECIAL_EPISODE_TYPE
                    let game_mode = emu.memory().u8().index_move(self.value_addrs.game_mode);
                    match game_mode {
                        1 => emu
                            .memory()
                            .u32()
                            .index_move(self.value_addrs.debug_special_episode_number)
                            as i32,
                        3 => {
                            let (_, v) = self.read(emu, 0x4a, 0, srs);
                            v
                        }
                        _ => 0,
                    }
                } else if var_id == 0x70 {
                    // NOTE_MODIFY_FLAG
                    emu.memory().u8().index_move(self.value_addrs.notify_note) as i32
                } else {
                    0
                }
            }
        };
        (var.name.as_ref(), value)
    }

    /// Saves a game variable.
    /// If the script runtime struct is not set, local variables can not be used!
    ///
    /// Partial reimplementation of
    /// SaveScriptVariableValue and SaveScriptVariableValueAtIndex
    pub fn write(
        &self,
        emu: &mut DeSmuME,
        var_id: u16,
        read_offset: u16,
        value: u32,
        srs: Option<&ScriptRuntime>,
    ) {
        let Some((var, is_local)) = self.get_var(var_id) else {
            warn!("Could not determine definition for variable {var_id}. Probably out of bounds. Write failed.");
            return;
        };
        let Some(value_ptr) = self.get_value_ptr(is_local, var, srs) else {
            warn!("Could not set local variable because no script runtime was provided.");
            return;
        };
        match var.data.r#type {
            ScriptVariableType::None => {
                // noop.
            }
            ScriptVariableType::Bit => {
                let offs = var.data.bitshift + read_offset;
                let value_ptr = value_ptr + (offs as u32 >> 3);
                let old_value = emu.memory().u8().index_move(value_ptr) as u32; // offset by higher 13 bits [removes the bit]
                let val_offs: u32 = 1 << (offs as u32 & 7); // offset by lower three bits
                let value = if value == 0 {
                    val_offs ^ (old_value | val_offs)
                } else {
                    old_value | val_offs
                };
                emu.memory_mut().u8().index_set(value_ptr, &(value as u8))
            }
            ScriptVariableType::String => {
                // This is for this purpose the same as reading an u8.
                emu.memory_mut()
                    .u8()
                    .index_set(value_ptr + read_offset as u32, &(value as u8))
            }
            ScriptVariableType::U8 => emu
                .memory_mut()
                .u8()
                .index_set(value_ptr + read_offset as u32, &(value as u8)),
            ScriptVariableType::I8 => emu
                .memory_mut()
                .i8()
                .index_set(value_ptr + read_offset as u32, &(value as i8)),
            ScriptVariableType::U16 => emu
                .memory_mut()
                .u16()
                .index_set(value_ptr + (read_offset as u32 * 2), &(value as u16)),
            ScriptVariableType::I16 => emu
                .memory_mut()
                .i16()
                .index_set(value_ptr + (read_offset as u32 * 2), &(value as i16)),
            ScriptVariableType::U32 => emu
                .memory_mut()
                .u32()
                .index_set(value_ptr + (read_offset as u32 * 4), &(value as u32)),
            ScriptVariableType::I32 => emu
                .memory_mut()
                .i32()
                .index_set(value_ptr + (read_offset as u32 * 4), &(value as i32)),
            ScriptVariableType::Special => {
                // Special cases (offset is ignored for these)
                // TODO: These are just reverses of the getters, I didn't really look at the ASM yet.
                if var_id == 0x3A {
                    // FRIEND_SUM
                    // noop. - TODO: Is this correct? the getter also doesn't really do anything.
                } else if var_id == 0x3B {
                    // UNIT_SUM
                    // TODO
                } else if var_id == 0x3C {
                    // CARRY_GOLD
                    let misc_data_begin = emu
                        .memory()
                        .u32()
                        .index_move(self.value_addrs.game_state_values);
                    // Possibly who the money belongs to? Main team, Special episode team, etc.
                    let some_sort_of_offset = emu.memory().u8().index_move(misc_data_begin + 0x388);
                    let address_carry_gold =
                        misc_data_begin + (some_sort_of_offset as u32 * 4) + 0x1394;
                    emu.memory_mut()
                        .u32()
                        .index_set(address_carry_gold, &(value));
                } else if var_id == 0x3D {
                    // BANK_GOLD
                    let misc_data_begin = emu
                        .memory()
                        .u32()
                        .index_move(self.value_addrs.game_state_values);
                    let address_bank_gold = misc_data_begin + 0x13a0;
                    emu.memory_mut()
                        .u32()
                        .index_set(address_bank_gold, &(value));
                } else if var_id == 0x47 {
                    // LANGUAGE_TYPE
                    emu.memory_mut()
                        .u8()
                        .index_set(self.value_addrs.language_info_data + 1, &(value as u8));
                } else if var_id == 0x48 {
                    // GAME_MODE
                    emu.memory_mut()
                        .u8()
                        .index_set(self.value_addrs.game_mode, &(value as u8));
                } else if var_id == 0x49 {
                    // EXECUTE_SPECIAL_EPISODE_TYPE
                    let game_mode = emu.memory().u8().index_move(self.value_addrs.game_mode);
                    if game_mode == 1 {
                        emu.memory_mut()
                            .u32()
                            .index_set(self.value_addrs.debug_special_episode_number, &(value));
                    }
                } else if var_id == 0x70 {
                    // NOTE_MODIFY_FLAG
                    emu.memory_mut()
                        .u8()
                        .index_set(self.value_addrs.notify_note, &(value as u8));
                } else {
                    // noop.
                }
            }
        }
    }

    fn get_var(&self, var_id: u16) -> Option<(&ScriptVariableDefinition, bool)> {
        if var_id >= 0x400 {
            self.defs
                .locals
                .get(var_id as usize - 0x400)
                .map(|v| (v, true))
        } else {
            self.defs.globals.get(var_id as usize).map(|v| (v, false))
        }
    }

    fn get_value_ptr(
        &self,
        is_local: bool,
        var: &ScriptVariableDefinition,
        srs: Option<&ScriptRuntime>,
    ) -> Option<u32> {
        if is_local {
            srs.map(|srs| {
                srs.ptr_to_self + START_OFFSET_LOCAL_VARIABLES + var.data.memoffset as u32
            })
        } else {
            Some(self.value_addrs.values + var.data.memoffset as u32)
        }
    }
}
