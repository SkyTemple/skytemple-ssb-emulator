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

use desmume_rs::{
    mem::{IndexMove, Processor, Register},
    DeSmuME, DeSmuMEMemory,
};
use sprintf::{vsprintf, ConversionSpecifier, ConversionType, Printf};

// TODO: Currently DeSmuME specific.
struct PrintfArg<'a> {
    emu: &'a DeSmuME,
    value: u32,
}

impl Printf for PrintfArg<'_> {
    fn format(&self, spec: &ConversionSpecifier) -> sprintf::Result<String> {
        match spec.conversion_type {
            ConversionType::String => {
                let dbg_cstring = self.emu.memory().read_cstring(self.value);
                let dbg_string = dbg_cstring.to_string_lossy();
                let dbg_string_brw = dbg_string.as_ref();
                Printf::format(&dbg_string_brw, spec)
            }
            ConversionType::SciFloatLower
            | ConversionType::SciFloatUpper
            | ConversionType::DecFloatLower
            | ConversionType::DecFloatUpper
            | ConversionType::CompactFloatLower
            | ConversionType::CompactFloatUpper => {
                // Interpret the value as a float
                let value_float: f32 = unsafe { *(std::mem::transmute::<&u32, &f32>(&self.value)) };
                Printf::format(&value_float, spec)
            }
            ConversionType::Char => {
                let value_char = self.value as u8 as char;
                Printf::format(&value_char, spec)
            }
            _ => Printf::format(&(self.value as i64), spec),
        }
    }

    fn as_int(&self) -> Option<i32> {
        Some(self.value as i32)
    }
}

/// Implements a subset of `printf` for hooking `DebugPrint` and friends.
///
/// 64-bit integers/floats are not supported and there are probably plenty
/// of other edge cases that don't work.
///
/// TODO: Float formatting seems to be broken?
/// For some reason, 32-bit float values ("f" suffix in C) are passed in two registers
/// instead of a single register, though this is might be a c-of-time bug.
/// Check if there is a `DebugPrint` in the base game that contains a "%f" pattern.
pub fn debug_print(
    emu: &DeSmuME,
    format_string: &str,
    first_register_with_variadic_args: u32,
) -> sprintf::Result<String> {
    let mut state = DebugPrintState {
        memory: emu.memory(),
        // Some arguments are passed in registers (r0-r3), others are passed on the stack
        register_values: &(first_register_with_variadic_args..4)
            .map(|i| {
                emu.memory()
                    .get_reg(Processor::Arm9, Register::try_from(i).unwrap())
            })
            .collect::<Vec<_>>(),
        read_register_values: 0,
        stack_pos: emu.memory().get_reg(Processor::Arm9, Register::SP),
    };

    let mut args = Vec::new();
    let mut chars = format_string.chars();
    loop {
        // Find the next "%"
        let Some(char) = chars.next() else {
            break;
        };
        if char != '%' {
            continue;
        }

        // We found a "%", push an argument
        let Some(char) = chars.next() else {
            break;
        };
        if char != '%' {
            // Skip "%%"
            args.push(PrintfArg {
                emu,
                value: state.read_next_value(),
            });
        }
    }

    let args_dyn = args
        .iter()
        .map(|v| v as &dyn Printf)
        .collect::<Vec<&dyn Printf>>();
    let formatted_string = vsprintf(format_string, &args_dyn)?;
    Ok(formatted_string)
}

struct DebugPrintState<'a> {
    memory: &'a DeSmuMEMemory,
    /// Values passed in registers
    register_values: &'a [u32],
    /// The number of register values that have been read
    read_register_values: u32,
    /// The position in the stack where the next value is located
    stack_pos: u32,
}

impl DebugPrintState<'_> {
    pub fn read_next_value(&mut self) -> u32 {
        // Read registers first, then read values from the stack
        if self.read_register_values < self.register_values.len() as u32 {
            let value = self.register_values[self.read_register_values as usize];
            self.read_register_values += 1;
            return value;
        }

        // Read from the stack.
        // Values are always promoted to 32-bit integers in variadic functions.
        let value = self.memory.u32().index_move(self.stack_pos);
        self.stack_pos += 4;

        value
    }
}
