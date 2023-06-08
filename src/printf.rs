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

use desmume_rs::DeSmuME;
use sprintf::{ConversionSpecifier, ConversionType, Printf};

// TODO: Currently DeSmuME specific.
pub struct PrintfArg<'a>(pub &'a DeSmuME, pub u32);

impl<'a> Printf for PrintfArg<'a> {
    fn format(&self, spec: &ConversionSpecifier) -> sprintf::Result<String> {
        match spec.conversion_type {
            ConversionType::String => {
                let dbg_cstring = self.0.memory().read_cstring(self.1);
                let dbg_string = dbg_cstring.to_string_lossy();
                let dbg_string_brw = dbg_string.as_ref();
                Printf::format(&dbg_string_brw, spec)
            }
            _ => Printf::format(&(self.1 as i32), spec),
        }
    }

    fn as_int(&self) -> Option<i32> {
        Some(self.1 as i32)
    }
}
