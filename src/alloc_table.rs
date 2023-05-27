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

use crate::stbytes::StBytes;
use pyo3::prelude::*;

#[pyclass(module = "ssb_emulator")]
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
/// Type of memory allocation.
pub enum EmulatorMemAllocType {
    Free = 0x00,
    Static = 0x01,
    Block = 0x02,
    Temporary = 0x03,
    SubTable = 0x04,
}

#[pymethods]
impl EmulatorMemAllocType {
    #[getter]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Free => "Free",
            Self::Static => "Static",
            Self::Block => "Block",
            Self::Temporary => "Temporary",
            Self::SubTable => "SubTable",
        }
    }

    #[getter]
    pub fn value(&self) -> u32 {
        *self as u32
    }
}

#[pyclass(module = "ssb_emulator")]
#[derive(Debug, Clone)]
/// n entry in a memory table.
pub struct EmulatorMemTableEntry {
    #[pyo3(get)]
    pub type_alloc: EmulatorMemAllocType,
    #[pyo3(get)]
    pub unk1: u32,
    #[pyo3(get)]
    pub unk2: u32,
    #[pyo3(get)]
    pub start_addres: u32,
    #[pyo3(get)]
    pub available: u32,
    #[pyo3(get)]
    pub used: u32,
}

#[pymethods]
impl EmulatorMemTableEntry {
    /// Returns the bytes of the entry.
    pub fn dump(&self) -> StBytes {
        todo!()
    }
}

#[pyclass(module = "ssb_emulator")]
#[derive(Debug, Clone)]
/// A memory table.
pub struct EmulatorMemTable {
    #[pyo3(get)]
    pub entries: Vec<EmulatorMemTableEntry>,
    #[pyo3(get)]
    pub start_address: u32,
    #[pyo3(get)]
    pub parent_table: u32,
    #[pyo3(get)]
    pub addr_table: u32,
    #[pyo3(get)]
    pub max_entries: u32,
    #[pyo3(get)]
    pub addr_data: u32,
    #[pyo3(get)]
    pub len_data: u32,
}
