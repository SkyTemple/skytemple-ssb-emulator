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

use crate::pycallbacks::EmulatorMemTableEntryCallback;
use crate::state::{command_channel_send, DebugCommand, EmulatorCommand};
use desmume_rs::mem::IndexMove;
use desmume_rs::DeSmuME;
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
    pub start_address: u32,
    #[pyo3(get)]
    pub available: u32,
    #[pyo3(get)]
    pub used: u32,
}

#[pymethods]
impl EmulatorMemTableEntry {
    /// Passes the bytes of the entry to the callback when ready and emulator_poll is called.
    pub fn dump(&self, cb: PyObject) {
        dbg_trace!("EmulatorMemTable::dump - {self:?}");
        command_channel_send(EmulatorCommand::Debug(DebugCommand::DumpMemTableEntry(
            EmulatorMemTableEntryCallback(cb),
            self.start_address,
            self.available,
        )));
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

impl EmulatorMemTable {
    pub fn read(emu: &DeSmuME, addr_ptr: u32) -> Self {
        dbg_trace!("EmulatorMemTable::read - {addr_ptr}");
        let start_address = emu.memory().u32().index_move(addr_ptr);
        let parent_table = emu.memory().u32().index_move(start_address + 0x4);
        let addr_table = emu.memory().u32().index_move(start_address + 0x8);
        let entries = emu.memory().u32().index_move(start_address + 0xc);
        let max_entries = emu.memory().u32().index_move(start_address + 0x10);
        let addr_data = emu.memory().u32().index_move(start_address + 0x14);
        let len_data = emu.memory().u32().index_move(start_address + 0x18);
        let mut blocks = Vec::with_capacity(entries as usize);
        for x in 0..entries {
            let entry_start = addr_table + 0x18 * x;
            let type_alloc = match emu.memory().u32().index_move(entry_start) {
                0 => EmulatorMemAllocType::Free,
                1 => EmulatorMemAllocType::Static,
                2 => EmulatorMemAllocType::Block,
                3 => EmulatorMemAllocType::Temporary,
                4 => EmulatorMemAllocType::SubTable,
                _ => EmulatorMemAllocType::SubTable,
            };
            let unk1 = emu.memory().u32().index_move(entry_start + 0x4);
            let unk2 = emu.memory().u32().index_move(entry_start + 0x8);
            let start_address = emu.memory().u32().index_move(entry_start + 0xc);
            let available = emu.memory().u32().index_move(entry_start + 0x10);
            let used = emu.memory().u32().index_move(entry_start + 0x14);
            blocks.push(EmulatorMemTableEntry {
                type_alloc,
                unk1,
                unk2,
                start_address,
                available,
                used,
            })
        }
        Self {
            entries: blocks,
            start_address,
            parent_table,
            addr_table,
            max_entries,
            addr_data,
            len_data,
        }
    }
}
