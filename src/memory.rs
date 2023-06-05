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

use crate::pycallbacks::ReadMemCallback;
use crate::state::{command_channel_send, EmulatorCommand};
use pyo3::prelude::*;

#[pyfunction]
/// Read a chunk of memory [address_start,address_end).
/// The chunk is passed to the callback as soon as it's available
/// and `emulator_poll` has been called to poll the value.
pub fn emulator_read_mem(address_start: u32, address_end: u32, cb: PyObject) {
    dbg_trace!("emulator_read_mem - {address_start} - {address_end}");
    command_channel_send(EmulatorCommand::ReadMem(
        address_start..address_end,
        ReadMemCallback(cb),
    ))
}

#[pyfunction]
/// Read a chunk of memory starting at the address pointed to by `ptr`, then shifted by `shift`
/// and with the length of `size` bytes.
/// The chunk is passed to the callback as soon as it's available
/// and `emulator_poll` has been called to poll the value.
pub fn emulator_read_mem_from_ptr(ptr: u32, shift: u32, size: u32, cb: PyObject) {
    dbg_trace!("emulator_read_mem_from_ptr - {ptr} - {shift} - {size}");
    command_channel_send(EmulatorCommand::ReadMemFromPtr(
        ptr,
        shift,
        size,
        ReadMemCallback(cb),
    ))
}

#[pyfunction]
/// Same as [`emulator_read_mem_from_ptr`], but only calls the callback if the
/// value at `validity_offset` read as an `i16` and starting from `(*ptr)+shift` is `> 0`.
pub fn emulator_read_mem_from_ptr_with_validity_check(
    ptr: u32,
    shift: u32,
    size: u32,
    validity_offset: u32,
    cb: PyObject,
) {
    dbg_trace!("emulator_read_mem_from_ptr_with_validity_check - {ptr} - {shift} - {size} - {validity_offset}");
    command_channel_send(EmulatorCommand::ReadMemFromPtrWithValidityCheck(
        ptr,
        shift,
        size,
        validity_offset,
        ReadMemCallback(cb),
    ))
}
