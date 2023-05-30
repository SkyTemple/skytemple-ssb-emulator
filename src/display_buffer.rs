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

use crate::state::DISPLAY_BUFFER;
use crate::stbytes::StBytes;
use crate::SCREEN_PIXEL_SIZE;
use pyo3::prelude::*;
use std::borrow::Cow;
use std::cell::Cell;
use std::pin::Pin;
use std::ptr;

pub const DISPLAY_BUFFER_SIZE: usize = SCREEN_PIXEL_SIZE * 2 * 4;

/// Display buffer.
#[derive(Debug, Clone)]
pub struct DisplayBuffer {
    slot_a: [u8; DISPLAY_BUFFER_SIZE],
    //slot_b: [u8; DISPLAY_BUFFER_SIZE],
    // We use one for now, because this seems fine and there is no tearing.
    read_write: Cell<*mut [u8; DISPLAY_BUFFER_SIZE]>,
    //write: Cell<*mut [u8; DISPLAY_BUFFER_SIZE]>,
}

impl DisplayBuffer {
    /// Constructs a new 0-initialized display buffer.
    pub fn new() -> Pin<Box<Self>> {
        let mut slf = Box::pin(Self {
            slot_a: [0; DISPLAY_BUFFER_SIZE],
            //slot_b: [0; DISPLAY_BUFFER_SIZE],
            read_write: Cell::new(ptr::null_mut()),
            //write: Cell::new(ptr::null_mut()),
        });
        // SAFETY: This is OK because we do not move any data out of the struct.
        unsafe {
            let slf_mut = Pin::get_unchecked_mut(Pin::as_mut(&mut slf));
            slf_mut.read_write.set(&mut slf_mut.slot_a);
        }
        //slf.write.set(&mut slf.slot_b);
        slf
    }

    /// Returns the current active display buffer.
    ///
    /// # Safety
    /// The returned buffer is also being written to periodically, it is thus not strictly
    /// memory safe.
    // Below is not relevant, this is not double-buffered at the moment.
    // # Safety
    // After [`write`] has been called and finished, the next [`write`] call
    // will modify the contents of the slice returned by this function.
    // As such the slice should be consumed fast.
    pub unsafe fn read(&self) -> &[u8; DISPLAY_BUFFER_SIZE] {
        &*self.read_write.get()
    }

    /// Passes a mutable reference to the inactive display buffer to the callback.
    // NOT TRUE: After the callback completed, the inactive and active buffers are swapped.
    ///
    /// # Safety
    /// This must only ever be called by a single writing thread.
    pub unsafe fn write<'a, 'b, F>(&self, write_cb: F)
    where
        F: FnOnce(&'b mut [u8; DISPLAY_BUFFER_SIZE]),
        'a: 'b,
    {
        write_cb(&mut *self.read_write.get());
        //self.write.swap(&self.read);
    }
}

/// SAFETY:
/// The interior state that doesn't implement Sync (ie. the Cells) can only be modified through
/// unsafe functions that state the limitations.
unsafe impl Sync for DisplayBuffer {}

#[pyfunction]
/// Returns the display buffer of the emulator in RGBx format.
pub fn emulator_display_buffer_as_rgbx() -> StBytes<'static> {
    unsafe { StBytes(Cow::Borrowed(DISPLAY_BUFFER.read().as_slice())) }
}
