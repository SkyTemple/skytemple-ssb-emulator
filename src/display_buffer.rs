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
use crate::{SCREEN_HEIGHT_BOTH, SCREEN_WIDTH};
use pyo3::prelude::*;
use std::borrow::Cow;
use std::cell::Cell;
use std::ptr;

pub const DISPLAY_BUFFER_SIZE: usize = SCREEN_WIDTH * SCREEN_HEIGHT_BOTH * 4;

/// Double-buffered display buffer.
#[derive(Debug, Clone)]
pub struct DisplayBuffer {
    slot_a: [u8; DISPLAY_BUFFER_SIZE],
    slot_b: [u8; DISPLAY_BUFFER_SIZE],
    // These will always either point to one or the other slot.
    read: Cell<*mut [u8; DISPLAY_BUFFER_SIZE]>,
    write: Cell<*mut [u8; DISPLAY_BUFFER_SIZE]>,
}

impl Default for DisplayBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl DisplayBuffer {
    /// Constructs a new 0-initialized display buffer.
    pub fn new() -> Self {
        let mut slf = Self {
            slot_a: [0; DISPLAY_BUFFER_SIZE],
            slot_b: [0; DISPLAY_BUFFER_SIZE],
            read: Cell::new(ptr::null_mut()),
            write: Cell::new(ptr::null_mut()),
        };
        slf.read.set(&mut slf.slot_a);
        slf.write.set(&mut slf.slot_b);
        slf
    }

    /// Returns the current active display buffer.
    ///
    /// # Safety
    /// After [`write`] has been called and finished, the next [`write`] call
    /// will modify the contents of the slice returned by this function.
    /// As such the slice should be consumed fast.
    pub unsafe fn read(&self) -> &[u8; DISPLAY_BUFFER_SIZE] {
        &*self.read.get()
    }

    /// Passes a mutable reference to the inactive display buffer to the callback.
    /// After the callback completed, the inactive and active buffers are swapped.
    ///
    /// # Safety
    /// This must only ever be called by a single writing thread.
    pub unsafe fn write<'a, 'b, F>(&self, write_cb: F)
    where
        F: FnOnce(&'b mut [u8; DISPLAY_BUFFER_SIZE]),
        'a: 'b,
    {
        write_cb(&mut *self.write.get());
        self.write.swap(&self.read);
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
