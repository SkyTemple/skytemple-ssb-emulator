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

#[macro_use]
mod macros;

mod alloc_table;
mod display_buffer;
mod eos_debug;
mod event_queue;
mod game_variable;
mod implementation;
mod input;
mod language;
mod memory;
mod printf;
mod pycallbacks;
mod python_module;
mod script_runtime;
mod state;
mod stbytes;
mod system;

pub const SCREEN_WIDTH: usize = 256;
pub const SCREEN_HEIGHT: usize = 192;
pub const SCREEN_HEIGHT_BOTH: usize = SCREEN_HEIGHT * 2;
pub const SCREEN_PIXEL_SIZE: usize = SCREEN_WIDTH * SCREEN_HEIGHT;
