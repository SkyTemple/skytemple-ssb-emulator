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

use crate::state::{
    command_channel_blocking_send, command_channel_send, init, EmulatorCommand,
    EMULATOR_IS_RUNNING, EMULATOR_THREAD, TICK_COUNT,
};
use log::warn;
use pyo3::pyfunction;
use std::ops::DerefMut;
use std::sync::atomic::Ordering;

#[pyfunction]
/// Starts the emulator. After this the other functions will work correctly, but only
/// from the thread that originally called this function.
pub fn emulator_start() {
    EMULATOR_THREAD.with(|thread_cell| {
        let mut thread_cell_mut = thread_cell.borrow_mut();
        if thread_cell_mut.is_some() {
            warn!("Emulator was already started.");
        } else {
            init(thread_cell_mut.deref_mut());
        }
    })
}

#[pyfunction]
/// Reset emulation. This also resets the game and fully reloads the ROM file.
pub fn emulator_reset() {
    command_channel_blocking_send(EmulatorCommand::Reset)
}

#[pyfunction]
/// Pause emulation, freezing the render and update loop.
pub fn emulator_pause() {
    command_channel_blocking_send(EmulatorCommand::Pause)
}

#[pyfunction]
/// Resume emulation, if it was paused.
pub fn emulator_resume() {
    command_channel_blocking_send(EmulatorCommand::Resume)
}

#[pyfunction]
/// Open a ROM file. This will reset emulation, if the emulator is currently running.
pub fn emulator_open_rom(filename: String) {
    command_channel_blocking_send(EmulatorCommand::OpenRom(filename))
}

#[pyfunction]
/// Shuts down the emulator. It can be loaded again after this.
pub fn emulator_shutdown() {
    command_channel_blocking_send(EmulatorCommand::Shutdown)
}

#[pyfunction]
/// Returns a value close or equal to the current tick count of the emulator.
/// Rolls over at the u64 limit.
pub fn emulator_tick() -> u64 {
    TICK_COUNT.load(Ordering::Relaxed)
}

#[pyfunction]
/// Returns `true`, if a game is loaded and the emulator is running (not paused).
pub fn emulator_is_running() -> bool {
    EMULATOR_IS_RUNNING.load(Ordering::Acquire)
}

#[pyfunction]
/// Set the emulator volume (0-100).
pub fn emulator_volume_set(volume: u8) {
    command_channel_send(EmulatorCommand::VolumeSet(volume))
}

#[pyfunction]
/// Queues the emulator to save a savestate file to the given path. May also do this blocking.
pub fn emulator_savestate_save_file(filename: String) {
    command_channel_blocking_send(EmulatorCommand::SavestateSaveFile(filename))
}

#[pyfunction]
/// Queues the emulator to load a savestate file from the given path. May also do this blocking.
pub fn emulator_savestate_load_file(filename: String) {
    command_channel_blocking_send(EmulatorCommand::SavestateLoadFile(filename))
}
