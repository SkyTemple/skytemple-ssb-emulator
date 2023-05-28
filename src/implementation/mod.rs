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

use crate::state::{BlockingReceiver, EmulatorCommand, HookExecute};
use crossbeam_channel::{Receiver, Sender};
use std::rc::Rc;

pub mod desmume;

/// An emulator implementation.
pub trait SsbEmulator {
    /// Prepare the execution of hooks.
    fn prepare_register_hooks(&mut self, hook_sender: &Rc<Sender<HookExecute>>);

    // Whether the emulator supports joysticks/gamepads.
    fn supports_joystick(&self) -> bool;

    // Whether the emulator is currently running and not paused.
    fn is_running(&self) -> bool;

    /// Process a single hardware cycle.
    fn cycle(&mut self);

    /// Flush the display buffer of the emulator to
    /// the global [`ssb_emulator::state::DISPLAY_BUFFER`].
    fn flush_display_buffer(&self);

    /// Process all currently pending commands by first processing
    /// everything from the receive channel and then the blocking
    /// receive channel. Any commands to shut down the emulator are
    /// delayed and executed last, after which [`SsbEmulatorCommandResult::Shutdown`]
    /// is returned. Otherwise [`SsbEmulatorCommandResult::Continue`] is returned.
    ///
    /// If `blocking` is `true`, this will block on the blocking receive channel
    /// until a message is received or a safety timeout of a few seconds has elapsed.
    fn process_cmds(
        &mut self,
        command_channel_receive: &Receiver<EmulatorCommand>,
        command_channel_blocking_receive: &BlockingReceiver<EmulatorCommand>,
        blocking: bool,
    ) -> SsbEmulatorCommandResult;
}

/// A resulting action that should be taken after
/// commands have been processed.
pub enum SsbEmulatorCommandResult {
    Continue,
    Shutdown,
}
