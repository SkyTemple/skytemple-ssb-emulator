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

use crate::implementation::{SsbEmulator, SsbEmulatorCommandResult};
use crate::state::{
    BlockingReceiver, DebugCommand, EmulatorCommand, HookExecute, DISPLAY_BUFFER,
    EMULATOR_IS_RUNNING, EMULATOR_JOYSTICK_SUPPORTS,
};
use crossbeam_channel::{Receiver, Sender};
use log::warn;
use rs_desmume::mem::IndexMove;
use rs_desmume::DeSmuME;
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::atomic::Ordering;
use std::time::Duration;

pub struct SsbEmulatorDesmume(DeSmuME);

thread_local! {
    /// Hook sender. This needs to be thread-global for the hook functions.
    static HOOK_SENDER: RefCell<Option<Rc<Sender<HookExecute>>>> = RefCell::new(None);
}

impl SsbEmulatorDesmume {
    pub fn new() -> Self {
        Self(match DeSmuME::init() {
            Ok(emu) => emu,
            Err(err) => {
                panic!("Failed to init the emulator: {}", err)
            }
        })
    }
}

impl SsbEmulator for SsbEmulatorDesmume {
    fn prepare_register_hooks(&mut self, hook_sender: &Rc<Sender<HookExecute>>) {
        HOOK_SENDER.with(|cell| cell.borrow_mut().replace(hook_sender.clone()));
    }

    fn supports_joystick(&self) -> bool {
        self.0.input().joy_number_connected().is_ok()
    }

    fn is_running(&self) -> bool {
        self.0.is_running()
    }

    fn cycle(&mut self) {
        self.0.cycle()
    }

    fn flush_display_buffer(&self) {
        // SAFETY:
        // - We are the only writer.
        // - The slice is big enough.
        unsafe { DISPLAY_BUFFER.write(|buffer| self.0.display_buffer_as_rgbx_into(buffer)) }
    }

    fn process_cmds(
        &mut self,
        command_channel_receive: &Receiver<EmulatorCommand>,
        command_channel_blocking_receive: &BlockingReceiver<EmulatorCommand>,
        boost_mode: bool,
        blocking: bool,
    ) -> SsbEmulatorCommandResult {
        let mut should_shutdown = false;
        for cmd in command_channel_receive.try_iter() {
            should_shutdown &= self.do_process(cmd, boost_mode);
        }

        let update_blocking_cb = |cmd| should_shutdown &= self.do_process(cmd, boost_mode);
        if blocking {
            command_channel_blocking_receive
                .recv_timeout(update_blocking_cb, Duration::from_secs(2))
        } else {
            command_channel_blocking_receive.try_recv(update_blocking_cb)
        }

        if should_shutdown {
            SsbEmulatorCommandResult::Shutdown
        } else {
            SsbEmulatorCommandResult::Continue
        }
    }
}

impl SsbEmulatorDesmume {
    fn do_process(&mut self, cmd: EmulatorCommand, boost_mode: bool) -> bool {
        match cmd {
            EmulatorCommand::NoOp => {}
            EmulatorCommand::Reset => self.0.reset(),
            EmulatorCommand::Pause => self.0.pause(),
            EmulatorCommand::Resume => self.0.resume(false),
            EmulatorCommand::Shutdown => {
                EMULATOR_IS_RUNNING.store(false, Ordering::Release);
                return true;
            }
            EmulatorCommand::OpenRom(filename) => {
                self.0
                    .open(&filename, false)
                    .map_err(|err| {
                        let msg = format!("Failed to open ROM: {err}");
                        warn!("{msg}");
                        self.send_hook(HookExecute::Error(msg));
                    })
                    .ok();
            }
            EmulatorCommand::VolumeSet(volume) => self.0.volume_set(volume),
            EmulatorCommand::SavestateSaveFile(filename) => {
                self.0
                    .savestate_mut()
                    .save_file(&filename)
                    .map_err(|err| {
                        let msg = format!("Failed to save savestate: {err}");
                        warn!("{msg}");
                        self.send_hook(HookExecute::Error(msg));
                    })
                    .ok();
            }
            EmulatorCommand::SavestateLoadFile(filename) => {
                self.0
                    .savestate_mut()
                    .load_file(&filename)
                    .map_err(|err| {
                        let msg = format!("Failed to load savestate: {err}");
                        warn!("{msg}");
                        self.send_hook(HookExecute::Error(msg));
                    })
                    .ok();
            }
            EmulatorCommand::SetLanguage(lang) => self.0.set_language(lang.into()),
            EmulatorCommand::UnpressAllKeys => self.0.input_mut().keypad_update(0),
            EmulatorCommand::JoyInit => {
                let was_success = self
                    .0
                    .input_mut()
                    .joy_init()
                    .map_err(|err| {
                        let msg = format!("Failed to initialize joystick support: {err}");
                        warn!("{msg}");
                        self.send_hook(HookExecute::Error(msg));
                    })
                    .is_ok();

                // This now also changed whether the emulator supports joystick!
                EMULATOR_JOYSTICK_SUPPORTS.store(was_success, Ordering::Release);
            }
            EmulatorCommand::ReadMem(range, cb) => {
                let mem = self.0.memory().u8().index_move(range);
                self.send_hook(HookExecute::ReadMemResult(mem, cb));
            }
            EmulatorCommand::ReadMemFromPtr(ptr, shift, size, cb) => {
                let start = self.0.memory().u32().index_move(ptr);
                let mem = self
                    .0
                    .memory()
                    .u8()
                    .index_move((start + shift)..(ptr + size));
                self.send_hook(HookExecute::ReadMemResult(mem, cb));
            }
            EmulatorCommand::SetJoystickControls(jscfg) => {
                for (i, jskey) in jscfg.into_iter().enumerate() {
                    self.0.input_mut().joy_set_key(i as u16, jskey).ok();
                }
            }
            EmulatorCommand::KeypadAddKey(keymask) => self.0.input_mut().keypad_add_key(keymask),
            EmulatorCommand::KeypadRmKey(keymask) => self.0.input_mut().keypad_rm_key(keymask),
            EmulatorCommand::TouchSetPos(x, y) => self.0.input_mut().touch_set_pos(x, y),
            EmulatorCommand::TouchRelease => self.0.input_mut().touch_release(),
            EmulatorCommand::JoyGetSetKey(key) => {
                self.0.input_mut().joy_get_set_key(key).ok();
            }
            EmulatorCommand::JoyGetNumberConnected(cb) => {
                let number = self.0.input().joy_number_connected().unwrap_or_default();
                self.send_hook(HookExecute::JoyGetNumberConnected(number, cb));
            }
            EmulatorCommand::Debug(debug_cmd) => self.handle_debug_cmd(debug_cmd),
        }
        EMULATOR_IS_RUNNING.store(self.0.is_running(), Ordering::Release);
        false
    }

    fn handle_debug_cmd(&self, debug_cmd: DebugCommand) {
        match debug_cmd {
            DebugCommand::RegisterScriptVariableSet {
                save_script_value_addr,
                save_script_value_at_index_addr,
                hook,
            } => {
                todo!()
            }
            DebugCommand::UnregisterScriptVariableSet => {
                todo!()
            }

            DebugCommand::RegisterScriptDebug {
                func_that_calls_command_parsing_addr,
                hook_start,
                hook_end,
            } => {}
            DebugCommand::UnregisterScriptDebug => {
                todo!()
            }

            DebugCommand::RegisterDebugPrint {
                printf_r0_functions_addr,
                printf_r1_functions_addr,
                script_hook_addr,
                hook,
            } => {
                todo!()
            }
            DebugCommand::UnregisterDebugPrint => {
                todo!()
            }

            DebugCommand::RegisterDebugFlag {
                get_debug_flag_1_addr,
                get_debug_flag_2_addr,
                set_debug_flag_1_addr,
                set_debug_flag_2_addr,
                script_get_debug_mode_addr,
                hook,
            } => {
                todo!()
            }
            DebugCommand::UnregisterDebugFlag => {
                todo!()
            }

            DebugCommand::RegisterExecGround { addr, hook } => {
                todo!()
            }

            DebugCommand::RegisterSsbLoad {
                ssb_load_addrs,
                hook,
            } => {
                todo!()
            }
            DebugCommand::UnregisterSsbLoad => {
                todo!()
            }

            DebugCommand::RegisterSsxLoad {
                ssx_load_addrs,
                hook,
            } => {
                todo!()
            }
            DebugCommand::UnregisterSsxLoad => {
                todo!()
            }

            DebugCommand::RegisterTalkLoad {
                talk_load_addrs,
                hook,
            } => {
                todo!()
            }
            DebugCommand::UnregisterTalkLoad => {
                todo!()
            }

            DebugCommand::RegisterUnionallLoadAddrChange(pnt) => {
                todo!()
            }
            DebugCommand::UnregisterUnionallLoadAddrChange => {
                todo!()
            }
            DebugCommand::UnionallLoadAddressUpdate => {
                todo!()
            }

            DebugCommand::WriteGameVariable {
                var_id,
                var_offset,
                value,
            } => {
                todo!()
            }
            DebugCommand::SetDebugMode(value) => {
                todo!()
            }
            DebugCommand::SetDebugFlag1(bit, value) => {
                todo!()
            }
            DebugCommand::SetDebugFlag2(bit, value) => {
                todo!()
            }
            DebugCommand::SyncGlobalVars(cb) => {
                todo!()
            }
            DebugCommand::SyncLocalVars(addr_of_pnt_to_breaked_for_entity, cb) => {
                todo!()
            }
            DebugCommand::SyncMemTables(cb) => {
                todo!()
            }
        }
    }

    fn send_hook(&self, msg: HookExecute) {
        HOOK_SENDER.with(|s| {
            s.borrow()
                .as_ref()
                .unwrap()
                .send(msg)
                .expect("Thread controlling emulator has disconnected. Bailing!")
        });
    }
}
