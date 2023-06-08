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

use crate::alloc_table::EmulatorMemTable;
use crate::eos_debug::{
    BreakpointInfo, BreakpointState, BreakpointStateType, EmulatorLogType, MAX_SSB, MAX_SSX,
    TALK_HANGER_OFFSET,
};
use crate::game_variable::GameVariableManipulator;
use crate::implementation::{SsbEmulator, SsbEmulatorCommandResult};
use crate::printf::PrintfArg;
use crate::pycallbacks::*;
use crate::script_runtime::ScriptRuntime;
use crate::state::{
    BlockingReceiver, DebugCommand, EmulatorCommand, HookExecute, BOOST_MODE, BREAK,
    BREAKPOINT_MANAGER, DISPLAY_BUFFER, EMULATOR_IS_RUNNING, EMULATOR_JOYSTICK_SUPPORTS,
    ERR_EMU_INIT, TICK_COUNT, UNIONALL_LOAD_ADDRESS,
};
use crate::stbytes::StBytes;
use crossbeam_channel::{Receiver, Sender};
use desmume_rs::mem::{IndexMove, IndexSet, Processor, Register};
use desmume_rs::DeSmuME;
use log::warn;
use sprintf::{vsprintf, Printf};
use std::borrow::Cow;
use std::cell::{RefCell, UnsafeCell};
use std::collections::HashMap;
use std::ffi::CString;
use std::mem;
use std::ops::{Deref, DerefMut, Range};
use std::rc::Rc;
use std::sync::atomic::Ordering;
use std::time::Duration;

const NB_DEBUG_FLAGS_1: usize = 0xC;
const NB_DEBUG_FLAGS_2: usize = 0x10;

#[derive(Default)]
struct HookStorage {
    save_script_value_addr: Vec<u32>,
    save_script_value_at_index_addr: Vec<u32>,
    func_that_calls_command_parsing_addr: Vec<u32>,
    printf_r0_functions_addr: Vec<u32>,
    printf_r1_functions_addr: Vec<u32>,
    script_hook_addr: Vec<u32>,
    get_debug_flag_1_addr: Vec<u32>,
    get_debug_flag_2_addr: Vec<u32>,
    set_debug_flag_1_addr: Vec<u32>,
    set_debug_flag_2_addr: Vec<u32>,
    script_get_debug_mode_addr: Vec<u32>,
    ssb_load_addrs: Vec<u32>,
    ssx_load_addrs: Vec<u32>,
    talk_load_addrs: Vec<u32>,
    unionall_load_addr_ptr: Option<u32>,
}

pub struct SsbEmulatorDesmume {
    emu: DeSmuME,
    volume: u8,
    had_ever_rom_loaded: bool,
    hooks: HookStorage,
    address_loaded_overlay_group_1: u32,
    vars: Option<GameVariableManipulator>,
    debug_mode: bool,
    skip_dungeon_floors: Option<(bool, u32)>,
    debug_flag_temp_input: u32,
    debug_flags_1: [bool; NB_DEBUG_FLAGS_1],
    debug_flags_2: [bool; NB_DEBUG_FLAGS_2],
    exec_ground_hooks: HashMap<u32, DebugRegisterExecGroundCallback>,
}

/// Mutable reference to the one global DeSmuME instance. Dropping this will drop the global
/// instance.
pub struct SsbEmulatorDesmumeGlobal(&'static mut SsbEmulatorDesmume);

impl Deref for SsbEmulatorDesmumeGlobal {
    type Target = SsbEmulatorDesmume;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl DerefMut for SsbEmulatorDesmumeGlobal {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0
    }
}

impl Drop for SsbEmulatorDesmumeGlobal {
    fn drop(&mut self) {
        SELF.with(|self_global| {
            // SAFETY: We are the only ones accessing the emulator right now, since no other threads
            // can access the thread local data and everything else would violate the stated safety
            // constraints.
            unsafe { *self_global.get() = None };
        })
    }
}

thread_local! {
    /// Global emulator instance. Needed for exec callbacks.
    /// This is ONLY safe to use in hook callbacks and SsbEmulatorDesmume::new.
    static SELF: UnsafeCell<Option<SsbEmulatorDesmume>> = UnsafeCell::new(None);
    /// Hook sender. This needs to be thread-global for the hook functions.
    static HOOK_SENDER: RefCell<Option<Rc<Sender<HookExecute>>>> = RefCell::new(None);
    static HOOK_CB_SCRIPT_VARIABLE_SET: RefCell<Option<DebugRegisterScriptVariableSetCallback>> = RefCell::new(None);
    static HOOK_CB_SCRIPT_DEBUG: RefCell<Option<DebugRegisterScriptDebugCallback>> = RefCell::new(None);
    static HOOK_CB_SSB_LOAD: RefCell<Option<DebugRegisterSsbLoadCallback>> = RefCell::new(None);
    static HOOK_CB_SSX_LOAD: RefCell<Option<DebugRegisterSsxLoadCallback>> = RefCell::new(None);
    static HOOK_CB_TALK_LOAD: RefCell<Option<DebugRegisterTalkLoadCallback>> = RefCell::new(None);
    static HOOK_CB_SET_DEBUG_FLAG: RefCell<Option<DebugRegisterDebugFlagCallback>> = RefCell::new(None);
    static HOOK_CB_DEBUG_PRINT: RefCell<Option<DebugRegisterDebugPrintCallback>> = RefCell::new(None);
}

impl SsbEmulatorDesmumeGlobal {
    /// Creates the emulator, but panics if a global instance already exists for this thread!
    pub fn new() -> SsbEmulatorDesmumeGlobal {
        SELF.with(|global_self| {
            // SAFETY: This is OK because this is the only mutable reference we ever hand out
            //         and dropping the returned drop guard will uninit DeSmuME
            //         and we panic if this function is called when SELF is not none.
            //         and the access to SELF is explained to only otherwise be safe from within hook
            //         callbacks.
            unsafe {
                if (*global_self.get()).is_some() {
                    panic!("Emulator was already initialised.")
                };
                let slf = SsbEmulatorDesmume {
                    emu: match DeSmuME::init() {
                        Ok(emu) => emu,
                        Err(err) => {
                            panic!("Failed to init the emulator: {}", err)
                        }
                    },
                    volume: 100,
                    had_ever_rom_loaded: false,
                    hooks: Default::default(),
                    address_loaded_overlay_group_1: 0,
                    vars: None,
                    debug_mode: false,
                    skip_dungeon_floors: None,
                    debug_flag_temp_input: 0,
                    debug_flags_1: Default::default(),
                    debug_flags_2: Default::default(),
                    exec_ground_hooks: Default::default(),
                };
                *global_self.get() = Some(slf);
                SsbEmulatorDesmumeGlobal((*global_self.get()).as_mut().unwrap())
            }
        })
    }
}

impl SsbEmulator for SsbEmulatorDesmume {
    fn prepare_register_hooks(&mut self, hook_sender: &Rc<Sender<HookExecute>>) {
        HOOK_SENDER.with(|cell| cell.borrow_mut().replace(hook_sender.clone()));
    }

    fn supports_joystick(&self) -> bool {
        self.emu.input().joy_number_connected().is_ok()
    }

    fn is_running(&self) -> bool {
        self.emu.is_running()
    }

    fn cycle(&mut self) {
        self.emu.cycle()
    }

    fn flush_display_buffer(&self) {
        // SAFETY:
        // - We are the only writer.
        // - The slice is big enough.
        unsafe { DISPLAY_BUFFER.write(|buffer| self.emu.display_buffer_as_rgbx_into(buffer)) }
    }

    fn process_cmds(
        &mut self,
        command_channel_receive: &Receiver<EmulatorCommand>,
        command_channel_blocking_receive: &BlockingReceiver<EmulatorCommand>,
        blocking: bool,
    ) -> SsbEmulatorCommandResult {
        let mut should_shutdown = false;
        for cmd in command_channel_receive.try_iter() {
            should_shutdown &= self.do_process(cmd);
        }

        let update_blocking_cb = |cmd| should_shutdown &= self.do_process(cmd);
        if blocking {
            command_channel_blocking_receive
                .recv_timeout(update_blocking_cb, Duration::from_secs(2))
        } else {
            command_channel_blocking_receive.try_recv(update_blocking_cb)
        }

        // Process the dungeon skip setting
        if let Some((value, addr_dungeon_ptr)) = self.skip_dungeon_floors {
            self.apply_dungeon_skip(addr_dungeon_ptr, value);
        }

        if should_shutdown {
            SsbEmulatorCommandResult::Shutdown
        } else {
            SsbEmulatorCommandResult::Continue
        }
    }
}

impl SsbEmulator for SsbEmulatorDesmumeGlobal {
    fn prepare_register_hooks(&mut self, hook_sender: &Rc<Sender<HookExecute>>) {
        self.deref_mut().prepare_register_hooks(hook_sender)
    }

    fn supports_joystick(&self) -> bool {
        self.deref().supports_joystick()
    }

    fn is_running(&self) -> bool {
        self.deref().is_running()
    }

    fn cycle(&mut self) {
        self.deref_mut().cycle()
    }

    fn flush_display_buffer(&self) {
        self.deref().flush_display_buffer()
    }

    fn process_cmds(
        &mut self,
        command_channel_receive: &Receiver<EmulatorCommand>,
        command_channel_blocking_receive: &BlockingReceiver<EmulatorCommand>,
        blocking: bool,
    ) -> SsbEmulatorCommandResult {
        self.deref_mut().process_cmds(
            command_channel_receive,
            command_channel_blocking_receive,
            blocking,
        )
    }
}

impl SsbEmulatorDesmume {
    fn apply_dungeon_skip(&mut self, addr_dungeon_ptr: u32, value: bool) {
        if self.emu.is_running() && TICK_COUNT.load(Ordering::Relaxed) % 30 == 0 {
            dbg_trace!("SsbEmulatorDesmume::apply_dungeon_skip - {addr_dungeon_ptr}");
            if overlay29_loaded(self) {
                let dungeon_ptr = self.emu.memory().u32().index_move(addr_dungeon_ptr);
                dbg_trace!("SsbEmulatorDesmume::apply_dungeon_skip - loc: {dungeon_ptr}");
                // safety/sanity check
                if dungeon_ptr != 0 {
                    let mut u8_mem = self.emu.memory_mut().u8();
                    u8_mem.index_set(dungeon_ptr + 0x6, &(value as u8));
                    u8_mem.index_set(dungeon_ptr + 0x8, &(value as u8));
                }
            }
        }
    }

    fn do_process(&mut self, cmd: EmulatorCommand) -> bool {
        dbg_trace!("SsbEmulatorDesmume::do_process - {cmd:?}");
        match cmd {
            EmulatorCommand::NoOp => {}
            EmulatorCommand::Reset => {
                if self.had_ever_rom_loaded {
                    self.emu.volume_set(self.volume);
                    self.emu.reset();
                    self.emu.volume_set(self.volume);
                }
            }
            EmulatorCommand::Pause => {
                if self.had_ever_rom_loaded {
                    self.emu.pause()
                }
            }
            EmulatorCommand::Resume => {
                if self.had_ever_rom_loaded {
                    self.emu.volume_set(self.volume);
                    self.emu.resume(false)
                }
            }
            EmulatorCommand::Shutdown => {
                EMULATOR_IS_RUNNING.store(false, Ordering::Release);
                return true;
            }
            EmulatorCommand::OpenRom(
                filename,
                address_loaded_overlay_group_1,
                (global_addr, local_addr),
                value_addrs,
            ) => {
                self.emu
                    .open(&filename, false)
                    .map_err(|err| {
                        let msg = format!("Failed to open ROM: {err}");
                        warn!("{msg}");
                        send_hook(HookExecute::Error(msg));
                    })
                    .ok();
                self.emu.volume_set(self.volume);
                self.had_ever_rom_loaded = true;
                self.address_loaded_overlay_group_1 = address_loaded_overlay_group_1;
                self.vars = Some(GameVariableManipulator::new(
                    global_addr,
                    local_addr,
                    value_addrs,
                ));
            }
            EmulatorCommand::VolumeSet(volume) => {
                self.volume = volume;
                self.emu.volume_set(volume);
            }
            EmulatorCommand::SavestateSaveFile(filename) => {
                self.emu
                    .savestate_mut()
                    .save_file(&filename)
                    .map_err(|err| {
                        let msg = format!("Failed to save savestate: {err}");
                        warn!("{msg}");
                        send_hook(HookExecute::Error(msg));
                    })
                    .ok();
            }
            EmulatorCommand::SavestateLoadFile(filename) => {
                self.emu.volume_set(self.volume);
                self.emu
                    .savestate_mut()
                    .load_file(&filename)
                    .map_err(|err| {
                        let msg = format!("Failed to load savestate: {err}");
                        warn!("{msg}");
                        send_hook(HookExecute::Error(msg));
                    })
                    .ok();
                self.emu.volume_set(self.volume);
            }
            EmulatorCommand::SetLanguage(lang) => self.emu.set_language(lang.into()),
            EmulatorCommand::UnpressAllKeys => self.emu.input_mut().keypad_update(0),
            EmulatorCommand::JoyInit => {
                let was_success = self
                    .emu
                    .input_mut()
                    .joy_init()
                    .map_err(|err| {
                        let msg = format!("Failed to initialize joystick support: {err}");
                        warn!("{msg}");
                        send_hook(HookExecute::Error(msg));
                    })
                    .is_ok();

                // This now also changed whether the emulator supports joystick!
                EMULATOR_JOYSTICK_SUPPORTS.store(was_success, Ordering::Release);
            }
            EmulatorCommand::ReadMem(range, cb) => {
                let mem = self.do_read_mem(range);
                send_hook(HookExecute::ReadMemResult(mem, cb));
            }
            EmulatorCommand::ReadMemFromPtr(ptr, shift, size, cb) => {
                let start = self.emu.memory().u32().index_move(ptr) + shift;
                let range = start..(start + size);
                let mem = self.do_read_mem(range);
                send_hook(HookExecute::ReadMemResult(mem, cb));
            }
            EmulatorCommand::ReadMemFromPtrWithValidityCheck(
                ptr,
                shift,
                size,
                validity_offset,
                cb,
            ) => {
                let start = self.emu.memory().u32().index_move(ptr) + shift;
                let valid = self.emu.memory().i16().index_move(start + validity_offset);
                if valid > 0 {
                    dbg_trace!("Memory read with validity check was valid.");
                    let range = start..(start + size);
                    let mem = self.do_read_mem(range);
                    send_hook(HookExecute::ReadMemResult(mem, cb));
                } else {
                    dbg_trace!("Memory read with validity check was invalid.");
                }
            }
            EmulatorCommand::SetJoystickControls(jscfg) => {
                for (i, jskey) in jscfg.into_iter().enumerate() {
                    self.emu.input_mut().joy_set_key(i as u16, jskey).ok();
                }
            }
            EmulatorCommand::KeypadAddKey(keymask) => self.emu.input_mut().keypad_add_key(keymask),
            EmulatorCommand::KeypadRmKey(keymask) => self.emu.input_mut().keypad_rm_key(keymask),
            EmulatorCommand::TouchSetPos(x, y) => self.emu.input_mut().touch_set_pos(x, y),
            EmulatorCommand::TouchRelease => self.emu.input_mut().touch_release(),
            EmulatorCommand::JoyGetSetKey(key, cb) => {
                // todo: should probably do proper error handling here.
                let keycode = self
                    .emu
                    .input_mut()
                    .joy_get_set_key(key)
                    .unwrap_or_default();
                send_hook(HookExecute::JoyGetSetKey(keycode, cb));
            }
            EmulatorCommand::JoyGetNumberConnected(cb) => {
                let number = self.emu.input().joy_number_connected().unwrap_or_default();
                send_hook(HookExecute::JoyGetNumberConnected(number, cb));
            }
            EmulatorCommand::Debug(debug_cmd) => self.handle_debug_cmd(debug_cmd),
        }
        EMULATOR_IS_RUNNING.store(self.emu.is_running(), Ordering::Release);
        false
    }

    fn handle_debug_cmd(&mut self, debug_cmd: DebugCommand) {
        match debug_cmd {
            DebugCommand::RegisterScriptVariableSet {
                save_script_value_addr,
                save_script_value_at_index_addr,
                hook,
            } => {
                self.hooks
                    .save_script_value_addr
                    .extend_from_slice(&save_script_value_addr);
                self.hooks
                    .save_script_value_at_index_addr
                    .extend_from_slice(&save_script_value_at_index_addr);
                HOOK_CB_SCRIPT_VARIABLE_SET.with(|hook_cb| hook_cb.borrow_mut().replace(hook));
                for addr in save_script_value_addr {
                    self.emu
                        .memory_mut()
                        .register_exec(addr, Some(hook_script_variable_set));
                }
                for addr in save_script_value_at_index_addr {
                    self.emu
                        .memory_mut()
                        .register_exec(addr, Some(hook_script_variable_set_with_offset));
                }
            }
            DebugCommand::UnregisterScriptVariableSet => {
                for addr in mem::take(&mut self.hooks.save_script_value_addr) {
                    self.emu.memory_mut().register_exec(addr, None);
                }
                for addr in mem::take(&mut self.hooks.save_script_value_at_index_addr) {
                    self.emu.memory_mut().register_exec(addr, None);
                }
            }

            DebugCommand::RegisterScriptDebug {
                func_that_calls_command_parsing_addr,
                hook,
            } => {
                self.hooks
                    .func_that_calls_command_parsing_addr
                    .extend_from_slice(&func_that_calls_command_parsing_addr);
                HOOK_CB_SCRIPT_DEBUG.with(|hook_cb| hook_cb.borrow_mut().replace(hook));
                for addr in func_that_calls_command_parsing_addr {
                    self.emu
                        .memory_mut()
                        .register_exec(addr, Some(hook_script_debug));
                }
            }
            DebugCommand::UnregisterScriptDebug => {
                for addr in mem::take(&mut self.hooks.func_that_calls_command_parsing_addr) {
                    self.emu.memory_mut().register_exec(addr, None);
                }
            }

            DebugCommand::RegisterDebugPrint {
                printf_r0_functions_addr,
                printf_r1_functions_addr,
                script_hook_addr,
                hook,
            } => {
                self.hooks
                    .printf_r0_functions_addr
                    .extend_from_slice(&printf_r0_functions_addr);
                self.hooks
                    .printf_r1_functions_addr
                    .extend_from_slice(&printf_r1_functions_addr);
                self.hooks
                    .script_hook_addr
                    .extend_from_slice(&script_hook_addr);
                HOOK_CB_DEBUG_PRINT.with(|hook_cb| hook_cb.borrow_mut().replace(hook));
                for addr in printf_r0_functions_addr {
                    self.emu
                        .memory_mut()
                        .register_exec(addr, Some(hook_debug_print_printfs0));
                }
                for addr in printf_r1_functions_addr {
                    self.emu
                        .memory_mut()
                        .register_exec(addr, Some(hook_debug_print_printfs1));
                }
                for addr in script_hook_addr {
                    self.emu
                        .memory_mut()
                        .register_exec(addr, Some(script_hook_addr_script));
                }
            }
            DebugCommand::UnregisterDebugPrint => {
                for addr in mem::take(&mut self.hooks.printf_r0_functions_addr) {
                    self.emu.memory_mut().register_exec(addr, None);
                }
                for addr in mem::take(&mut self.hooks.printf_r1_functions_addr) {
                    self.emu.memory_mut().register_exec(addr, None);
                }
                for addr in mem::take(&mut self.hooks.script_hook_addr) {
                    self.emu.memory_mut().register_exec(addr, None);
                }
            }

            DebugCommand::RegisterDebugFlag {
                get_debug_flag_1_addr,
                get_debug_flag_2_addr,
                set_debug_flag_1_addr,
                set_debug_flag_2_addr,
                script_get_debug_mode_addr,
                hook,
            } => {
                self.hooks
                    .get_debug_flag_1_addr
                    .extend_from_slice(&get_debug_flag_1_addr);
                self.hooks
                    .get_debug_flag_2_addr
                    .extend_from_slice(&get_debug_flag_2_addr);
                self.hooks
                    .set_debug_flag_1_addr
                    .extend_from_slice(&set_debug_flag_1_addr);
                self.hooks
                    .set_debug_flag_2_addr
                    .extend_from_slice(&set_debug_flag_2_addr);
                self.hooks
                    .script_get_debug_mode_addr
                    .extend_from_slice(&script_get_debug_mode_addr);
                HOOK_CB_SET_DEBUG_FLAG.with(|hook_cb| hook_cb.borrow_mut().replace(hook));
                for addr in get_debug_flag_1_addr {
                    self.emu
                        .memory_mut()
                        .register_exec(addr, Some(hook_debug_get_debug_flag_get_input));
                    self.emu
                        .memory_mut()
                        .register_exec(addr + 4, Some(hook_debug_get_debug_flag_1));
                }
                for addr in get_debug_flag_2_addr {
                    self.emu
                        .memory_mut()
                        .register_exec(addr, Some(hook_debug_get_debug_flag_get_input));
                    self.emu
                        .memory_mut()
                        .register_exec(addr + 4, Some(hook_debug_get_debug_flag_2));
                }
                for addr in set_debug_flag_1_addr {
                    self.emu
                        .memory_mut()
                        .register_exec(addr, Some(hook_debug_set_debug_flag_1));
                }
                for addr in set_debug_flag_2_addr {
                    self.emu
                        .memory_mut()
                        .register_exec(addr, Some(hook_debug_set_debug_flag_2));
                }
                for addr in script_get_debug_mode_addr {
                    self.emu
                        .memory_mut()
                        .register_exec(addr, Some(hook_debug_debug_mode));
                }
            }
            DebugCommand::UnregisterDebugFlag => {
                for addr in mem::take(&mut self.hooks.get_debug_flag_1_addr) {
                    self.emu.memory_mut().register_exec(addr, None);
                    self.emu.memory_mut().register_exec(addr + 4, None);
                }
                for addr in mem::take(&mut self.hooks.get_debug_flag_2_addr) {
                    self.emu.memory_mut().register_exec(addr, None);
                    self.emu.memory_mut().register_exec(addr + 4, None);
                }
                for addr in mem::take(&mut self.hooks.set_debug_flag_1_addr) {
                    self.emu.memory_mut().register_exec(addr, None);
                }
                for addr in mem::take(&mut self.hooks.set_debug_flag_2_addr) {
                    self.emu.memory_mut().register_exec(addr, None);
                }
                for addr in mem::take(&mut self.hooks.script_get_debug_mode_addr) {
                    self.emu.memory_mut().register_exec(addr, None);
                }
            }

            DebugCommand::RegisterExecGround { addr, hook } => match hook {
                None => {
                    self.exec_ground_hooks.remove(&addr);
                    self.emu.memory_mut().register_exec(addr, None);
                }
                Some(hook) => {
                    self.exec_ground_hooks.insert(addr, hook);
                    self.emu
                        .memory_mut()
                        .register_exec(addr, Some(hook_exec_ground));
                }
            },

            DebugCommand::RegisterSsbLoad {
                ssb_load_addrs,
                hook,
            } => {
                self.hooks.ssb_load_addrs.extend_from_slice(&ssb_load_addrs);
                HOOK_CB_SSB_LOAD.with(|hook_cb| hook_cb.borrow_mut().replace(hook));
                for addr in ssb_load_addrs {
                    self.emu
                        .memory_mut()
                        .register_exec(addr, Some(hook_ssb_load));
                }
            }
            DebugCommand::UnregisterSsbLoad => {
                for addr in mem::take(&mut self.hooks.ssb_load_addrs) {
                    self.emu.memory_mut().register_exec(addr, None);
                }
            }

            DebugCommand::RegisterSsxLoad {
                ssx_load_addrs,
                hook,
            } => {
                self.hooks.ssx_load_addrs.extend_from_slice(&ssx_load_addrs);
                HOOK_CB_SSX_LOAD.with(|hook_cb| hook_cb.borrow_mut().replace(hook));
                for addr in ssx_load_addrs {
                    self.emu
                        .memory_mut()
                        .register_exec(addr, Some(hook_ssx_load));
                }
            }
            DebugCommand::UnregisterSsxLoad => {
                for addr in mem::take(&mut self.hooks.ssx_load_addrs) {
                    self.emu.memory_mut().register_exec(addr, None);
                }
            }

            DebugCommand::RegisterTalkLoad {
                talk_load_addrs,
                hook,
            } => {
                self.hooks
                    .talk_load_addrs
                    .extend_from_slice(&talk_load_addrs);
                HOOK_CB_TALK_LOAD.with(|hook_cb| hook_cb.borrow_mut().replace(hook));
                for addr in talk_load_addrs {
                    self.emu
                        .memory_mut()
                        .register_exec(addr, Some(hook_talk_load));
                }
            }
            DebugCommand::UnregisterTalkLoad => {
                for addr in mem::take(&mut self.hooks.talk_load_addrs) {
                    self.emu.memory_mut().register_exec(addr, None);
                }
            }

            DebugCommand::RegisterUnionallLoadAddrChange(pnt) => {
                self.hooks.unionall_load_addr_ptr = Some(pnt);
                self.emu.memory_mut().register_write(
                    pnt,
                    4,
                    Some(hook_write_unionall_load_addr_change),
                );
            }
            DebugCommand::UnregisterUnionallLoadAddrChange => {
                if let Some(unionall_load_addr_ptr) = self.hooks.unionall_load_addr_ptr {
                    self.emu
                        .memory_mut()
                        .register_write(unionall_load_addr_ptr, 4, None)
                }
            }
            DebugCommand::UnionallLoadAddressUpdate => update_unionall_load_address(self),

            DebugCommand::WriteGameVariable {
                var_id,
                var_offset,
                value,
            } => self.vars.as_ref().expect(ERR_EMU_INIT).write(
                &mut self.emu,
                var_id as u16,
                var_offset as u16,
                value,
                None,
            ),
            DebugCommand::SetDebugMode(value) => {
                self.debug_mode = value;
            }
            DebugCommand::SetDebugFlag1(bit, value) => {
                if bit < NB_DEBUG_FLAGS_1 {
                    self.debug_flags_1[bit] = value;
                }
            }
            DebugCommand::SetDebugFlag2(bit, value) => {
                if bit < NB_DEBUG_FLAGS_2 {
                    self.debug_flags_2[bit] = value;
                }
            }
            DebugCommand::SetDungeonSkip(addr, value) => {
                self.skip_dungeon_floors = Some((value, addr))
            }
            DebugCommand::SyncGlobalVars(cb) => {
                if let Some(vars) = self.vars.as_ref() {
                    vars.with_defs(&self.emu, |maybe_defs| {
                        if let Ok(defs) = maybe_defs {
                            let mut values = HashMap::with_capacity(defs.globals.len());
                            for var in &defs.globals {
                                let mut var_values = Vec::with_capacity(var.data.nbvalues as usize);
                                for offset in 0..(var.data.nbvalues) {
                                    let (_, val) =
                                        vars.read(&self.emu, var.id as u16, offset, None);
                                    var_values.push(val);
                                }
                                values.insert(var.id, var_values);
                            }
                            send_hook(HookExecute::SyncGlobalVars(cb.clone(), values));
                        }
                    })
                }
            }
            DebugCommand::SyncLocalVars(addr_of_pnt_to_breaked_for_entity, cb) => {
                let srs = ScriptRuntime::new(
                    addr_of_pnt_to_breaked_for_entity,
                    self.emu.memory().u8().index_move(
                        addr_of_pnt_to_breaked_for_entity
                            ..(addr_of_pnt_to_breaked_for_entity + ScriptRuntime::SIZE),
                    ),
                    UNIONALL_LOAD_ADDRESS.load(Ordering::Acquire),
                );
                let values = self.get_local_vars(&srs);
                if let Some(values) = values {
                    send_hook(HookExecute::SyncLocalVars(cb, values));
                }
            }
            DebugCommand::SyncMemTables(address_table_head, cb) => {
                let mut tables = vec![];

                for x in 0..(self.emu.memory().u32().index_move(address_table_head)) {
                    let address_table = address_table_head + 0x20 + 0x4 * x;
                    tables.push(EmulatorMemTable::read(&self.emu, address_table));
                }
                send_hook(HookExecute::SyncMemTables(cb, tables));
            }
            DebugCommand::DumpMemTableEntry(cb, start, length) => {
                send_hook(HookExecute::DumpMemTableEntry(
                    cb,
                    StBytes(Cow::Owned(
                        self.emu.memory().u8().index_move(start..(start + length)),
                    )),
                ));
            }
        }
    }

    fn vars(&self) -> &GameVariableManipulator {
        self.vars.as_ref().unwrap()
    }
    fn do_read_mem(&self, range: Range<u32>) -> Vec<u8> {
        #[cfg(not(debug_assertions))]
        let mem = self.emu.memory().u8().index_move(range);
        #[cfg(debug_assertions)]
        let mem = {
            let time_before = std::time::Instant::now();
            let mem = self.emu.memory().u8().index_move(range);
            let time_after = std::time::Instant::now();
            dbg_trace!(
                "memory read of {} bytes took {} ms.",
                mem.len(),
                (time_after - time_before).as_millis()
            );
            mem
        };
        mem
    }
    fn get_local_vars(&self, srs: &ScriptRuntime) -> Option<Vec<i32>> {
        self.vars.as_ref().and_then(|vars| {
            vars.with_defs(&self.emu, |maybe_defs| {
                if let Ok(defs) = maybe_defs {
                    let mut values = Vec::with_capacity(defs.locals.len());
                    for var in &defs.locals {
                        let (_, val) = vars.read(&self.emu, var.id as u16, 0, Some(srs));
                        values.push(val);
                    }
                    Some(values)
                } else {
                    None
                }
            })
        })
    }
}

fn send_hook(msg: HookExecute) {
    dbg_trace!("send_hook - {msg:?}");
    HOOK_SENDER.with(|s| {
        s.borrow()
            .as_ref()
            .unwrap()
            .send(msg)
            .expect("Thread controlling emulator has disconnected. Bailing!")
    });
}

macro_rules! take_pycallback_and_send_hook {
    ($global:expr, $cb_name:pat, $hook_execute:expr) => {
        $global.with(|cb_refcell| {
            let cb_borrowed = cb_refcell.borrow();
            if let Some(cb_asref) = cb_borrowed.as_ref() {
                let $cb_name = cb_asref.clone();
                send_hook($hook_execute);
            }
        });
    };
}

extern "C" fn hook_script_variable_set(_addr: u32, _size: i32) -> i32 {
    //dbg_trace!("desmume: hook_script_variable_set");
    SELF.with(|emu_cell| {
        let emu = unsafe { (*emu_cell.get()).as_mut().unwrap() };

        let var_id = emu.emu.memory().get_reg(Processor::Arm9, Register::R1);
        if BOOST_MODE.load(Ordering::Relaxed) || var_id >= 0x400 {
            return 1;
        };

        let value = emu.emu.memory().get_reg(Processor::Arm9, Register::R2);

        take_pycallback_and_send_hook!(
            HOOK_CB_SCRIPT_VARIABLE_SET,
            cb,
            HookExecute::DebugScriptVariableSet(cb, var_id, 0, value)
        );
        1
    })
}

extern "C" fn hook_script_variable_set_with_offset(_addr: u32, _size: i32) -> i32 {
    //dbg_trace!("desmume: hook_script_variable_set_with_offset");
    SELF.with(|emu_cell| {
        let emu = unsafe { (*emu_cell.get()).as_mut().unwrap() };

        let var_id = emu.emu.memory().get_reg(Processor::Arm9, Register::R1);
        if BOOST_MODE.load(Ordering::Relaxed) || var_id >= 0x400 {
            return 1;
        };

        let var_offset = emu.emu.memory().get_reg(Processor::Arm9, Register::R2);
        let value = emu.emu.memory().get_reg(Processor::Arm9, Register::R3);

        take_pycallback_and_send_hook!(
            HOOK_CB_SCRIPT_VARIABLE_SET,
            cb,
            HookExecute::DebugScriptVariableSet(cb, var_id, var_offset, value)
        );

        1
    })
}

/// MAIN DEBUGGER HOOK.
extern "C" fn hook_script_debug(_addr: u32, _size: i32) -> i32 {
    //dbg_trace!("desmume: hook_script_debug");
    SELF.with(|emu_cell| {
        let emu = unsafe { (*emu_cell.get()).as_mut().unwrap() };

        if BOOST_MODE.load(Ordering::Relaxed) {
            return 1;
        };

        let start_script_struct = emu.emu.memory().get_reg(Processor::Arm9, Register::R6);
        let srs = ScriptRuntime::new(
            start_script_struct,
            emu.emu
                .memory()
                .u8()
                .index_move(start_script_struct..(start_script_struct + ScriptRuntime::SIZE)),
            UNIONALL_LOAD_ADDRESS.load(Ordering::Acquire),
        );
        let current_opcode = emu.emu.memory().u16().index_move(srs.current_opcode_addr) as u32;

        let mut breakpoint_manager_guard =
            BREAKPOINT_MANAGER.lock().expect("debugger lock tainted");
        let mut breakpoint_manager = breakpoint_manager_guard.as_mut().expect(ERR_EMU_INIT);
        // this is ok, because only this thread writes to it.
        let tick = TICK_COUNT.load(Ordering::Relaxed);

        let script_target_slot =
            emu.emu.memory().u16().index_move(srs.script_target_address) as u32;

        let info = BreakpointInfo {
            opcode_offset: Some(srs.current_opcode_addr_relative),
            is_in_unionall: Some(srs.is_in_unionall),
            script_target_type: srs.script_target_type,
            script_target_slot,
        };

        let mut has_breaked = false;

        if !breakpoint_manager.breakpoints_disabled
            && breakpoint_manager.breakpoints_disabled_for_tick != Some(tick)
        {
            breakpoint_manager.breakpoints_disabled_for_tick = None;

            if let Some(Some(ssb_name)) = &breakpoint_manager
                .loaded_ssb_files
                .get(srs.hanger_ssb as usize)
            {
                if breakpoint_manager.force_break || breakpoint_manager.has(ssb_name, &info) {
                    has_breaked = true;
                    breakpoint_manager.reset_temporary();
                    breakpoint_manager.force_break = false;

                    drop(breakpoint_manager_guard);

                    {
                        let state = BreakpointState::new(
                            &srs,
                            start_script_struct,
                            script_target_slot,
                            emu.get_local_vars(&srs).unwrap_or_else(|| vec![0; 4]),
                        );
                        take_pycallback_and_send_hook!(
                            HOOK_CB_SCRIPT_DEBUG,
                            cb,
                            HookExecute::DebugScriptDebug {
                                cb,
                                breakpoint_state: Some(state),
                                script_target_slot_id: script_target_slot,
                                current_opcode,
                                script_runtime_struct_mem: StBytes(Cow::Owned(
                                    srs.clone().into_inner()
                                )),
                            }
                        );
                    }

                    emu.emu.volume_set(0);
                    // BREAK DEBUGGER
                    let break_signal = BREAK.clone();
                    let (break_mutex, break_cv) = &*break_signal;
                    let mut state_now = break_mutex
                        .lock()
                        .expect("Breakpoint controller panicked, bailing!");
                    // Wait for a change signal, then check again in the loop.
                    while state_now.state == BreakpointStateType::Stopped {
                        state_now = break_cv
                            .wait(state_now)
                            .expect("Breakpoint controller panicked, bailing!");
                    }

                    // Re-acquire breakpoint manager.
                    breakpoint_manager_guard =
                        BREAKPOINT_MANAGER.lock().expect("debugger lock tainted");
                    breakpoint_manager = breakpoint_manager_guard.as_mut().expect(ERR_EMU_INIT);

                    match state_now.state {
                        BreakpointStateType::FailHard => {
                            // Ok, we won't pause again this tick.
                            breakpoint_manager.breakpoints_disabled_for_tick = Some(tick);
                        }
                        BreakpointStateType::Resume => {
                            // We just resume, this is easy :)
                        }
                        BreakpointStateType::StepNext => {
                            // We force a break at the next run of this hook.
                            breakpoint_manager.force_break = true;
                        }
                        BreakpointStateType::StepOver => {
                            // We break at the next opcode in the current script file
                            breakpoint_manager.add_temporary(BreakpointInfo {
                                opcode_offset: None,
                                is_in_unionall: Some(srs.is_in_unionall),
                                script_target_type: srs.script_target_type,
                                script_target_slot,
                            });
                            // If the current op is the last one (we will step out next) this will lead to issues.
                            // We need to alternatively break at the current stack opcode (see StepOut).
                            if srs.has_call_stack {
                                breakpoint_manager.add_temporary(BreakpointInfo {
                                    opcode_offset: Some(
                                        srs.call_stack_current_opcode_addr_relative,
                                    ),
                                    is_in_unionall: None,
                                    script_target_type: srs.script_target_type,
                                    script_target_slot,
                                })
                            }
                        }
                        BreakpointStateType::StepInto => {
                            // We break at whatever is executed next for the current script target.
                            breakpoint_manager.add_temporary(BreakpointInfo {
                                opcode_offset: None,
                                is_in_unionall: None,
                                script_target_type: srs.script_target_type,
                                script_target_slot,
                            })
                        }
                        BreakpointStateType::StepOut => {
                            if srs.has_call_stack {
                                // We break at the opcode address stored on the call stack position.
                                breakpoint_manager.add_temporary(BreakpointInfo {
                                    opcode_offset: Some(
                                        srs.call_stack_current_opcode_addr_relative,
                                    ),
                                    is_in_unionall: None,
                                    script_target_type: srs.script_target_type,
                                    script_target_slot,
                                })
                            } else {
                                // We just resume
                            }
                        }
                        BreakpointStateType::StepManual => {
                            // We break at the requested opcode offset in the current hanger.
                            breakpoint_manager.add_temporary(BreakpointInfo {
                                opcode_offset: state_now.manual_step_opcode_offset,
                                is_in_unionall: Some(srs.is_in_unionall),
                                script_target_type: srs.script_target_type,
                                script_target_slot,
                            })
                        }
                        BreakpointStateType::Stopped => unreachable!(),
                    }
                }
            }
        }

        if !has_breaked {
            take_pycallback_and_send_hook!(
                HOOK_CB_SCRIPT_DEBUG,
                cb,
                HookExecute::DebugScriptDebug {
                    cb,
                    breakpoint_state: None,
                    script_target_slot_id: script_target_slot,
                    current_opcode,
                    script_runtime_struct_mem: StBytes(Cow::Owned(srs.clone().into_inner())),
                }
            );
        }

        1
    })
}

extern "C" fn hook_ssb_load(_addr: u32, _size: i32) -> i32 {
    //dbg_trace!("desmume: hook_ssb_load");
    SELF.with(|emu_cell| {
        let emu = unsafe { (*emu_cell.get()).as_mut().unwrap() };

        if overlay11_loaded(emu) {
            let name = emu
                .emu
                .memory()
                .read_cstring(emu.emu.memory().get_reg(Processor::Arm9, Register::R1));
            let name_as_string = name.to_string_lossy().to_string();
            {
                let mut breakpoint_manager_guard =
                    BREAKPOINT_MANAGER.lock().expect("debugger lock tainted");
                let breakpoint_manager = breakpoint_manager_guard.as_mut().expect(ERR_EMU_INIT);
                let load_for = breakpoint_manager.load_ssb_for.take().unwrap_or_default();
                if load_for as usize > MAX_SSB {
                    warn!("Invalid hanger ID for ssb: {load_for}")
                }
                breakpoint_manager.loaded_ssb_files[load_for as usize] =
                    Some(name_as_string.clone());
            }

            take_pycallback_and_send_hook!(
                HOOK_CB_SSB_LOAD,
                cb,
                HookExecute::DebugSsbLoad(cb, name_as_string)
            );
        }

        1
    })
}

extern "C" fn hook_ssx_load(_addr: u32, _size: i32) -> i32 {
    //dbg_trace!("desmume: hook_ssx_load");
    SELF.with(|emu_cell| {
        let emu = unsafe { (*emu_cell.get()).as_mut().unwrap() };

        if overlay11_loaded(emu) {
            let hanger = emu.emu.memory().get_reg(Processor::Arm9, Register::R2);
            if hanger as usize > MAX_SSX {
                warn!("Invalid hanger ID for ssx: {hanger}");
                return 1;
            }
            {
                let mut breakpoint_manager_guard =
                    BREAKPOINT_MANAGER.lock().expect("debugger lock tainted");
                let breakpoint_manager = breakpoint_manager_guard.as_mut().expect(ERR_EMU_INIT);
                breakpoint_manager.load_ssb_for = Some(hanger as u8);
            }

            let name = emu
                .emu
                .memory()
                .read_cstring(emu.emu.memory().get_reg(Processor::Arm9, Register::R3));
            let name_as_string = name.to_string_lossy().to_string();

            take_pycallback_and_send_hook!(
                HOOK_CB_SSX_LOAD,
                cb,
                HookExecute::DebugSsxLoad(cb, hanger, name_as_string)
            );
        }

        1
    })
}

extern "C" fn hook_talk_load(_addr: u32, _size: i32) -> i32 {
    //dbg_trace!("desmume: hook_talk_load");
    SELF.with(|emu_cell| {
        let emu = unsafe { (*emu_cell.get()).as_mut().unwrap() };

        if overlay11_loaded(emu) {
            let mut hanger = emu.emu.memory().get_reg(Processor::Arm9, Register::R0);

            // If the hanger is 1 - 3, this is a load for SSA/SSE/SSS.
            // Otherwise just take the number.
            // It's unknown what the exact mechanism / side effects are here.
            if hanger as usize <= TALK_HANGER_OFFSET {
                hanger += TALK_HANGER_OFFSET as u32;
            }

            {
                let mut breakpoint_manager_guard =
                    BREAKPOINT_MANAGER.lock().expect("debugger lock tainted");
                let breakpoint_manager = breakpoint_manager_guard.as_mut().expect(ERR_EMU_INIT);
                breakpoint_manager.load_ssb_for = Some(hanger as u8);
            }

            take_pycallback_and_send_hook!(
                HOOK_CB_TALK_LOAD,
                cb,
                HookExecute::DebugTalkLoad(cb, hanger)
            );
        }

        1
    })
}

extern "C" fn hook_write_unionall_load_addr_change(_addr: u32, _size: i32) -> i32 {
    //dbg_trace!("desmume: hook_write_unionall_load_addr_change");
    SELF.with(|emu_cell| {
        let emu = unsafe { (*emu_cell.get()).as_mut().unwrap() };
        update_unionall_load_address(emu);
    });
    1
}

fn update_unionall_load_address(emu: &mut SsbEmulatorDesmume) {
    //dbg_trace!("desmume: update_unionall_load_address");
    if overlay11_loaded(emu) {
        UNIONALL_LOAD_ADDRESS.store(
            emu.emu
                .memory()
                .u32()
                .index_move(emu.hooks.unionall_load_addr_ptr.expect(ERR_EMU_INIT)),
            Ordering::Release,
        );
    }
}

extern "C" fn hook_debug_print_printfs0(_addr: u32, _size: i32) -> i32 {
    //dbg_trace!("desmume: hook_debug_print_printfs0");
    _hook_debug_print_printfs(0)
}

extern "C" fn hook_debug_print_printfs1(_addr: u32, _size: i32) -> i32 {
    //dbg_trace!("desmume: hook_debug_print_printfs1");
    _hook_debug_print_printfs(1)
}

fn _hook_debug_print_printfs(register_offset: u32) -> i32 {
    SELF.with(|emu_cell| {
        let emu = unsafe { (*emu_cell.get()).as_mut().unwrap() };

        if BOOST_MODE.load(Ordering::Relaxed) {
            return 1;
        };

        let ptr = emu.emu.memory().get_reg(
            Processor::Arm9,
            Register::try_from(register_offset).unwrap(),
        );
        let dbg_cstring = emu.emu.memory().read_cstring(ptr);
        let dbg_string = dbg_cstring.to_string_lossy();

        let args_count = dbg_string.chars().filter(|c| *c == '%').count() as u32;
        let args = (0..args_count)
            .map(|i| {
                PrintfArg(
                    &emu.emu,
                    emu.emu.memory().get_reg(
                        Processor::Arm9,
                        Register::try_from(register_offset + i + 1).unwrap_or(Register::R15),
                    ),
                )
            })
            .collect::<Vec<_>>();
        let args_dyn = args
            .iter()
            .map(|v| v as &dyn Printf)
            .collect::<Vec<&dyn Printf>>();
        let formatted = vsprintf(dbg_string.as_ref(), &args_dyn).unwrap_or_else(|err| {
            format!(
                "[SkyTemple] Format failed: Format string was: '{dbg_string}' - Error: '{err:?}'"
            )
        });

        take_pycallback_and_send_hook!(
            HOOK_CB_DEBUG_PRINT,
            cb,
            HookExecute::DebugPrint(cb, EmulatorLogType::Printfs, formatted)
        );

        1
    })
}

extern "C" fn script_hook_addr_script(_addr: u32, _size: i32) -> i32 {
    //dbg_trace!("desmume: script_hook_addr_script");
    SELF.with(|emu_cell| {
        let emu = unsafe { (*emu_cell.get()).as_mut().unwrap() };

        if BOOST_MODE.load(Ordering::Relaxed) {
            return 1;
        };

        let start_script_struct = emu.emu.memory().get_reg(Processor::Arm9, Register::R4);
        let srs = ScriptRuntime::new(
            start_script_struct,
            emu.emu
                .memory()
                .u8()
                .index_move(start_script_struct..(start_script_struct + ScriptRuntime::SIZE)),
            UNIONALL_LOAD_ADDRESS.load(Ordering::Acquire),
        );
        let ssb_str_table_pointer = srs.start_addr_str_table;
        let current_op_pnt = emu.emu.memory().get_reg(Processor::Arm9, Register::R5);
        let current_op = emu.emu.memory().get_reg(Processor::Arm9, Register::R6);
        if current_op == 0x6B {
            // debug_Print
            let const_string = read_ssb_str_mem(
                emu,
                ssb_str_table_pointer,
                emu.emu.memory().u16().index_move(current_op_pnt + 2) as u32,
            );
            let string = format!("debug_Print: {}", const_string.to_string_lossy());
            take_pycallback_and_send_hook!(
                HOOK_CB_DEBUG_PRINT,
                cb,
                HookExecute::DebugPrint(cb, EmulatorLogType::DebugPrint, string)
            );
        } else if current_op == 0x6C {
            // debug_PrintFlag
            let var_id = emu.emu.memory().u16().index_move(current_op_pnt + 2);
            let (game_var_name, game_var_value) = emu.vars().read(&emu.emu, var_id, 0, Some(&srs));
            let const_string = read_ssb_str_mem(
                emu,
                ssb_str_table_pointer,
                emu.emu.memory().u16().index_move(current_op_pnt + 4) as u32,
            );
            let string = format!(
                "debug_PrintFlag: {} - {} = {}",
                const_string.to_string_lossy(),
                game_var_name,
                game_var_value
            );
            take_pycallback_and_send_hook!(
                HOOK_CB_DEBUG_PRINT,
                cb,
                HookExecute::DebugPrint(cb, EmulatorLogType::DebugPrint, string)
            );
        } else if current_op == 0x6D {
            // debug_PrintScenario
            let var_id = emu.emu.memory().u16().index_move(current_op_pnt + 2);
            let (game_var_name, game_var_value) = emu.vars().read(&emu.emu, var_id, 0, Some(&srs));
            let (_, level_value) = emu.vars().read(&emu.emu, var_id, 1, Some(&srs));
            let const_string = read_ssb_str_mem(
                emu,
                ssb_str_table_pointer,
                emu.emu.memory().u16().index_move(current_op_pnt + 4) as u32,
            );
            let string = format!(
                "debug_PrintScenario: {} - {} = scenario:{}, level:{}",
                const_string.to_string_lossy(),
                game_var_name,
                game_var_value,
                level_value
            );

            take_pycallback_and_send_hook!(
                HOOK_CB_DEBUG_PRINT,
                cb,
                HookExecute::DebugPrint(cb, EmulatorLogType::DebugPrint, string)
            );
        }

        1
    })
}

extern "C" fn hook_debug_get_debug_flag_get_input(_addr: u32, _size: i32) -> i32 {
    //dbg_trace!("desmume: hook_debug_get_debug_flag_get_input");
    SELF.with(|emu_cell| {
        let emu = unsafe { (*emu_cell.get()).as_mut().unwrap() };

        emu.debug_flag_temp_input = emu.emu.memory().get_reg(Processor::Arm9, Register::R0);

        1
    })
}

extern "C" fn hook_debug_get_debug_flag_1(_addr: u32, _size: i32) -> i32 {
    //dbg_trace!("desmume: hook_debug_get_debug_flag_1");
    SELF.with(|emu_cell| {
        let emu = unsafe { (*emu_cell.get()).as_mut().unwrap() };
        if emu.debug_flag_temp_input < NB_DEBUG_FLAGS_1 as u32 {
            emu.emu.memory_mut().set_reg(
                Processor::Arm9,
                Register::R0,
                emu.debug_flags_1[emu.debug_flag_temp_input as usize] as u32,
            );
        } else {
            warn!(
                "Invalid in hook_debug_get_debug_flag_1: {}",
                emu.debug_flag_temp_input
            );
        }
        1
    })
}

extern "C" fn hook_debug_get_debug_flag_2(_addr: u32, _size: i32) -> i32 {
    //dbg_trace!("desmume: hook_debug_get_debug_flag_2");
    SELF.with(|emu_cell| {
        let emu = unsafe { (*emu_cell.get()).as_mut().unwrap() };
        if emu.debug_flag_temp_input < NB_DEBUG_FLAGS_2 as u32 {
            emu.emu.memory_mut().set_reg(
                Processor::Arm9,
                Register::R0,
                emu.debug_flags_2[emu.debug_flag_temp_input as usize] as u32,
            );
        } else {
            warn!(
                "Invalid in hook_debug_get_debug_flag_2: {}",
                emu.debug_flag_temp_input
            );
        }
        1
    })
}

extern "C" fn hook_debug_set_debug_flag_1(_addr: u32, _size: i32) -> i32 {
    //dbg_trace!("desmume: hook_debug_set_debug_flag_1");
    SELF.with(|emu_cell| {
        let emu = unsafe { (*emu_cell.get()).as_mut().unwrap() };
        let flag_id = emu.emu.memory().get_reg(Processor::Arm9, Register::R0);
        let value = emu.emu.memory().get_reg(Processor::Arm9, Register::R1);

        if flag_id < NB_DEBUG_FLAGS_1 as u32 {
            emu.debug_flags_1[flag_id as usize] = value > 0;
        }

        take_pycallback_and_send_hook!(
            HOOK_CB_SET_DEBUG_FLAG,
            cb,
            HookExecute::DebugSetFlag(cb, 1, flag_id, value)
        );

        1
    })
}

extern "C" fn hook_debug_set_debug_flag_2(_addr: u32, _size: i32) -> i32 {
    //dbg_trace!("desmume: hook_debug_set_debug_flag_2");
    SELF.with(|emu_cell| {
        let emu = unsafe { (*emu_cell.get()).as_mut().unwrap() };
        let flag_id = emu.emu.memory().get_reg(Processor::Arm9, Register::R0);
        let value = emu.emu.memory().get_reg(Processor::Arm9, Register::R1);

        if flag_id < NB_DEBUG_FLAGS_2 as u32 {
            emu.debug_flags_2[flag_id as usize] = value > 0;
        }

        take_pycallback_and_send_hook!(
            HOOK_CB_SET_DEBUG_FLAG,
            cb,
            HookExecute::DebugSetFlag(cb, 2, flag_id, value)
        );

        1
    })
}

extern "C" fn hook_debug_debug_mode(_addr: u32, _size: i32) -> i32 {
    //dbg_trace!("desmume: hook_debug_debug_mode");
    SELF.with(|emu_cell| {
        let emu = unsafe { (*emu_cell.get()).as_mut().unwrap() };
        if emu.debug_mode {
            let old_v = emu.emu.memory_mut().get_reg(Processor::Arm9, Register::R0);
            let new_v = if old_v == 0 { 1 } else { 0 };
            emu.emu
                .memory_mut()
                .set_reg(Processor::Arm9, Register::R0, new_v);
        }
        1
    })
}

extern "C" fn hook_exec_ground(addr: u32, _size: i32) -> i32 {
    //dbg_trace!("desmume: hook_exec_ground");
    SELF.with(|emu_cell| {
        let emu = unsafe { (*emu_cell.get()).as_mut().unwrap() };

        if overlay11_loaded(emu) {
            if let Some(cb) = emu.exec_ground_hooks.get(&addr) {
                send_hook(HookExecute::ExecGround(cb.clone()));
            } else {
                panic!("Did not find registered ground callback: {addr}");
            }
        }
        1
    })
}

const ID_OF_SLOT_OF_OVERLAY11: u32 = 0xD;
const ID_OF_SLOT_OF_OVERLAY29: u32 = 0xE;

#[inline]
fn overlay_group1_loaded(emu: &SsbEmulatorDesmume) -> u32 {
    emu.emu
        .memory()
        .u32()
        .index_move(emu.address_loaded_overlay_group_1)
}

fn overlay11_loaded(emu: &SsbEmulatorDesmume) -> bool {
    overlay_group1_loaded(emu) == ID_OF_SLOT_OF_OVERLAY11
}

fn overlay29_loaded(emu: &SsbEmulatorDesmume) -> bool {
    overlay_group1_loaded(emu) == ID_OF_SLOT_OF_OVERLAY29
}

fn read_ssb_str_mem(emu: &SsbEmulatorDesmume, str_table_pointer: u32, index: u32) -> CString {
    let rel_pointer_to_const_str = emu
        .emu
        .memory()
        .u16()
        .index_move(str_table_pointer + (index * 2)) as u32;
    let abs_pointer_to_const_str = str_table_pointer + rel_pointer_to_const_str;
    // TODO: Support PMD2 strings?
    emu.emu.memory().read_cstring(abs_pointer_to_const_str)
}
