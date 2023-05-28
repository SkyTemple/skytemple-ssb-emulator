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

use crate::eos_debug::{
    emulator_unionall_load_address, BreakpointInfo, BreakpointState, BreakpointStateType, MAX_SSB,
    MAX_SSX, TALK_HANGER_OFFSET,
};
use crate::implementation::{SsbEmulator, SsbEmulatorCommandResult};
use crate::pycallbacks::*;
use crate::script_runtime::ScriptRuntime;
use crate::state::{
    BlockingReceiver, DebugCommand, EmulatorCommand, HookExecute, BOOST_MODE, BREAK,
    BREAKPOINT_MANAGER, DISPLAY_BUFFER, EMULATOR_IS_RUNNING, EMULATOR_JOYSTICK_SUPPORTS,
    ERR_EMU_INIT, TICK_COUNT, UNIONALL_LOAD_ADDRESS,
};
use crate::stbytes::StBytes;
use crossbeam_channel::{Receiver, Sender};
use log::warn;
use rs_desmume::mem::{IndexMove, Processor, Register};
use rs_desmume::DeSmuME;
use std::borrow::Cow;
use std::cell::{RefCell, UnsafeCell};
use std::ffi::CStr;
use std::mem;
use std::ops::{Deref, DerefMut};
use std::rc::Rc;
use std::sync::atomic::Ordering;
use std::time::Duration;

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
}

pub struct SsbEmulatorDesmume(DeSmuME, HookStorage);

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
                let slf = SsbEmulatorDesmume(
                    match DeSmuME::init() {
                        Ok(emu) => emu,
                        Err(err) => {
                            panic!("Failed to init the emulator: {}", err)
                        }
                    },
                    Default::default(),
                );
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
    fn do_process(&mut self, cmd: EmulatorCommand) -> bool {
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
                        send_hook(HookExecute::Error(msg));
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
                        send_hook(HookExecute::Error(msg));
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
                        send_hook(HookExecute::Error(msg));
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
                        send_hook(HookExecute::Error(msg));
                    })
                    .is_ok();

                // This now also changed whether the emulator supports joystick!
                EMULATOR_JOYSTICK_SUPPORTS.store(was_success, Ordering::Release);
            }
            EmulatorCommand::ReadMem(range, cb) => {
                let mem = self.0.memory().u8().index_move(range);
                send_hook(HookExecute::ReadMemResult(mem, cb));
            }
            EmulatorCommand::ReadMemFromPtr(ptr, shift, size, cb) => {
                let start = self.0.memory().u32().index_move(ptr);
                let mem = self
                    .0
                    .memory()
                    .u8()
                    .index_move((start + shift)..(ptr + size));
                send_hook(HookExecute::ReadMemResult(mem, cb));
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
                send_hook(HookExecute::JoyGetNumberConnected(number, cb));
            }
            EmulatorCommand::Debug(debug_cmd) => self.handle_debug_cmd(debug_cmd),
        }
        EMULATOR_IS_RUNNING.store(self.0.is_running(), Ordering::Release);
        false
    }

    fn handle_debug_cmd(&mut self, debug_cmd: DebugCommand) {
        match debug_cmd {
            DebugCommand::RegisterScriptVariableSet {
                save_script_value_addr,
                save_script_value_at_index_addr,
                hook,
            } => {
                self.1
                    .save_script_value_addr
                    .extend_from_slice(&save_script_value_addr);
                self.1
                    .save_script_value_at_index_addr
                    .extend_from_slice(&save_script_value_at_index_addr);
                HOOK_CB_SCRIPT_VARIABLE_SET.with(|hook_cb| hook_cb.borrow_mut().replace(hook));
                for addr in save_script_value_addr {
                    self.0
                        .memory_mut()
                        .register_exec(addr, Some(hook_script_variable_set));
                }
                for addr in save_script_value_at_index_addr {
                    self.0
                        .memory_mut()
                        .register_exec(addr, Some(hook_script_variable_set_with_offset));
                }
            }
            DebugCommand::UnregisterScriptVariableSet => {
                for addr in mem::take(&mut self.1.save_script_value_addr) {
                    self.0.memory_mut().register_exec(addr, None);
                }
                for addr in mem::take(&mut self.1.save_script_value_at_index_addr) {
                    self.0.memory_mut().register_exec(addr, None);
                }
            }

            DebugCommand::RegisterScriptDebug {
                func_that_calls_command_parsing_addr,
                hook,
            } => {
                self.1
                    .func_that_calls_command_parsing_addr
                    .extend_from_slice(&func_that_calls_command_parsing_addr);
                HOOK_CB_SCRIPT_DEBUG.with(|hook_cb| hook_cb.borrow_mut().replace(hook));
                for addr in func_that_calls_command_parsing_addr {
                    self.0
                        .memory_mut()
                        .register_exec(addr, Some(hook_script_debug));
                }
            }
            DebugCommand::UnregisterScriptDebug => {
                for addr in mem::take(&mut self.1.func_that_calls_command_parsing_addr) {
                    self.0.memory_mut().register_exec(addr, None);
                }
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
                self.1.ssb_load_addrs.extend_from_slice(&ssb_load_addrs);
                HOOK_CB_SSB_LOAD.with(|hook_cb| hook_cb.borrow_mut().replace(hook));
                for addr in ssb_load_addrs {
                    self.0.memory_mut().register_exec(addr, Some(hook_ssb_load));
                }
            }
            DebugCommand::UnregisterSsbLoad => {
                for addr in mem::take(&mut self.1.ssb_load_addrs) {
                    self.0.memory_mut().register_exec(addr, None);
                }
            }

            DebugCommand::RegisterSsxLoad {
                ssx_load_addrs,
                hook,
            } => {
                self.1.ssx_load_addrs.extend_from_slice(&ssx_load_addrs);
                HOOK_CB_SSX_LOAD.with(|hook_cb| hook_cb.borrow_mut().replace(hook));
                for addr in ssx_load_addrs {
                    self.0.memory_mut().register_exec(addr, Some(hook_ssx_load));
                }
            }
            DebugCommand::UnregisterSsxLoad => {
                for addr in mem::take(&mut self.1.ssx_load_addrs) {
                    self.0.memory_mut().register_exec(addr, None);
                }
            }

            DebugCommand::RegisterTalkLoad {
                talk_load_addrs,
                hook,
            } => {
                self.1.talk_load_addrs.extend_from_slice(&talk_load_addrs);
                HOOK_CB_TALK_LOAD.with(|hook_cb| hook_cb.borrow_mut().replace(hook));
                for addr in talk_load_addrs {
                    self.0
                        .memory_mut()
                        .register_exec(addr, Some(hook_talk_load));
                }
            }
            DebugCommand::UnregisterTalkLoad => {
                for addr in mem::take(&mut self.1.talk_load_addrs) {
                    self.0.memory_mut().register_exec(addr, None);
                }
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
}

fn send_hook(msg: HookExecute) {
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
    SELF.with(|emu_cell| {
        let emu = unsafe { (*emu_cell.get()).as_mut().unwrap() };

        let var_id = emu.0.memory().get_reg(Processor::Arm9, Register::R1);
        if BOOST_MODE.load(Ordering::Relaxed) || var_id >= 0x400 {
            return 1;
        };

        let value = emu.0.memory().get_reg(Processor::Arm9, Register::R2);

        take_pycallback_and_send_hook!(
            HOOK_CB_SCRIPT_VARIABLE_SET,
            cb,
            HookExecute::DebugScriptVariableSet(cb, var_id, 0, value)
        );
        1
    })
}

extern "C" fn hook_script_variable_set_with_offset(_addr: u32, _size: i32) -> i32 {
    SELF.with(|emu_cell| {
        let emu = unsafe { (*emu_cell.get()).as_mut().unwrap() };

        let var_id = emu.0.memory().get_reg(Processor::Arm9, Register::R1);
        if BOOST_MODE.load(Ordering::Relaxed) || var_id >= 0x400 {
            return 1;
        };

        let var_offset = emu.0.memory().get_reg(Processor::Arm9, Register::R2);
        let value = emu.0.memory().get_reg(Processor::Arm9, Register::R3);

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
    SELF.with(|emu_cell| {
        let emu = unsafe { (*emu_cell.get()).as_mut().unwrap() };

        if BOOST_MODE.load(Ordering::Relaxed) {
            return 1;
        };

        let start_script_struct = emu.0.memory().get_reg(Processor::Arm9, Register::R6);
        let srs = ScriptRuntime::new(
            emu.0
                .memory()
                .u8()
                .index_move(start_script_struct..(start_script_struct + ScriptRuntime::SIZE)),
            UNIONALL_LOAD_ADDRESS.load(Ordering::Acquire),
        );

        let mut breakpoint_manager_guard =
            BREAKPOINT_MANAGER.lock().expect("debugger lock tainted");
        let mut breakpoint_manager = breakpoint_manager_guard.as_mut().expect(ERR_EMU_INIT);
        // this is ok, because only this thread writes to it.
        let tick = TICK_COUNT.load(Ordering::Relaxed);

        let script_target_slot = emu.0.memory().u16().index_move(srs.script_target_address) as u32;

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
                        let state = BreakpointState::new(&srs, script_target_slot);
                        take_pycallback_and_send_hook!(
                            HOOK_CB_SCRIPT_DEBUG,
                            cb,
                            HookExecute::DebugScriptDebug {
                                cb,
                                breakpoint_state: Some(state),
                                script_target_slot_id: script_target_slot,
                                current_opcode: srs.current_opcode_addr_relative,
                                script_runtime_struct_mem: StBytes(Cow::Owned(
                                    srs.clone().into_inner()
                                )),
                            }
                        );
                    }

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
                    current_opcode: srs.current_opcode_addr_relative,
                    script_runtime_struct_mem: StBytes(Cow::Owned(srs.clone().into_inner())),
                }
            );
        }

        1
    })
}

extern "C" fn hook_ssb_load(_addr: u32, _size: i32) -> i32 {
    SELF.with(|emu_cell| {
        let emu = unsafe { (*emu_cell.get()).as_mut().unwrap() };

        if overlay11_loaded(emu) {
            if let Ok(name) =
                read_cstring(emu, emu.0.memory().get_reg(Processor::Arm9, Register::R1))
            {
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
            } else {
                warn!("Invalid SSB name string when loading.");
            }
        }

        1
    })
}

extern "C" fn hook_ssx_load(_addr: u32, _size: i32) -> i32 {
    SELF.with(|emu_cell| {
        let emu = unsafe { (*emu_cell.get()).as_mut().unwrap() };

        if overlay11_loaded(emu) {
            let hanger = emu.0.memory().get_reg(Processor::Arm9, Register::R2);
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

            if let Ok(name) =
                read_cstring(emu, emu.0.memory().get_reg(Processor::Arm9, Register::R3))
            {
                let name_as_string = name.to_string_lossy().to_string();

                take_pycallback_and_send_hook!(
                    HOOK_CB_SSX_LOAD,
                    cb,
                    HookExecute::DebugSsxLoad(cb, hanger, name_as_string)
                );
            } else {
                warn!("Invalid SSX name string when loading.");
            }
        }

        1
    })
}

extern "C" fn hook_talk_load(_addr: u32, _size: i32) -> i32 {
    SELF.with(|emu_cell| {
        let emu = unsafe { (*emu_cell.get()).as_mut().unwrap() };

        if overlay11_loaded(emu) {
            let mut hanger = emu.0.memory().get_reg(Processor::Arm9, Register::R0);

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

fn overlay11_loaded(emu: &mut SsbEmulatorDesmume) -> bool {
    todo!()
}

fn read_cstring(emu: &mut SsbEmulatorDesmume, start: u32) -> Result<&CStr, ()> {
    todo!()
}
