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
use crate::display_buffer::DisplayBuffer;
use crate::eos_debug::{
    BreakpointManager, BreakpointResumeInfo, BreakpointState, BreakpointStateType, EmulatorLogType,
};
use crate::game_variable::GameVariablesValueAddresses;
use crate::implementation::desmume::SsbEmulatorDesmumeGlobal;
use crate::implementation::{SsbEmulator, SsbEmulatorCommandResult};
use crate::language::Language;
use crate::pycallbacks::{
    DebugRegisterDebugFlagCallback, DebugRegisterDebugPrintCallback,
    DebugRegisterExecGroundCallback, DebugRegisterScriptDebugCallback,
    DebugRegisterScriptVariableSetCallback, DebugRegisterSsbLoadCallback,
    DebugRegisterSsxLoadCallback, DebugRegisterTalkLoadCallback, DebugSyncGlobalVarsCallback,
    DebugSyncLocalVarsCallback, DebugSyncMemTablesCallback, EmulatorMemTableEntryCallback,
    JoyGetNumberConnectedCallback, JoyGetSetKeyCallback, ReadMemCallback,
};
use crate::stbytes::StBytes;
use crossbeam_channel::{bounded, unbounded, Receiver, Sender};
use lazy_static::lazy_static;
use log::warn;
use std::cell::RefCell;
use std::collections::HashMap;
use std::ops::Range;
use std::panic::{catch_unwind, panic_any, AssertUnwindSafe, UnwindSafe};
use std::pin::Pin;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::thread::{sleep, JoinHandle};
use std::time::{Duration, Instant};

pub static ERR_EMU_INIT: &str = "Emulator was not properly initialized.";

// ---------------------------------------------------
// Local to the thread that called [`emulator_start`].
thread_local! {
    /// The thread join handle of the thread that currently runs the emulator.
    pub static EMULATOR_THREAD: RefCell<Option<JoinHandle<()>>> = RefCell::new(None);
    /// Sender channel for sending commands to the emulator thread
    /// that do not require acknowledgement.
    static COMMAND_CHANNEL_SEND: RefCell<Option<Sender<EmulatorCommand>>> = RefCell::new(None);
    /// Sender channel for sending commands to the emulator thread
    /// that do require acknowledgement. This channel has zero-capacity.
    static COMMAND_CHANNEL_BLOCKING_SEND: RefCell<Option<BlockingSender<EmulatorCommand>>> = RefCell::new(None);
    /// Receiver channel for hook events.
    pub static HOOK_CHANNEL_RECEIVE: RefCell<Option<Receiver<HookExecute>>> = RefCell::new(None);
}
// ---------------------------------------------------

// ------------
// Global state
lazy_static! {
    /// The display buffer, RGBx, ready for display.
    pub static ref DISPLAY_BUFFER: Pin<Box<DisplayBuffer>> = DisplayBuffer::new();
    /// The global registry of breakpoints for a loaded ROM.
    pub static ref BREAKPOINT_MANAGER: Arc<Mutex<Option<BreakpointManager>>> = Arc::new(Mutex::new(None));
    /// Condvar and breakpoint state for the debugger when breaking and waking to be woken up again.
    /// The Option<u32> is the manual requested next breakpoint, if any.
    pub static ref BREAK: Arc<(Mutex<BreakpointResumeInfo>, Condvar)> = Arc::new((
        Mutex::new(BreakpointResumeInfo {
            state: BreakpointStateType::Stopped,
            manual_step_opcode_offset: None,
        }),
        Condvar::new(),
    ));
}
/// Whether or not boost mode is on. In boost mode some operations are not processed or processed
/// less frequently to speed up overall emulation. In this mode the framerate of the emulator is
/// unlocked.
pub static BOOST_MODE: AtomicBool = AtomicBool::new(false);
/// Current tick count. Rolls over and may be reset.
pub static TICK_COUNT: AtomicU64 = AtomicU64::new(0);
/// Whether or not the emulator is currently running.
pub static EMULATOR_IS_RUNNING: AtomicBool = AtomicBool::new(false);
/// Whether joystick/gamepads are supported by the emulator.
pub static EMULATOR_JOYSTICK_SUPPORTS: AtomicBool = AtomicBool::new(false);
/// Current unionall load address. May be zero if non determinable.
pub static UNIONALL_LOAD_ADDRESS: AtomicU32 = AtomicU32::new(0);
// ------------

const NANOS_PER_TICK: u64 = 16666666;

/// State of the emulator thread.
pub struct EmulatorThreadState<E>
where
    E: SsbEmulator,
{
    emulator: E,
    /// Receive channel for commands to execute to the emulator.
    command_channel_receive: Receiver<EmulatorCommand>,
    /// Receive channel for blocking commands to execute to the emulator.
    command_channel_blocking_receive: BlockingReceiver<EmulatorCommand>,
    /// Send channel for executed hooks.
    hook_channel_send: Rc<Sender<HookExecute>>,
}

#[derive(Debug)]
pub enum DebugCommand {
    RegisterScriptVariableSet {
        save_script_value_addr: Vec<u32>,
        save_script_value_at_index_addr: Vec<u32>,
        hook: DebugRegisterScriptVariableSetCallback,
    },
    UnregisterScriptVariableSet,
    RegisterScriptDebug {
        func_that_calls_command_parsing_addr: Vec<u32>,
        hook: DebugRegisterScriptDebugCallback,
    },
    UnregisterScriptDebug,
    RegisterDebugPrint {
        printf_r0_functions_addr: Vec<u32>,
        printf_r1_functions_addr: Vec<u32>,
        script_hook_addr: Vec<u32>,
        hook: DebugRegisterDebugPrintCallback,
    },
    UnregisterDebugPrint,
    RegisterDebugFlag {
        get_debug_flag_1_addr: Vec<u32>,
        get_debug_flag_2_addr: Vec<u32>,
        set_debug_flag_1_addr: Vec<u32>,
        set_debug_flag_2_addr: Vec<u32>,
        script_get_debug_mode_addr: Vec<u32>,
        hook: DebugRegisterDebugFlagCallback,
    },
    UnregisterDebugFlag,
    RegisterExecGround {
        addr: u32,
        hook: Option<DebugRegisterExecGroundCallback>,
    },
    RegisterSsbLoad {
        ssb_load_addrs: Vec<u32>,
        hook: DebugRegisterSsbLoadCallback,
    },
    UnregisterSsbLoad,
    RegisterSsxLoad {
        ssx_load_addrs: Vec<u32>,
        hook: DebugRegisterSsxLoadCallback,
    },
    UnregisterSsxLoad,
    RegisterTalkLoad {
        talk_load_addrs: Vec<u32>,
        hook: DebugRegisterTalkLoadCallback,
    },
    UnregisterTalkLoad,
    RegisterUnionallLoadAddrChange(u32),
    UnregisterUnionallLoadAddrChange,
    UnionallLoadAddressUpdate,
    WriteGameVariable {
        var_id: u32,
        var_offset: u32,
        value: i32,
    },
    SetDebugMode(bool),
    SetDebugFlag1(usize, bool),
    SetDebugFlag2(usize, bool),
    SetDungeonSkip(u32, bool),
    SyncGlobalVars(DebugSyncGlobalVarsCallback),
    SyncLocalVars(u32, DebugSyncLocalVarsCallback),
    SyncMemTables(u32, DebugSyncMemTablesCallback),
    DumpMemTableEntry(EmulatorMemTableEntryCallback, u32, u32),
}

#[derive(Debug)]
pub enum EmulatorCommand {
    NoOp,
    Reset,
    Pause,
    Resume,
    Shutdown,
    OpenRom(String, u32, (u32, u32), GameVariablesValueAddresses),
    VolumeSet(u8),
    SavestateSaveFile(String),
    SavestateLoadFile(String),
    SetLanguage(Language),
    UnpressAllKeys,
    JoyInit,
    ReadMem(Range<u32>, ReadMemCallback),
    ReadMemFromPtr(u32, u32, u32, ReadMemCallback),
    ReadMemFromPtrWithValidityCheck(u32, u32, u32, u32, ReadMemCallback),
    SetJoystickControls([i32; 15]),
    KeypadAddKey(u16),
    KeypadRmKey(u16),
    TouchSetPos(u16, u16),
    TouchRelease,
    JoyGetSetKey(u16, JoyGetSetKeyCallback),
    JoyGetNumberConnected(JoyGetNumberConnectedCallback),
    Debug(DebugCommand),
}

#[derive(Debug)]
pub enum HookExecute {
    /// An error to display.
    Error(String),
    /// Read memory, ready to be passed to the callback.
    ReadMemResult(Vec<u8>, ReadMemCallback),
    /// Call callback for `emulator_get_joy_number_connected`.
    JoyGetNumberConnected(u16, JoyGetNumberConnectedCallback),
    JoyGetSetKey(u16, JoyGetSetKeyCallback),
    DebugScriptVariableSet(DebugRegisterScriptVariableSetCallback, u32, u32, u32),
    DebugScriptDebug {
        cb: DebugRegisterScriptDebugCallback,
        breakpoint_state: Option<BreakpointState>,
        script_target_slot_id: u32,
        current_opcode: u32,
        script_runtime_struct_mem: StBytes<'static>,
    },
    DebugSsbLoad(DebugRegisterSsbLoadCallback, String),
    DebugSsxLoad(DebugRegisterSsxLoadCallback, u32, String),
    DebugTalkLoad(DebugRegisterTalkLoadCallback, u32),
    DebugPrint(DebugRegisterDebugPrintCallback, EmulatorLogType, String),
    DebugSetFlag(DebugRegisterDebugFlagCallback, u32, u32, u32),
    ExecGround(DebugRegisterExecGroundCallback),
    SyncGlobalVars(DebugSyncGlobalVarsCallback, HashMap<usize, Vec<i32>>),
    SyncLocalVars(DebugSyncLocalVarsCallback, Vec<i32>),
    SyncMemTables(DebugSyncMemTablesCallback, Vec<EmulatorMemTable>),
    DumpMemTableEntry(EmulatorMemTableEntryCallback, StBytes<'static>),
}

struct EmulatorThreadStateCreate<E>
where
    E: SsbEmulator,
{
    emulator_create: fn() -> E,
    command_channel_receive: Receiver<EmulatorCommand>,
    command_channel_blocking_receive: BlockingReceiver<EmulatorCommand>,
    hook_channel_send: Sender<HookExecute>,
    command_channel_send: Sender<EmulatorCommand>,
    command_channel_blocking_send: BlockingSender<EmulatorCommand>,
    hook_channel_receive: Receiver<HookExecute>,
}

impl EmulatorThreadStateCreate<SsbEmulatorDesmumeGlobal> {
    fn create_desmume() -> Self {
        dbg_trace!("EmulatorThreadStateCreate::create_desmume");
        let emulator_create = SsbEmulatorDesmumeGlobal::new;
        let (command_channel_send, command_channel_receive) = unbounded();
        let (command_channel_blocking_send, command_channel_blocking_receive) =
            make_blocking_channel();
        let (hook_channel_send, hook_channel_receive) = unbounded();

        EmulatorThreadStateCreate {
            emulator_create,
            command_channel_receive,
            command_channel_blocking_receive,
            hook_channel_send,
            command_channel_send,
            command_channel_blocking_send,
            hook_channel_receive,
        }
    }
}

pub fn init(cell: &mut Option<JoinHandle<()>>) {
    dbg_trace!("init state");
    let EmulatorThreadStateCreate {
        emulator_create,
        command_channel_receive,
        command_channel_blocking_receive,
        hook_channel_send,
        command_channel_send,
        command_channel_blocking_send,
        hook_channel_receive,
    } = EmulatorThreadStateCreate::create_desmume();

    COMMAND_CHANNEL_SEND.with(|v| v.borrow_mut().replace(command_channel_send));
    COMMAND_CHANNEL_BLOCKING_SEND.with(|v| v.borrow_mut().replace(command_channel_blocking_send));
    HOOK_CHANNEL_RECEIVE.with(|v| v.borrow_mut().replace(hook_channel_receive));

    cell.replace(emulator_thread(
        emulator_create,
        command_channel_receive,
        command_channel_blocking_receive,
        hook_channel_send,
    ));
}

fn emulator_thread<E>(
    emulator_create: fn() -> E,
    command_channel_receive: Receiver<EmulatorCommand>,
    command_channel_blocking_receive: BlockingReceiver<EmulatorCommand>,
    hook_channel_send: Sender<HookExecute>,
) -> JoinHandle<()>
where
    E: SsbEmulator + 'static,
{
    dbg_trace!("emulator_thread");

    thread::spawn(move || {
        let mut state = EmulatorThreadState {
            emulator: emulator_create(),
            command_channel_receive,
            command_channel_blocking_receive,
            hook_channel_send: Rc::new(hook_channel_send),
        };
        state
            .emulator
            .prepare_register_hooks(&state.hook_channel_send);

        EMULATOR_JOYSTICK_SUPPORTS.store(state.emulator.supports_joystick(), Ordering::Release);

        loop {
            // We can use relaxed ordering, as we really don't need any accuracy here.
            let mut boost_mode = BOOST_MODE.load(Ordering::Relaxed);
            // We can use relaxed ordering, since we are the only one writing to it.
            let mut tick_count = TICK_COUNT.load(Ordering::Relaxed);
            dbg_trace!("emulator_thread - resume?");
            while {
                let is_running = state.emulator.is_running();
                EMULATOR_IS_RUNNING.store(is_running, Ordering::Release);
                is_running
            } {
                // Run update and draw loop.
                let time_before = Instant::now();
                state.emulator.cycle();

                if !boost_mode || tick_count % 60 == 0 {
                    state.emulator.flush_display_buffer();
                }

                if !boost_mode {
                    let diff = Instant::now() - time_before;
                    // we sleep 0,05ms less, just to account for potential scheduling lag. Probably
                    // a better experience if we overall run a tiny bit faster than slower.
                    let diff_ns = diff.as_nanos() as u64 - 50000;
                    if diff_ns < NANOS_PER_TICK {
                        sleep(Duration::from_nanos(NANOS_PER_TICK - diff_ns))
                    }
                }

                // Check and process commands.
                match state.emulator.process_cmds(
                    &state.command_channel_receive,
                    &state.command_channel_blocking_receive,
                    false,
                ) {
                    SsbEmulatorCommandResult::Continue => {}
                    SsbEmulatorCommandResult::Shutdown => {
                        // End the thread.
                        return;
                    }
                }

                tick_count += 1;
                TICK_COUNT.store(tick_count, Ordering::Relaxed);
                boost_mode = BOOST_MODE.load(Ordering::Relaxed);
            }
            dbg_trace!("emulator_thread - paused");

            if !boost_mode || tick_count % 60 == 0 {
                state.emulator.flush_display_buffer();
            }

            // Wait for a new command to come in, blocking.
            match state.emulator.process_cmds(
                &state.command_channel_receive,
                &state.command_channel_blocking_receive,
                true,
            ) {
                SsbEmulatorCommandResult::Continue => {}
                SsbEmulatorCommandResult::Shutdown => {
                    // End the thread.
                    return;
                }
            }
        }
    })
}

/// A channel that is a pair of a zero-capacity data/task channel
/// and a zero-capacity acknowledgement channel. Whenever sending tasks
/// over the data channel, the thread will block for acknowledgements on the
/// receive channel. Whenever receiving, after the task is done, an acknowledgment
/// will send over the acknowledgement channel.
fn make_blocking_channel<T>() -> (BlockingSender<T>, BlockingReceiver<T>)
where
    T: UnwindSafe,
{
    let (data_send, data_receive) = bounded(0);
    let (ack_send, ack_receive) = bounded(0);
    (
        BlockingSender::new(data_send, ack_receive),
        BlockingReceiver::new(data_receive, ack_send),
    )
}

enum AckResponse {
    Ok,
    Panic,
}

pub struct BlockingSender<T> {
    data: Sender<T>,
    ack: Receiver<AckResponse>,
}

impl<T> BlockingSender<T> {
    fn new(data: Sender<T>, ack: Receiver<AckResponse>) -> Self {
        Self { data, ack }
    }

    /// Send a message and block until it is received and either acknowledged
    /// or the thread receiving it panicked before acknowledging, in which case
    /// this will panic. On disconnect, does nothing.
    ///
    /// Times out after 2 seconds on data and ack channels respectively.
    pub fn send(&self, data: T) {
        match self.data.send_timeout(data, Duration::from_secs(2)) {
            Ok(_) => match self.ack.recv_timeout(Duration::from_secs(2)) {
                Ok(AckResponse::Ok) => {}
                Ok(AckResponse::Panic) => {
                    panic!("BlockingSender: Receiver thread panicked! Bailing!")
                }
                Err(_) => warn!("Blocking sender ack channel timed out or is disconnected."),
            },
            Err(_) => warn!("Blocking sender data channel timed out or is disconnected."),
        }
    }
}

pub struct BlockingReceiver<T> {
    data: Receiver<T>,
    ack: Sender<AckResponse>,
}

impl<T> BlockingReceiver<T>
where
    T: UnwindSafe,
{
    fn new(data: Receiver<T>, ack: Sender<AckResponse>) -> Self {
        Self { data, ack }
    }

    /// Try to receive a message. If not available, does nothing.
    /// If available, calls the passed callback and passes the received data to it.
    /// Afterwards acknowledges the receive. If the callback panics, this is signaled
    /// to the sender and the panic is propagated. Panics on any errors.
    pub fn try_recv<F>(&self, cb: F)
    where
        F: FnOnce(T),
    {
        if let Ok(v) = self.data.try_recv() {
            self.process(cb, v)
        }
    }

    /// Receive a message. If not available, blocks waiting for a message.
    /// If available, calls the passed callback and passes the received data to it.
    /// Afterwards acknowledges the receive. If the callback panics, this is signaled
    /// to the sender and the panic is propagated. Panics on any errors.
    pub fn recv_timeout<F>(&self, cb: F, timeout: Duration)
    where
        F: FnOnce(T),
    {
        if let Ok(v) = self.data.recv_timeout(timeout) {
            self.process(cb, v)
        }
    }

    fn process<F>(&self, cb: F, v: T)
    where
        F: FnOnce(T),
    {
        match catch_unwind(AssertUnwindSafe(|| cb(v))) {
            Ok(_) => self
                .ack
                .send(AckResponse::Ok)
                .expect("BlockingReceiver: Other end disconnected. Bailing."),
            Err(panic) => {
                self.ack.send(AckResponse::Panic).ok();
                panic_any(panic)
            }
        }
    }
}

#[inline]
pub fn command_channel_send(data: EmulatorCommand) {
    COMMAND_CHANNEL_SEND.with(|sender| {
        if sender
            .borrow()
            .as_ref()
            .expect(ERR_EMU_INIT)
            .send(data)
            .is_err()
        {
            warn!("Sender is disconnected.")
        }
    })
}

#[inline]
pub fn command_channel_blocking_send(data: EmulatorCommand) {
    COMMAND_CHANNEL_BLOCKING_SEND
        .with(|sender| sender.borrow().as_ref().expect(ERR_EMU_INIT).send(data))
}
