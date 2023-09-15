"""
Emulator interface for SkyTemple Script Engine Debugger.
"""
from __future__ import annotations
from typing import Sequence, Callable, Optional, Mapping, ClassVar, Protocol

from range_typed_integers import u32, u64

SCREEN_PIXEL_SIZE: int
SCREEN_WIDTH: int
SCREEN_HEIGHT: int
SCREEN_HEIGHT_BOTH: int


class EmulatorMemAllocType:
    """Type of memory allocation, enum like."""
    Free: ClassVar[EmulatorMemAllocType] # = 0x00
    Static: ClassVar[EmulatorMemAllocType] # = 0x01
    Block: ClassVar[EmulatorMemAllocType] # = 0x02
    Temporary: ClassVar[EmulatorMemAllocType] # = 0x03
    SubTable: ClassVar[EmulatorMemAllocType] # = 0x04

    def __int__(self):
        """Returns the numeric value."""
        ...

    name: str
    value: int


class EmulatorMemTableEntry:
    """An entry in a memory table."""
    type_alloc: EmulatorMemAllocType
    unk1: int
    unk2: int
    start_address: int
    available: int
    used: int

    def dump(self, cb: Callable[[bytes], None]):
        """Passes the bytes of the entry to the callback when ready and emulator_poll is called."""


class EmulatorMemTable:
    """"A memory table."""
    entries: Sequence[EmulatorMemTableEntry]
    start_address: int
    parent_table: int
    addr_table: int
    max_entries: int
    addr_data: int
    len_data: int


class Language:
    """Language codes, enum like."""
    Japanese: ClassVar[Language]
    English: ClassVar[Language]
    French: ClassVar[Language]
    German: ClassVar[Language]
    Italian: ClassVar[Language]
    Spanish: ClassVar[Language]

    def __new__(cls, value: int):
        ...

    def __int__(self):
        """Returns the numeric value."""
        ...

    name: str
    value: int


class EmulatorLogType:
    Printfs: ClassVar[EmulatorLogType]
    DebugPrint: ClassVar[EmulatorLogType]


class EmulatorKeys:
    """DS key identifiers. NB_KEYS contains the total number of keys."""
    NB_KEYS	= 15
    KEY_NONE = 0
    KEY_A = 1
    KEY_B = 2
    KEY_SELECT = 3
    KEY_START = 4
    KEY_RIGHT = 5
    KEY_LEFT = 6
    KEY_UP = 7
    KEY_DOWN = 8
    KEY_R = 9
    KEY_L = 10
    KEY_X = 11
    KEY_Y = 12
    KEY_DEBUG = 13
    KEY_BOOST = 14
    KEY_LID = 15
    NO_KEY_SET = 0xFFFF


def emulator_is_initialized() -> bool:
    """
    Checks if the emulator was initialized with `emulator_start` (from this thread).
    """
    ...


def emulator_start():
    """
    Starts the emulator. After this the other functions will work correctly, but only
    from the thread that originally called this function.
    """
    ...


def emulator_reset():
    """
    Reset emulation. This also resets the game and fully reloads the ROM file.
    """
    ...


def emulator_pause():
    """
    Pause emulation, freezing the render and update loop.
    """
    ...


def emulator_resume():
    """
    Resume emulation, if it was paused.
    """
    ...


def emulator_unpress_all_keys():
    """
    Clears all pressed keys and buttons.
    """
    ...


def emulator_joy_init():
    """
    Initializes joystick support, if available, otherwise does nothing.
    """
    ...


def emulator_set_boost(state: bool):
    """
    Enable or disable boost mode. In this mode some debugging hooks may not be executed to improve
    emulator performance.
    """
    ...


def emulator_set_language(lang: Language):
    """
    Set firmware language.
    """
    ...


def emulator_open_rom(
        filename: str,
        *,
        address_loaded_overlay_group_1: u32,
        global_variable_table_start_addr: u32,
        local_variable_table_start_addr: u32,
        global_script_var_values: u32,
        game_state_values: u32,
        language_info_data: u32,
        game_mode: u32,
        debug_special_episode_number: u32,
        notify_note: u32
):
    """
    Open a ROM file. This will reset emulation, if the emulator is currently running.
    """
    ...


def emulator_shutdown():
    """
    Shuts down the emulator. It can be loaded again after this.
    """
    ...


def emulator_wait_one_cycle():
    """
    Waits until the emulator has completed the currently processing frame and all queued-up commands
    previous to this call.
    """
    ...


EmulatorErrorCallback = Callable[[str], None]
EmulatorErrorCallback.__doc__ = "signature: def _(error: str)"



def emulator_poll(error_consumer: EmulatorErrorCallback):
    """
    Polls new emulator events from the emulator thread and runs all pending hooks.
    All pending hook functions will be run blocking on the thread calling emulator_poll.

    The error_consumer callback function will be called for any error that occurred since
    the last poll.
    
    Returns true if at least one event was processed.
    """
    ...


def emulator_read_mem(address_start: u32, address_end: u32, cb: Callable[[bytes], None]):
    """
    Read a chunk of memory [address_start,address_end).
    The chunk is passed to the callback as soon as it's available
    and `emulator_poll` has been called to poll the value.
    """
    ...


def emulator_read_mem_from_ptr(ptr: u32, shift: u32, size: u32, cb: Callable[[bytes], None]):
    """
    Read a chunk of memory starting at the address pointed to by `ptr`, then shifted by `shift`
    and with the length of `size` bytes.
    The chunk is passed to the callback as soon as it's available
    and `emulator_poll` has been called to poll the value.
    """
    ...


def emulator_read_mem_from_ptr_with_validity_check(ptr: u32, shift: u32, size: u32, validity_offset: u32, cb: Callable[[bytes], None]):
    """
    Same as `emulator_read_mem_from_ptr`, but only calls the callback if the
    value at `validity_offset` read as an `i16` and starting from `(*ptr)+shift` is `> 0`.
    """
    ...



EmulatorScriptVariableSetHook = Callable[[int, int, int], None]
EmulatorScriptVariableSetHook.__doc__ = "signature: def _(var_id: int, var_offset: int, value: int)"


def emulator_register_script_variable_set(
        save_script_value_addr: Optional[Sequence[int]],
        save_script_value_at_index_addr: Optional[Sequence[int]],
        hook: EmulatorScriptVariableSetHook
):
    """
    Register a hook to call when a script variable was set. Replaces the previously registered hook.
    The hook is called asynchronously by polling `emulator_poll` on the receiving thread.
    """
    ...


def emulator_unregister_script_variable_set():
    """Unregister all potentially previously registered hooks for setting script variables."""
    ...


def emulator_sync_tables(addr_mem_alloc_table: u32, cb: Callable[[Sequence[EmulatorMemTable]], None]):
    """
    Synchronize and retrieve and return the memory allocation tables and pass
    them to the callback when ready and [`emulator_poll`] is called.
    """
    ...


EmulatorScriptDebugHook = Callable[[Optional[BreakpointState], bytes, u32, u32], None]
EmulatorScriptDebugHook.__doc__ = "signature: def _(break_state: Optional[BreakpointState], script_runtime_struct_mem: bytes, script_target_slot_id: u32, current_opcode: u32)"


def emulator_register_script_debug(
        func_that_calls_command_parsing_addr: Optional[Sequence[int]],
        hook: EmulatorScriptDebugHook,
):
    """
    Registers the debugger. The debugger will break depending on the state of the breakpoints currently
    configured.

    Also register a hook to process script engine debugging events. Replaces the previously registered hooks.
    The hooks are called asynchronously by polling `emulator_poll` on the receiving thread.
    """
    ...


def emulator_unregister_script_debug():
    """Unregister all potentially previously registered hooks for processing script debugging events."""
    ...


EmulatorDebugPrintHook = Callable[[EmulatorLogType, str], None]
EmulatorDebugPrintHook.__doc__ = "signature: def _(type: EmulatorLogType, msg: str)"
EmulatorSetDebugFlagHook = Callable[[int, int, int], None]
EmulatorSetDebugFlagHook.__doc__ = "signature: def _(var_id: int, flag_id: int, value: int)"
EmulatorExecHook = Callable[[], None]
EmulatorExecHook.__doc__ = "signature: def _()"
EmulatorSsbLoadHook = Callable[[str], None]
EmulatorSsbLoadHook.__doc__ = "signature: def _(name: str)"
EmulatorSsxLoadHook = Callable[[int, str], None]
EmulatorSsxLoadHook.__doc__ = "signature: def _(hanger: int, name: str)"
EmulatorTalkLoadHook = Callable[[int], None]
EmulatorTalkLoadHook.__doc__ = "signature: def _(hanger: int)"


def emulator_register_debug_print(
        printf_r0_functions_addr: Optional[Sequence[int]],
        printf_r1_functions_addr: Optional[Sequence[int]],
        script_hook_addr: Optional[Sequence[int]],
        hook: EmulatorDebugPrintHook
):
    """
    Register a hook to process debug print logging. Replaces the previously registered hook.
    The hook is called asynchronously by polling `emulator_poll` on the receiving thread.

    The messaged passed to the hook may already be preformatted for display in the UI.

    # printf hooks
    `printf_r0_functions_addr` will be hooked into and will read registers for printf starting at r0,
    `printf_r1_functions_addr` will also be hooked into but start reading at r1.

    # script debug log hook
    `script_hook_addr` must be 0x3C40 bytes into the `ScriptCommandParsing` function of the game. This hook
    processes `debug_Print` and related script opcodes.

    """
    ...


def emulator_unregister_debug_print():
    """Unregister all potentially previously registered hooks for processing debug print logging."""
    ...


def emulator_register_debug_flag(
        get_debug_flag_1_addr: Optional[Sequence[int]],
        get_debug_flag_2_addr: Optional[Sequence[int]],
        set_debug_flag_1_addr: Optional[Sequence[int]],
        set_debug_flag_2_addr: Optional[Sequence[int]],
        script_get_debug_mode_addr: Optional[Sequence[int]],
        hook: EmulatorSetDebugFlagHook
):
    """
    Register an internal hook to the game's functions to retrieve debug flag values to instead return the flags
    set by `emulator_set_debug_flag_1` and `emulator_set_debug_flag_2`.

    These values are also overwritten, and reported back to the `hook_debug_flag` when they are set by the game.

    Additionally, hooks the script engine function responsible to determine if script debugging is enabled and returns
    the value set by `emulator_set_debug_mode`.
    The hook is called asynchronously by polling `emulator_poll` on the receiving thread.
    """
    ...


def emulator_unregister_debug_flag():
    """Unregister all potentially previously registered hooks for processing debug flags."""
    ...


def emulator_register_exec_ground(addr: int, hook: Optional[EmulatorExecHook]):
    """
    Register a hook to run when the given address is executed. If the hook is None, it is unregistered.

    The hook is not called should overlay 11 not be loaded.
    """
    ...


def emulator_register_ssb_load(
        ssb_load_addrs: Optional[Sequence[int]], hook: EmulatorSsbLoadHook
):
    """
    Register a hook to run, whenever an SSB file is loaded.

    The hook is not called should overlay 11 not be loaded.
    """
    ...


def emulator_unregister_ssb_load():
    """Unregister SSB load hook."""
    ...


def emulator_register_ssx_load(
        ssx_load_addrs: Optional[Sequence[int]], hook: EmulatorSsxLoadHook
):
    """
    Register a hook to run, whenever an SSx file is loaded.

    The hook is not called should overlay 11 not be loaded.
    """
    ...


def emulator_unregister_ssx_load():
    """Unregister SSx load hook."""
    ...


def emulator_register_talk_load(
        talk_load_addrs: Optional[Sequence[int]], hook: EmulatorTalkLoadHook
):
    """
    Register a hook to run, whenever a talk SSx file is loaded.

    The hook is not called should overlay 11 not be loaded.
    """
    ...


def emulator_unregister_talk_load():
    """Unregister SSx talk load hook."""
    ...


def emulator_register_unionall_load_addr_change(unionall_pointer: int):
    """
    Registers a hook for watching the unionall pointer. This allows retreiving it at any time via
    `emulator_unionall_load_address`
    """
    ...


def emulator_unregister_unionall_load_addr_change():
    """Unregister unionall update watcher. The address returned will now no longer match the game state."""
    ...


def emulator_unionall_load_address() -> int:
    """
    Returns the address unionall is loaded at currently. May return 0 if not determinable.
    """
    ...


def emulator_unionall_load_address_update():
    """
    Fetches the current unionall load address from the emulator into the cache.
    This requires `emulator_register_unionall_load_addr_change` to be called before.
    """
    ...


def emulator_write_game_variable(var_id: int, var_offset: int, value: int):
    """
    Queues writing the game variable to the game.
    This is done at latest the next time the emulator's memory is ready to be written to.
    """
    ...


def emulator_set_debug_mode(value: bool):
    """
    Queues writing the debug mode state.
    This is done at latest the next time the emulator's memory is ready to be written to.
    """
    ...


def emulator_set_debug_flag_1(bit: int, value: bool):
    """
    Queues writing a bit of debug flag 1.
    This is done at latest the next time the emulator's memory is ready to be written to.
    """
    ...


def emulator_set_debug_flag_2(bit: int, value: bool):
    """
    Queues writing a bit of debug flag 2.
    This is done at latest the next time the emulator's memory is ready to be written to.
    """
    ...


def emulator_set_debug_dungeon_skip(addr_of_ptr_to_dungeon_struct: u32, value: bool):
    """
    Enables or disables the automatic skip of dungeon floors when inside of dungeons.
    """
    ...


def emulator_tick() -> u64:
    """Returns a value close or equal to the current tick count of the emulator. Rolls over at the u64 limit."""
    ...


def emulator_sync_vars(cb: Callable[[Mapping[int, Sequence[int]]], None]):
    """
    Retrieve the values of global variable values from the emulator and passes
    them to the callback when ready and [`emulator_poll`] is called.
    """
    ...


def emulator_sync_local_vars(addr_of_pnt_to_breaked_for_entity: int, cb: Callable[[Sequence[int]], None]):
    """
    Retrieve the values of local variable values from the emulator and passes
    them to the callback when ready and [`emulator_poll`] is called.
    """
    ...


def emulator_load_controls(keyboard_cfg: Optional[Sequence[int]], joypad_cfg: Optional[Sequence[int]]):
    """
    Change the control settings for keyboard and joystick to the values provided. If any of the values is None,
    the controls are not changed.
    """
    ...


def emulator_get_kbcfg() -> Sequence[int]:
    """Returns the currently active keyboard configuration."""
    ...


def emulator_get_jscfg() -> Sequence[int]:
    """Returns the currently active joystick configuration."""
    ...


def emulator_set_kbcfg(value: Sequence[int]):
    """Sets the currently active keyboard configuration."""
    ...


def emulator_set_jscfg(value: Sequence[int], propagate_to_emulator: bool):
    """
    Sets the currently active joystick configuration.

    NOTE: If `propagate_to_emulator` is false, this does NOT forward the information to the
    emulator's internals that control the joystick/gamepad.
    Useful when also using emulator_joy_get_set_key.
    """
    ...


def emulator_keymask(key: int) -> int:
    """Returns the keymask for key `k`. `k` is a constant of `EmulatorKeys`."""
    ...


def emulator_keypad_add_key(keymask: int):
    """Add a key to the keypad."""
    ...


def emulator_keypad_rm_key(keymask: int):
    """Remove a key from the keypad."""
    ...


def emulator_touch_set_pos(pos_x: int, pos_y: int):
    """Touch and hold a point on the touchscreen."""
    ...


def emulator_touch_release():
    """Release the touchscreen."""
    ...


def emulator_supports_joystick() -> bool:
    """Returns whether the emulator supports joysticks."""
    ...


def emulator_get_joy_number_connected(cb: Callable[[int], None]):
    """
    Returns the number of connected joysticks.
    The callback is called eventually when the emulator is polled (`emulator_poll`).
    """
    ...


def emulator_joy_get_set_key(key: int, cb: Callable[[int], None]):
    """
    Pause the thread and wait for the user to press a button.
    This button will be assigned to the specified emulator key. Joysticks must be initialized.
    This does not update the internal joystick control map. Collect set keys and after
    all changes use `emulator_set_jscfg`.
    The callback is called eventually when the emulator is polled (`emulator_poll`).
    """
    ...


def emulator_is_running() -> bool:
    """
    Returns `true`, if a game is loaded and the emulator is running (not paused).
    """
    ...


def emulator_volume_set(value: int):
    """Set the emulator volume (0-100)."""
    ...


def emulator_savestate_save_file(path: str):
    """Queues the emulator to save a savestate file to the given path. May also do this blocking."""
    ...


def emulator_savestate_load_file(path: str):
    """Queues the emulator to load a savestate file from the given path. May also do this blocking."""
    ...


def emulator_get_key_names() -> Sequence[str]:
    """Returns the internal names of keys, indexed by key ID"""
    ...


def emulator_display_buffer_as_rgbx() -> bytes:
    """Returns the display buffer of the emulator in RGBx format."""
    ...


def emulator_debug_init_breakpoint_manager(breakpoints_json_filename: str):
    """(Re)-initializes the debug breakpoint manager."""
    ...


def emulator_debug_set_loaded_ssb_breakable(ssb_filename: str, value: bool):
    """
    Change whether the SSB file identified by the given name can currently be breaked in.
    A file is not debuggable, if an old state is loaded in RAM and old breakpoint mappings are not available.

    Defaults to true for all files.
    """
    ...


def emulator_debug_breakpoints_disabled_get() -> bool:
    """Whether halting at breakpoints is currently globally disabled"""
    ...


def emulator_debug_breakpoints_disabled_set(val: bool):
    """Set whether halting at breakpoints is currently globally disabled"""
    ...


class SsbLoadedFileProtocol(Protocol):
    filename: str
    ram_state_up_to_date: bool

    def register_reload_event_manager(self, cb: Callable[[SsbLoadedFileProtocol], None]):
        pass


def emulator_debug_breakpoints_resync(ssb_filename: str, b_points: Sequence[int], ssb_loaded_file: SsbLoadedFileProtocol):
    """
    Re-synchronize breakpoints for the given ssb file.
    
    This is triggered, after a ssb file was saved.
    If the file is still open in the ground engine, the new state is written to file and
    a temporary dict, but is not used yet. The Breakpoint register registers itself as a
    callback for that SSB file and waits until it is no longer loaded in the ground engine.
    If the file is not open in the ground engine, the changes are applied immediately.
   
    Callbacks for adding are NOT called as for emulator_debug_breakpoint_add.
    """
    ...


def emulator_debug_breakpoint_add(ssb_filename: str, opcode_offset: int):
    """Add a breakpoint for the given ssb file."""
    ...


def emulator_debug_breakpoint_remove(ssb_filename: str, opcode_offset: int):
    """Remove a breakpoint for the given ssb file, if it exists. Otherwise do nothing."""
    ...


def emulator_breakpoints_get_saved_in_ram_for(ssb_filename: str) -> Sequence[int]:
    """Returns all breakpoints currently stored for the given ssb file in RAM."""
    ...


def emulator_breakpoints_set_loaded_ssb_files(
        hanger0: Optional[str],
        hanger1: Optional[str],
        hanger2: Optional[str],
        hanger3: Optional[str],
        hanger4: Optional[str],
        hanger5: Optional[str],
        hanger6: Optional[str],
):
    """Set the loaded SSB files for all 7 hangers. This is needed when loading save states, resetting the ROM etc."""
    ...


def emulator_breakpoints_set_load_ssb_for(hanger_id: Optional[int]):
    """Set the hanger that an SSB will be loaded for next. This is needed when loading save states, resetting the ROM etc."""
    ...


EmulatorDebugBreakpointCallback = Callable[[str, int], None]
EmulatorDebugBreakpointCallback.__doc__ = "signature: def _(ssb_filename: str, opcode_offset: int)"


def emulator_debug_register_breakpoint_callbacks(
        on_breakpoint_added: EmulatorDebugBreakpointCallback,
        on_breakpoint_removed: EmulatorDebugBreakpointCallback
) -> Sequence[int]:
    """
    Register callbacks to call when breakpoints are added or removed.
    The callbacks may be called when calling emulator_poll, or directly when
    emulator_debug_breakpoint_add or emulator_debug_breakpoint_remove are called.
    """
    ...


class BreakpointStateType:
    """State of the debugger halted at a breakpoint. Enum-like."""
    # INITIAL STATE: The breakpoint is being stopped at.
    Stopped: ClassVar[BreakpointStateType]
    # FINAL STATES: What happened / what to do next? - See the corresponding methods of BreakpointState.
    FailHard: ClassVar[BreakpointStateType]
    Resume: ClassVar[BreakpointStateType]
    StepOver: ClassVar[BreakpointStateType]
    StepInto: ClassVar[BreakpointStateType]
    StepOut: ClassVar[BreakpointStateType]
    StepNext: ClassVar[BreakpointStateType]
    # Manually step to an opcode offset of the SSB file currently stopped for.
    StepManual: ClassVar[BreakpointStateType]

    def __int__(self):
        """Returns the numeric value."""
        ...


class BreakpointState:
    """
    The current state of the stepping mechanism of the debugger.
    If is_stopped(), the code execution of the emulator thread is currently on hold.

    The object may optionally have a file state object, which describes more about the debugger state
    for this breakpoint (eg. which source file is breaked in, if breaked on macro call)

    These objects are not reusable. They can not transition back to the initial STOPPED state.
    """
    file_state: Optional[object]

    @property
    def state(self) -> BreakpointStateType: ...

    @property
    def script_runtime_struct_mem(self) -> bytes: ...

    @property
    def script_runtime_struct_addr(self) -> u32: ...

    @property
    def script_target_slot_id(self) -> u32: ...

    @property
    def local_vars_values(self) -> Sequence[int]: ...

    @property
    def current_opcode(self) -> u32: ...

    @property
    def hanger_id(self) -> u32: ...

    def add_release_hook(self, hook: Callable[[BreakpointState], None]):
        """Called when polling the emulator after the debugging break has been released."""
        ...

    def is_stopped(self) -> bool: ...

    def fail_hard(self):
        """Immediately abort debugging and don't break again it this tick."""
        ...

    def resume(self):
        """Resume normal code execution."""
        ...

    def step_into(self):
        """Step into the current call (if it's a call that creates a call stack), otherwise same as step over."""
        ...

    def step_over(self):
        """Step over the current call (remain in the current script file + skip debugging any calls to subroutines)."""
        ...

    def step_out(self):
        """Step out of the current routine, if there's a call stack, otherwise same as resume."""
        ...

    def step_next(self):
        """Break at the next opcode, even if it's for a different script target."""
        ...

    def step_manual(self, opcode_offset: int):
        """Transition to the StepManual state and set the opcode to halt at."""
        ...

    def transition(self, state_type: BreakpointStateType):
        """Transition to the specified state. Can not transition to Stopped."""
        ...
