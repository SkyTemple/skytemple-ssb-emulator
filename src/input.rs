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

use crate::pycallbacks::{JoyGetNumberConnectedCallback, JoyGetSetKeyCallback};
use crate::state::{
    command_channel_blocking_send, command_channel_send, EmulatorCommand,
    EMULATOR_JOYSTICK_SUPPORTS,
};
use desmume_rs::input::keymask;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PySequence;
use std::cell::RefCell;
use std::sync::atomic::Ordering;

pub const NB_KEYS: u8 = desmume_rs::input::NB_KEYS;
pub type EmulatorKeys = desmume_rs::input::Key;
pub const NO_KEY_SET: u16 = desmume_rs::input::NO_KEY_SET;

thread_local! {
    /// Registered emulator controls.
    static EMULATOR_CONTROLS: RefCell<EmulatorControls> = RefCell::new(Default::default());
}

#[derive(Debug, Clone)]
/// Indices are emulator keys (see Keys), starting with KEY_A.
/// Values are Gdk key codes and SDL joystick codes respectively.
/// NO_KEY_SET is a magic number for no key set (i16::MAX-1)
struct EmulatorControls {
    kbcfg: [i32; 15],
    jscfg: [i32; 15],
}

impl Default for EmulatorControls {
    fn default() -> Self {
        Self {
            kbcfg: [
                120, 122, 65506, 65293, 65363, 65361, 65362, 65364, 119, 113, 115, 97, 112, 111,
                65288,
            ],
            jscfg: [
                513,
                512,
                517,
                520,
                1,
                0,
                2,
                3,
                519,
                518,
                516,
                515,
                NO_KEY_SET as i32,
                NO_KEY_SET as i32,
                514,
            ],
        }
    }
}

#[pyfunction]
/// Clears all pressed keys and buttons.
pub fn emulator_unpress_all_keys() {
    dbg_trace!("emulator_unpress_all_keys");
    command_channel_send(EmulatorCommand::UnpressAllKeys)
}

#[pyfunction]
/// Initializes joystick support, if available, otherwise does nothing.
pub fn emulator_joy_init() {
    dbg_trace!("emulator_joy_init");
    command_channel_blocking_send(EmulatorCommand::JoyInit)
}

fn read_cfg(value: &PySequence) -> PyResult<[i32; 15]> {
    let value_vec = value
        .iter()?
        .map(|v| v.and_then(|vv| vv.extract()))
        .collect::<PyResult<Vec<i32>>>()?;
    value_vec.try_into().map_err(|vv: Vec<i32>| {
        PyValueError::new_err(format!(
            "Controls have invalid length. Must by 15, are {}",
            vv.len()
        ))
    })
}

#[pyfunction]
/// Change the control settings for keyboard and joystick to the values provided.
/// If any of the values is None, the controls are not changed.
pub fn emulator_load_controls(
    keyboard_cfg: Option<&PySequence>,
    joypad_cfg: Option<&PySequence>,
) -> PyResult<()> {
    dbg_trace!("emulator_load_controls");
    EMULATOR_CONTROLS.with(|controls| {
        if let Some(keyboard_cfg) = keyboard_cfg {
            controls.borrow_mut().kbcfg = read_cfg(keyboard_cfg)?;
        }
        if let Some(joypad_cfg) = joypad_cfg {
            controls.borrow_mut().jscfg = read_cfg(joypad_cfg)?;
        }
        command_channel_send(EmulatorCommand::SetJoystickControls(
            controls.borrow().jscfg,
        ));
        Ok(())
    })
}

#[pyfunction]
/// Returns the currently active keyboard configuration.
pub fn emulator_get_kbcfg(py: Python) -> PyObject {
    dbg_trace!("emulator_get_kbcfg");
    EMULATOR_CONTROLS.with(|controls| controls.borrow().kbcfg.into_py(py))
}

#[pyfunction]
/// Returns the currently active joystick configuration.
pub fn emulator_get_jscfg(py: Python) -> PyObject {
    dbg_trace!("emulator_get_jscfg");
    EMULATOR_CONTROLS.with(|controls| controls.borrow().jscfg.into_py(py))
}

#[pyfunction]
/// Sets the currently active keyboard configuration.
pub fn emulator_set_kbcfg(value: &PySequence) -> PyResult<()> {
    dbg_trace!("emulator_set_kbcfg");
    EMULATOR_CONTROLS.with(|controls| {
        controls.borrow_mut().kbcfg = read_cfg(value)?;
        Ok(())
    })
}

#[pyfunction]
/// Sets the currently active joystick configuration.
///
/// NOTE: If `propagate_to_emulator` is false, this does NOT forward the information to the
/// emulator's internals that control the joystick/gamepad.
/// Useful when also using emulator_joy_get_set_key.
pub fn emulator_set_jscfg(value: &PySequence, propagate_to_emulator: bool) -> PyResult<()> {
    dbg_trace!("emulator_set_jscfg");
    EMULATOR_CONTROLS.with(|controls| {
        controls.borrow_mut().jscfg = read_cfg(value)?;
        if propagate_to_emulator {
            command_channel_send(EmulatorCommand::SetJoystickControls(
                controls.borrow().jscfg,
            ));
        }
        Ok(())
    })
}

#[pyfunction]
/// Returns the keymask for key `k`. `k` is a constant of `EmulatorKeys`.
pub fn emulator_keymask(key: u32) -> PyResult<u16> {
    dbg_trace!("emulator_keymask");
    let key = match key {
        0 => EmulatorKeys::None,
        1 => EmulatorKeys::A,
        2 => EmulatorKeys::B,
        3 => EmulatorKeys::Select,
        4 => EmulatorKeys::Start,
        5 => EmulatorKeys::Right,
        6 => EmulatorKeys::Left,
        7 => EmulatorKeys::Up,
        8 => EmulatorKeys::Down,
        9 => EmulatorKeys::R,
        10 => EmulatorKeys::L,
        11 => EmulatorKeys::X,
        12 => EmulatorKeys::Y,
        13 => EmulatorKeys::Debug,
        14 => EmulatorKeys::Boost,
        15 => EmulatorKeys::Lid,
        v => return Err(PyValueError::new_err(format!("Unknown key ID: {v}"))),
    };
    Ok(keymask(key))
}

#[pyfunction]
/// Add a key to the keypad.
pub fn emulator_keypad_add_key(keymask: u16) {
    dbg_trace!("emulator_keypad_add_key");
    command_channel_send(EmulatorCommand::KeypadAddKey(keymask));
}

#[pyfunction]
/// Remove a key from the keypad.
pub fn emulator_keypad_rm_key(keymask: u16) {
    dbg_trace!("emulator_keypad_rm_key");
    command_channel_send(EmulatorCommand::KeypadRmKey(keymask));
}

#[pyfunction]
/// Touch and hold a point on the touchscreen.
pub fn emulator_touch_set_pos(pos_x: u16, pos_y: u16) {
    dbg_trace!("emulator_touch_set_pos");
    command_channel_send(EmulatorCommand::TouchSetPos(pos_x, pos_y));
}

#[pyfunction]
/// Release the touchscreen.
pub fn emulator_touch_release() {
    dbg_trace!("emulator_touch_release");
    command_channel_send(EmulatorCommand::TouchRelease);
}

#[pyfunction]
/// Returns whether the emulator supports joysticks.
pub fn emulator_supports_joystick() -> bool {
    dbg_trace!("emulator_supports_joystick");
    EMULATOR_JOYSTICK_SUPPORTS.load(Ordering::Acquire)
}

#[pyfunction]
/// Returns the number of connected joysticks to the passed callback.
/// The callback is called eventually when the emulator is polled (`emulator_poll`).
pub fn emulator_get_joy_number_connected(cb: PyObject) {
    dbg_trace!("emulator_get_joy_number_connected");
    command_channel_send(EmulatorCommand::JoyGetNumberConnected(
        JoyGetNumberConnectedCallback(cb),
    ));
}

#[pyfunction]
/// Pause the thread and wait for the user to press a button.
/// This button will be assigned to the specified emulator key. Joysticks must be initialized.
/// This does not update the internal joystick control map. Collect set keys and after
/// all changes use `emulator_set_jscfg`.
/// The callback is called eventually when the emulator is polled (`emulator_poll`).
pub fn emulator_joy_get_set_key(key: u16, cb: PyObject) {
    dbg_trace!("emulator_joy_get_set_key - {key}");
    command_channel_send(EmulatorCommand::JoyGetSetKey(key, JoyGetSetKeyCallback(cb)));
}

#[pyfunction]
/// Returns the internal names of keys, indexed by key ID.
pub fn emulator_get_key_names() -> [&'static str; 15] {
    [
        "A", "B", "Select", "Start", "Right", "Left", "Up", "Down", "R", "L", "X", "Y", "Debug",
        "Boost", "Lid",
    ]
}
