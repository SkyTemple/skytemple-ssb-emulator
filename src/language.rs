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
use crate::state::{command_channel_send, EmulatorCommand};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

#[pyclass(module = "ssb_emulator")]
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
/// Type of memory allocation.
pub enum Language {
    Japanese = 0,
    English = 1,
    French = 2,
    German = 3,
    Italian = 4,
    Spanish = 5,
}

#[pymethods]
impl Language {
    #[new]
    pub fn new(value: u32) -> PyResult<Self> {
        match value {
            0 => Ok(Self::Japanese),
            1 => Ok(Self::English),
            2 => Ok(Self::French),
            3 => Ok(Self::German),
            4 => Ok(Self::Italian),
            5 => Ok(Self::Spanish),
            _ => Err(PyValueError::new_err("Invalid Language ID.")),
        }
    }

    #[getter]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Japanese => "Japanese",
            Self::English => "English",
            Self::French => "French",
            Self::German => "German",
            Self::Italian => "Italian",
            Self::Spanish => "Spanish",
        }
    }

    #[getter]
    pub fn value(&self) -> u32 {
        *self as u32
    }
}

impl From<Language> for desmume_rs::Language {
    fn from(value: Language) -> Self {
        match value {
            Language::Japanese => desmume_rs::Language::Japanese,
            Language::English => desmume_rs::Language::English,
            Language::French => desmume_rs::Language::French,
            Language::German => desmume_rs::Language::German,
            Language::Italian => desmume_rs::Language::Italian,
            Language::Spanish => desmume_rs::Language::Spanish,
        }
    }
}

#[pyfunction]
/// Set firmware language.
pub fn emulator_set_language(lang: Language) {
    dbg_trace!("emulator_set_language");
    command_channel_send(EmulatorCommand::SetLanguage(lang))
}
