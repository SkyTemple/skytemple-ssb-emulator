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

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use std::borrow::Cow;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct StBytes<'a>(pub(crate) Cow<'a, [u8]>);

/// Export as bytes
impl<'a> IntoPy<PyObject> for StBytes<'a> {
    fn into_py(self, py: Python) -> PyObject {
        PyBytes::new(py, self.0.as_ref()).into()
    }
}
