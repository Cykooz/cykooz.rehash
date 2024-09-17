use pyo3::prelude::*;

mod hasher;

/// This module is a python module implemented in Rust.
#[pymodule]
fn rust_lib(_py: Python, m: &Bound<PyModule>) -> PyResult<()> {
    m.add_class::<hasher::Sha1>()?;
    Ok(())
}
