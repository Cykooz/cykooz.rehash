use pyo3::prelude::*;
use pyo3::types::PyBytes;

#[pyclass]
pub struct Sha1 {
    sha1: sha1_smol_r::Sha1,
}

#[pymethods]
impl Sha1 {
    #[new]
    #[pyo3(signature = (data = None))]
    fn new(py: Python, data: Option<&[u8]>) -> Self {
        let mut sha1 = sha1_smol_r::Sha1::new();
        if let Some(data) = data {
            py.allow_threads(|| {
                sha1.update(data);
            });
        }
        Self { sha1 }
    }

    #[getter]
    fn digest_size(&self) -> u32 {
        sha1_smol_r::DIGEST_LENGTH as u32
    }

    #[getter]
    fn block_size(&self) -> u32 {
        64
    }

    /// Resets the hash object to it's initial state.
    fn reset(&mut self) {
        self.sha1.reset();
    }

    /// Update hash with input data.
    #[pyo3(signature = (data))]
    fn update(&mut self, py: Python, data: &[u8]) {
        py.allow_threads(move || {
            self.sha1.update(data);
        });
    }

    /// Retrieve digest result.
    fn digest(&self, py: Python) -> PyObject {
        let digest = self.sha1.digest().bytes();
        PyBytes::new_bound(py, &digest).into()
    }

    /// Retrieve digest result as string in hex-format.
    fn hexdigest(&self) -> String {
        self.sha1.hexdigest()
    }

    /// Serialize of hasher state.
    fn serialize(&self, py: Python) -> PyResult<PyObject> {
        let state_size = self.sha1.state_size();
        PyBytes::new_bound_with(py, state_size, |buffer| {
            self.sha1.serialize(buffer);
            Ok(())
        })
        .map(|bytes| bytes.to_object(py))
    }

    /// Deserialize of hasher from state.
    #[staticmethod]
    fn deserialize(buffer: &[u8]) -> Option<Self> {
        sha1_smol_r::Sha1::deserialize(buffer).map(|sha1| Self { sha1 })
    }
}
