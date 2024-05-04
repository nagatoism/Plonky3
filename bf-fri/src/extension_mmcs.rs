use alloc::vec::Vec;
use core::marker::PhantomData;

use p3_field::{AbstractExtensionField, ExtensionField, Field};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::{Dimensions, Matrix, MatrixRows};

use crate::{DirectMmcs, Mmcs};

#[derive(Clone)]
pub struct ExtensionMmcs<F, EF, InnerMmcs> {
    inner: InnerMmcs,
    _phantom: PhantomData<(F, EF)>,
}


