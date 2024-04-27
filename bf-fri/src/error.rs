use bitcoin::taproot::{
    LeafNode, LeafNodes, NodeInfo, TapTree, TaprootBuilderError, TaprootMerkleBranch,
};

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum BfError {
    TaprootBuilderError(TaprootBuilderError),
    TaprootError,
    TapLeafError,
    TapTreeError,
    EvaluationLeafError,
    ExecuteScriptError,
    InvalidMerkleProof,
}

impl From<TaprootBuilderError> for BfError {
    fn from(error: TaprootBuilderError) -> Self {
        BfError::TaprootBuilderError(error)
    }
}
