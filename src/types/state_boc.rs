use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize};

/// Represents a state init object.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StateInit {
    /// The code of the contract.
    pub code: Option<Vec<u8>>,
    /// The data of the contract.
    pub data: Option<Vec<u8>>,
    /// The library of the contract.
    pub library: Option<Vec<u8>>,
}

// Slice of a cell
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Slice {
    pub start: u64,
    pub end: u64,
}

// Cell type
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CellType {
    Ordinary,
    MerkleProof,
}

// Cell
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Cell {
    pub cell_type: CellType,
    pub data: Vec<u8>,
    pub references: Vec<u64>,
    pub slice: Option<Slice>,
}

// State BOC
#[derive(Debug, Clone, PartialEq)]
pub struct StateBOC {
    pub state_cells: Vec<Cell>,
    pub references: Vec<Vec<u8>>,
    pub roots: Vec<Vec<u8>>,
    pub hash: Option<[u8; 32]>,
}

impl StateBOC {
    pub fn new() -> Self {
        StateBOC { state_cells: Vec::new(), references: Vec::new(), roots: Vec::new(), hash: None }
    }

    pub fn add_cell(&mut self, cell: Cell) { self.state_cells.push(cell); }

    pub fn serialize(&self) -> Result<Vec<u8>, anyhow::Error> {
        // Implement serialization logic
        Ok(vec![]) // Placeholder
    }

    pub fn deserialize(_data: &[u8]) -> Result<Self, anyhow::Error> {
        // Implement deserialization logic
        Ok(Self::new()) // Placeholder
    }

    pub fn compute_hash(&self) -> [u8; 32] {
        // Implement hash computation
        [0u8; 32] // Placeholder
    }

    pub fn update_balance(&mut self, _balance: u64) {
        // Update the balance in the state
    }

    pub fn update_balances(&mut self, _balances: &[u64; 2]) {
        // Update balances for multiple participants
    }

    pub fn set_state_cells(&mut self, _cells: Vec<u8>) {
        // Set the state cells
    }
}

impl Default for StateBOC {
    fn default() -> Self { Self::new() }
}

impl Serialize for StateBOC {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("StateBOC", 4)?;
        state.serialize_field("state_cells", &self.state_cells)?;
        state.serialize_field("references", &self.references)?;
        state.serialize_field("roots", &self.roots)?;
        state.serialize_field("hash", &self.hash)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for StateBOC {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct StateBocHelper {
            state_cells: Vec<Cell>,
            references: Vec<Vec<u8>>,
            roots: Vec<Vec<u8>>,
            hash: Option<[u8; 32]>,
        }

        let helper = StateBocHelper::deserialize(deserializer)?;

        Ok(StateBOC {
            state_cells: helper.state_cells,
            references: helper.references,
            roots: helper.roots,
            hash: helper.hash,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_boc_new() {
        let state_boc = StateBOC::new();
        assert!(state_boc.state_cells.is_empty());
        assert!(state_boc.references.is_empty());
        assert!(state_boc.roots.is_empty());
        assert!(state_boc.hash.is_none());
    }

    #[test]
    fn test_state_boc_builder() {
        let state_cells = vec![Cell {
            cell_type: CellType::Ordinary,
            data: vec![1, 2, 3],
            references: vec![],
            slice: None,
        }];
        let references = vec![vec![4, 5, 6]];
        let roots = vec![vec![7, 8, 9]];
        let hash = [0u8; 32];

        let state_boc = StateBOC {
            state_cells: state_cells.clone(),
            references: references.clone(),
            roots: roots.clone(),
            hash: Some(hash),
        };

        assert_eq!(state_boc.state_cells, state_cells);
        assert_eq!(state_boc.references, references);
        assert_eq!(state_boc.roots, roots);
        assert_eq!(state_boc.hash, Some(hash));
    }
}
