use anyhow::{anyhow, Context, Result};
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    hash::{
        hash_types::{HashOut, HashOutTarget},
        poseidon::PoseidonHash,
    },
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{Hasher, PoseidonGoldilocksConfig},
        proof::ProofWithPublicInputs,
    },
};
use plonky2_field::types::{Field, PrimeField64};

type C = PoseidonGoldilocksConfig;

pub struct StateTransitionCircuit {
    circuit_data: CircuitData<GoldilocksField, C, 2>,
    current_state_target: HashOutTarget,
    next_state_target: HashOutTarget,
    transition_data_target: HashOutTarget,
}

impl StateTransitionCircuit {
    pub fn new() -> Self {
        let config = CircuitConfig::standard_recursion_zk_config();
        let mut builder = CircuitBuilder::<GoldilocksField, 2>::new(config);

        let current_state_target = builder.add_virtual_hash();
        let transition_data_target = builder.add_virtual_hash();
        let next_state_target = builder.add_virtual_hash();

        builder.register_public_inputs(&current_state_target.elements);
        builder.register_public_inputs(&next_state_target.elements);
        
        let inputs = current_state_target.elements.iter()
            .zip(transition_data_target.elements.iter())
            .flat_map(|(&c, &t)| vec![c, t])
            .collect::<Vec<_>>();
            
        let computed_next_state = builder.hash_n_to_hash_no_pad::<PoseidonHash>(inputs);

        for i in 0..4 {
            builder.connect(computed_next_state.elements[i], next_state_target.elements[i]);
        }

        let circuit_data = builder.build::<C>();

        Self {
            circuit_data,
            current_state_target,
            next_state_target,
            transition_data_target,
        }
    }

    pub fn generate_proof(
        &self,
        current_state: [u8; 32],
        next_state: [u8; 32],
        transition_data: [u8; 32],
    ) -> Result<ProofWithPublicInputs<GoldilocksField, C, 2>> {
        let mut pw = PartialWitness::new();

        let current_hash = Self::to_hash_out(current_state)?;
        let transition_hash = Self::to_hash_out(transition_data)?;
        let next_hash = Self::to_hash_out(next_state)?;

        pw.set_hash_target(self.current_state_target, current_hash)?;
        pw.set_hash_target(self.transition_data_target, transition_hash)?;
        pw.set_hash_target(self.next_state_target, next_hash)?;

        self.circuit_data
            .prove(pw)
            .map_err(|e| anyhow!("Proof generation failed: {}", e))
    }

    pub fn verify_proof(
        &self,
        proof: ProofWithPublicInputs<GoldilocksField, C, 2>,
    ) -> Result<bool> {
        self.circuit_data
            .verify(proof)
            .map(|_| true)
            .context("Proof verification failed")
    }

    pub fn to_hash_out(data: [u8; 32]) -> Result<HashOut<GoldilocksField>> {
        let mut elements = Vec::with_capacity(4);
        for chunk in data.chunks(8) {
            let bytes: [u8; 8] = chunk.try_into()
                .map_err(|_| anyhow!("Invalid byte length"))?;
            elements.push(GoldilocksField::from_canonical_u64(
                u64::from_le_bytes(bytes)
            ));
        }
        Ok(HashOut::from_partial(&elements))
    }

    pub fn hash_out_to_bytes(hash: &HashOut<GoldilocksField>) -> Result<[u8; 32]> {
        let mut bytes = [0u8; 32];
        for (i, &element) in hash.elements.iter().enumerate() {
            let element_bytes = element.to_canonical_u64().to_le_bytes();
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&element_bytes);
        }
        Ok(bytes)
    }

    pub fn compute_poseidon_hash(
        current_state: &HashOut<GoldilocksField>,
        transition_data: &HashOut<GoldilocksField>,
    ) -> HashOut<GoldilocksField> {
        let mut inputs = Vec::new();
        for i in 0..4 {
            inputs.push(current_state.elements[i]);
            inputs.push(transition_data.elements[i]);
        }
        PoseidonHash::hash_no_pad(&inputs)
    }

    pub fn compute_next_state(current_state: [u8; 32], transition_data: [u8; 32]) -> Result<[u8; 32]> {
        let current_hash = Self::to_hash_out(current_state)?;
        let transition_hash = Self::to_hash_out(transition_data)?;
        let next_hash = Self::compute_poseidon_hash(&current_hash, &transition_hash);
        Self::hash_out_to_bytes(&next_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    #[test]
    fn test_state_transition_circuit() -> Result<()> {
        let circuit = StateTransitionCircuit::new();
        let current_state = [1u8; 32];
        let transition_data = [2u8; 32];
        let next_state = StateTransitionCircuit::compute_next_state(current_state, transition_data)?;

        let proof = circuit.generate_proof(
            current_state,
            next_state,
            transition_data
        )?;

        assert!(circuit.verify_proof(proof)?);
        Ok(())
    }

    #[test]
    fn test_invalid_inputs() -> Result<()> {
        let circuit = StateTransitionCircuit::new();

        let current_state = [0u8; 32];
        let transition_data = [0u8; 32];
        let next_state = StateTransitionCircuit::compute_next_state(current_state, transition_data)?;

        let result = circuit.generate_proof(
            current_state,
            next_state,
            transition_data
        );
        assert!(result.is_ok());
        Ok(())
    }

    #[test]
    fn test_random_states() -> Result<()> {
        let circuit = StateTransitionCircuit::new();
        let mut rng = rand::thread_rng();
        
        let current_state: [u8; 32] = rng.gen();
        let transition_data: [u8; 32] = rng.gen();
        let next_state = StateTransitionCircuit::compute_next_state(current_state, transition_data)?;

        let proof = circuit.generate_proof(
            current_state,
            next_state,
            transition_data
        )?;

        assert!(circuit.verify_proof(proof)?);
        Ok(())
    }

    #[test]
    fn test_invalid_proof() -> Result<()> {
        let circuit = StateTransitionCircuit::new();
        let current_state = [1u8; 32];
        let transition_data = [2u8; 32];
        let next_state = StateTransitionCircuit::compute_next_state(current_state, transition_data)?;

        let mut proof = circuit.generate_proof(
            current_state,
            next_state,
            transition_data
        )?;

        for i in 0..4 {
            proof.public_inputs[i + 4] = GoldilocksField::ZERO;
        }

        assert!(circuit.verify_proof(proof).is_err());
        Ok(())
    }
}