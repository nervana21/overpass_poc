    use plonky2_field::types::Field64;
use plonky2::plonk::config::Hasher;
use plonky2_field::types::PrimeField64;
use plonky2::iop::witness::WitnessWrite;
use anyhow::{anyhow, Result};
    use plonky2::plonk::circuit_data::CircuitData;
    use plonky2_field::goldilocks_field::GoldilocksField;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    use plonky2::hash::hash_types::HashOutTarget;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::hash::poseidon::PoseidonHash;
    use plonky2::plonk::proof::ProofWithPublicInputs;
    use plonky2::iop::witness::PartialWitness;
    use plonky2::hash::hash_types::HashOut;

    pub struct StateTransitionCircuit {
        circuit_data: CircuitData<GoldilocksField, PoseidonGoldilocksConfig, 2>,
        current_state: HashOutTarget,
        next_state: HashOutTarget,
        transition_data: HashOutTarget,
    }

    impl StateTransitionCircuit {
        pub fn new() -> Self {
            let config = CircuitConfig::standard_recursion_config();
            let mut builder = CircuitBuilder::<GoldilocksField, 2>::new(config);

            let current_state = builder.add_virtual_hash();
            builder.register_public_inputs(&current_state.elements);

            let next_state = builder.add_virtual_hash();
            builder.register_public_inputs(&next_state.elements);

            let transition_data = builder.add_virtual_hash();

            let computed_next = builder.hash_n_to_hash_no_pad::<PoseidonHash>(
                vec![
                    current_state.elements[0],
                    transition_data.elements[0],
                    current_state.elements[1],
                    transition_data.elements[1],
                    current_state.elements[2],
                    transition_data.elements[2],
                    current_state.elements[3],
                    transition_data.elements[3],
                ],
            );

            for i in 0..4 {
                builder.connect(computed_next.elements[i], next_state.elements[i]);
            }

            let circuit_data = builder.build::<PoseidonGoldilocksConfig>();

            Self {
                circuit_data,
                current_state,
                next_state,
                transition_data,
            }
        }

        pub fn generate_proof(
            &self,
            current: [u8; 32],
            next: [u8; 32],
            transition: [u8; 32],
        ) -> Result<ProofWithPublicInputs<GoldilocksField, PoseidonGoldilocksConfig, 2>> {
            let mut pw = PartialWitness::new();

            pw.set_hash_target(self.current_state, Self::to_hash_out(current)?);
            pw.set_hash_target(self.next_state, Self::to_hash_out(next)?);
            pw.set_hash_target(self.transition_data, Self::to_hash_out(transition)?);

            self.circuit_data
                .prove(pw)
                .map_err(|e| anyhow!("Proof generation failed: {}", e))
        }

        pub fn verify_proof(
            &self,
            proof: ProofWithPublicInputs<GoldilocksField, PoseidonGoldilocksConfig, 2>,
        ) -> Result<bool> {
            self.circuit_data
                .verify(proof)
                .map(|_| true)
                .map_err(|e| anyhow!("Proof verification failed: {}", e))
        }

        fn to_hash_out(data: [u8; 32]) -> Result<HashOut<GoldilocksField>> {
            data.chunks(8)
                .map(|chunk| {
                    let bytes: [u8; 8] = chunk.try_into()
                        .map_err(|_| anyhow!("Invalid chunk length"))?;
                    Ok(GoldilocksField::from_canonical_i64(u64::from_le_bytes(bytes).try_into().unwrap()))
                })
                .collect::<Result<Vec<_>>>()
                .map(|fields| HashOut::from_partial(&fields))
        }

        fn hash_out_to_bytes(hash: &HashOut<GoldilocksField>) -> [u8; 32] {
            let mut bytes = [0u8; 32];
            for (i, field_elem) in hash.elements.iter().enumerate() {
                bytes[i * 8..(i + 1) * 8]
                    .copy_from_slice(&field_elem.to_canonical_u64().to_le_bytes());
            }
            bytes
        }

        fn compute_poseidon_hash(
            current_state: &HashOut<GoldilocksField>,
            transition_data: &HashOut<GoldilocksField>,
        ) -> HashOut<GoldilocksField> {
            let mut input = Vec::new();
            input.push(current_state.elements[0]);
            input.push(transition_data.elements[0]);
            input.push(current_state.elements[1]);
            input.push(transition_data.elements[1]);
            input.push(current_state.elements[2]);
            input.push(transition_data.elements[2]);
            input.push(current_state.elements[3]);
            input.push(transition_data.elements[3]);
            PoseidonHash::hash_no_pad(&input)
        }
    }
