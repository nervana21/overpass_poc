// ./src/state/coordinator.rs

use plonky2::hash::hash_types::HashOut;
use crate::state::wallet_state::WalletState;
use crate::state::global_state::GlobalState;
use crate::error::client_errors::{SystemError, SystemErrorType};
use crate::circuit::CircuitManager;
use crate::state::channel_state::ChannelState;

pub struct StateCoordinator {
    pub circuit_manager: CircuitManager,
    pub global_state: GlobalState,
    pub wallet_state: WalletState,
    pub channel_state: Option<ChannelState>,
}

impl StateCoordinator {
    pub fn new(initial_balance: u64) -> Result<Self, SystemError> {
        Ok(Self {
            circuit_manager: CircuitManager::new(initial_balance)?,
            global_state: GlobalState::new(),
            wallet_state: WalletState { balance: initial_balance, nonce: 0, merkle_root: todo!(), proof: todo!() },
            channel_state: None,
        })
    }

    pub async fn update_wallet_state(
        &mut self,
        amount: u64,
    ) -> Result<(), SystemError> {
        let next_state = WalletState {
            balance: self.wallet_state.balance.checked_add(amount).ok_or_else(|| SystemError::new(
                SystemErrorType::StateUpdateError,
                "Balance overflow".to_string(),
            ))?,
            nonce: self.wallet_state.nonce + 1,
            merkle_root: todo!(),
            proof: todo!(),
        };

        // Generate proof for wallet state transition
        let proof = self.circuit_manager.wallet_circuit.prove().map_err(|e| SystemError::new(
            SystemErrorType::ProofGenerationError,
            format!("Failed to generate wallet state transition proof: {}", e),
        ))?;

        // Public inputs for verification
        let _public_inputs = vec![
            self.wallet_state.balance,
            next_state.balance,
            self.wallet_state.nonce,
            next_state.nonce,
        ];

        if !self.circuit_manager.wallet_circuit.verify(&proof).map_err(|e| SystemError::new(
            SystemErrorType::VerificationError,
            format!("Wallet state transition proof verification failed: {}", e),
        ))? {
            return Err(SystemError::new(
                SystemErrorType::VerificationError,
                "Wallet state transition proof verification failed".to_string(),
            ));
        }

        self.wallet_state = next_state;
        Ok(())
    }   

    pub async fn update_channel_state(
        &mut self,
        from: usize,
        to: usize,
        amount: u64,
    ) -> Result<(), SystemError> {
        let channel_state = self.channel_state.as_mut().ok_or_else(|| SystemError::new(
            SystemErrorType::StateUpdateError,
            "Channel state not initialized".to_string(),
        ))?;

        let next_state = ChannelState {
            balances: {
                let mut new_balances = channel_state.balances;
                new_balances[from] = new_balances[from].checked_sub(amount).ok_or_else(|| SystemError::new(
                    SystemErrorType::StateUpdateError,
                    "Insufficient balance for transfer".to_string(),
                ))?;
                new_balances[to] = new_balances[to].checked_add(amount).ok_or_else(|| SystemError::new(
                    SystemErrorType::StateUpdateError,
                    "Balance overflow".to_string(),
                ))?;
                new_balances
            },
            nonce: channel_state.nonce + 1,
            merkle_root: HashOut::ZERO,
            proof: None,
        };

        // Generate proof for channel state transition
        let proof = self.circuit_manager.bridge_circuit.prove().map_err(|e| SystemError::new(
            SystemErrorType::ProofGenerationError,
            format!("Failed to generate channel state transition proof: {}", e),
        ))?;

        // Public inputs for verification
        let mut public_inputs = vec![
            from as u64,
            to as u64,
            amount,
            channel_state.nonce,
            next_state.nonce,
        ];
        public_inputs.extend_from_slice(&channel_state.balances);
        public_inputs.extend_from_slice(&next_state.balances);

        if !self.circuit_manager.bridge_circuit.verify(&proof).map_err(|e| SystemError::new(
            SystemErrorType::VerificationError,
            format!("Channel state transition proof verification failed: {}", e),
        ))? {
            return Err(SystemError::new(
                SystemErrorType::VerificationError,
                "Channel state transition proof verification failed".to_string(),
            ));
        }

        *channel_state = next_state;
        Ok(())
    }
}