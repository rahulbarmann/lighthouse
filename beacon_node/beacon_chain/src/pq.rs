use crate::chain_config::PqProverConfig;
use pq_prover::{ProverBackend, ReferenceBackend};
use prover_scheduler::ProverScheduler;
use std::sync::Arc;
use types::EthSpec;

pub(crate) mod attestation_preparation;
pub(crate) mod duties;
pub(crate) mod measurement;
pub(crate) mod prover_scheduler;
pub(crate) mod signature_pool;

pub(crate) struct Provers<E: EthSpec> {
    pub(crate) aggregate: Arc<dyn ProverBackend>,
    pub(crate) block: Arc<dyn ProverBackend>,
    pub(crate) scheduler: Arc<ProverScheduler<E>>,
    local_duties: duties::LocalDuties,
}

impl<E: EthSpec> Provers<E> {
    pub(crate) fn connect(config: &PqProverConfig) -> Result<Self, String> {
        match config {
            PqProverConfig::Reference => Ok(Self {
                aggregate: Arc::new(ReferenceBackend),
                block: Arc::new(ReferenceBackend),
                scheduler: Arc::default(),
                local_duties: duties::LocalDuties::default(),
            }),
            PqProverConfig::InProcess { threads } => {
                use pq_prover::{InProcessBackend, InProcessConfig};

                let backend = InProcessBackend::new(InProcessConfig {
                    threads: *threads,
                    ..InProcessConfig::default()
                })
                .map_err(|error| format!("Unable to start the PQ prover: {error:?}"))?;
                // One backend serves gossip and blocks: leanVM verifies without waiting for
                // proofs in progress.
                let backend: Arc<dyn ProverBackend> = Arc::new(backend);
                Ok(Self {
                    aggregate: backend.clone(),
                    block: backend,
                    scheduler: Arc::default(),
                    local_duties: duties::LocalDuties::default(),
                })
            }
        }
    }
}
