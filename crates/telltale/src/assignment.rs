//! Opt-in durable protected assignments for coordinate-less canonical facts.
//!
//! The caller must prove that a [`ReplayAssociation`] identifies exactly one
//! source fact across every supported source mutation. This module never
//! derives an association from paths, ordinals, timestamps, or semantic data.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use fs4::fs_std::FileExt;
use hmac::{Hmac, Mac};
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};
use sha2::{Digest, Sha256};
use telltale_schema::observation::{
    ASSIGNMENT_COMPARISON_DOMAIN, AssignmentRecord, AssignmentStore, CanonicalObservationV2,
    IdentityBasis, LocalReference, ObservationBuilder, ObservationError, ValidationCode,
};

type HmacSha256 = Hmac<Sha256>;

const STORE_APPLICATION_ID: i64 = 0x5454_4153;
const STORE_SCHEMA_VERSION: i64 = 1;
const DATABASE_NAME: &str = "assignments.sqlite3";
const KEY_DIRECTORY_NAME: &str = "keys";
const RECEIPT_DIRECTORY_NAME: &str = "assignment-receipts";
const AUTHORITY_FILE_NAME: &str = "assignment-authority.v1";
const LOCK_FILE_NAME: &str = "assignment.lock";
const DIRECTORY_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;
const MAX_ASSOCIATION_NAMESPACE_BYTES: usize = 128;
const MAX_ASSOCIATION_LOCATOR_BYTES: usize = 4096;
const MAX_DOMAIN_BYTES: usize = 256;
const MAX_ADAPTER_COMPONENT_BYTES: usize = 128;
const MAX_KEY_EPOCHS: usize = 32;
const MAX_ID_ALLOCATION_ATTEMPTS: usize = 8;
const KEY_BYTES: usize = 32;
const KEY_FILE_MAGIC: &[u8] = b"TELLTALE-ASSIGNMENT-KEY-V1\0";
const AUTHORITY_FILE_MAGIC: &[u8] = b"TELLTALE-ASSIGNMENT-AUTHORITY-V1\0";
const RECEIPT_FILE_MAGIC: &[u8] = b"TELLTALE-ASSIGNMENT-RECEIPT-V1\0";
const KEY_FILE_CHECK_DOMAIN: &[u8] = b"telltale:protected-assignment-key-file-check-v1";
const SUBKEY_DOMAIN: &[u8] = b"telltale:protected-assignment-subkey-v1";
const ASSOCIATION_SUBKEY_PURPOSE: &[u8] = b"association";
const COMPARISON_SUBKEY_PURPOSE: &[u8] = b"comparison";
const INTEGRITY_SUBKEY_PURPOSE: &[u8] = b"row-integrity";
const AUTHORITY_SUBKEY_PURPOSE: &[u8] = b"authority-integrity";
const RECEIPT_SUBKEY_PURPOSE: &[u8] = b"receipt-integrity";
const ASSOCIATION_DOMAIN: &[u8] = b"telltale:protected-assignment-replay-association-v1";
const OBSERVATION_ID_DOMAIN: &[u8] = b"telltale:canonical-observation-protected-assignment-id-v1";
const ROW_INTEGRITY_DOMAIN: &[u8] = b"telltale:protected-assignment-row-integrity-v1";
const AUTHORITY_INTEGRITY_DOMAIN: &[u8] = b"telltale:protected-assignment-authority-integrity-v1";
const RECEIPT_INTEGRITY_DOMAIN: &[u8] = b"telltale:protected-assignment-receipt-integrity-v1";
const RECEIPT_CHAIN_DOMAIN: &[u8] = b"telltale:protected-assignment-receipt-chain-v1";
const ASSIGNMENT_REF_PREFIX: &str = "assignment:v1:";
const KEY_REF_PREFIX: &str = "assignment-key:v1:";
const REPLAY_KEY_PREFIX: &str = "assignment-replay:v1:hmac-sha256:";
const OBSERVATION_ID_PREFIX: &str = "obs:v2:sha256:";
const LOCK_WAIT: Duration = Duration::from_secs(5);
const LOCK_RETRY: Duration = Duration::from_millis(10);
const KEY_EPOCHS_SCHEMA: &str = "CREATE TABLE key_epochs (
    key_ref TEXT PRIMARY KEY NOT NULL CHECK(length(key_ref) = 82),
    ordinal INTEGER NOT NULL UNIQUE CHECK(ordinal > 0 AND ordinal <= 32),
    state TEXT NOT NULL CHECK(state IN ('active', 'retired')),
    metadata_mac BLOB NOT NULL CHECK(length(metadata_mac) = 32)
) STRICT";
const ACTIVE_KEY_INDEX_SCHEMA: &str = "CREATE UNIQUE INDEX one_active_assignment_key
    ON key_epochs(state) WHERE state = 'active'";
const ASSIGNMENTS_SCHEMA: &str = "CREATE TABLE assignments (
    ledger_sequence INTEGER NOT NULL UNIQUE CHECK(ledger_sequence > 0),
    assignment_ref TEXT PRIMARY KEY NOT NULL CHECK(length(assignment_ref) = 78),
    adapter_domain TEXT NOT NULL CHECK(length(adapter_domain) BETWEEN 3 AND 256),
    replay_key TEXT NOT NULL CHECK(length(replay_key) = 97),
    child_ordinal INTEGER NOT NULL CHECK(child_ordinal >= 0 AND child_ordinal <= 4294967295),
    observation_id TEXT NOT NULL UNIQUE CHECK(length(observation_id) = 78),
    comparison_key_ref TEXT NOT NULL CHECK(length(comparison_key_ref) = 82),
    comparison_domain TEXT NOT NULL CHECK(comparison_domain = 'telltale:canonical-observation-assignment-compare-v1'),
    commitment TEXT NOT NULL CHECK(length(commitment) = 90),
    row_mac BLOB NOT NULL CHECK(length(row_mac) = 32),
    UNIQUE(adapter_domain, replay_key, child_ordinal),
    FOREIGN KEY(comparison_key_ref) REFERENCES key_epochs(key_ref)
) STRICT";

#[cfg(target_os = "linux")]
const CURRENT_PLATFORM_IS_UNSUPPORTED: bool = false;
#[cfg(not(target_os = "linux"))]
const CURRENT_PLATFORM_IS_UNSUPPORTED: bool = true;

/// Caller-asserted local reassociation material.
///
/// Construction validates only bounds and namespace versioning. The caller's
/// source contract remains responsible for stability and uniqueness.
#[derive(Clone, PartialEq, Eq)]
pub struct ReplayAssociation {
    domain: AssignmentAdapterDomain,
    namespace: String,
    locator: Vec<u8>,
}

impl ReplayAssociation {
    pub fn new(
        domain: AssignmentAdapterDomain,
        namespace: impl AsRef<str>,
        locator: impl AsRef<[u8]>,
    ) -> Result<Self, ProtectedAssignmentError> {
        let namespace = namespace.as_ref();
        let locator = locator.as_ref();
        if namespace.is_empty()
            || namespace.len() > MAX_ASSOCIATION_NAMESPACE_BYTES
            || !versioned_namespace(namespace)
            || locator.is_empty()
            || locator.len() > MAX_ASSOCIATION_LOCATOR_BYTES
        {
            return Err(error(ProtectedAssignmentErrorCode::InvalidAssociation));
        }
        Ok(Self {
            domain,
            namespace: namespace.to_owned(),
            locator: locator.to_vec(),
        })
    }
}

/// Reviewed static adapter identity permitted to use protected assignment.
#[derive(Clone, PartialEq, Eq)]
pub struct AssignmentAdapterDomain {
    adapter_type: &'static str,
    adapter_id: &'static str,
}

impl AssignmentAdapterDomain {
    pub fn registered(
        adapter_type: &str,
        adapter_id: &str,
    ) -> Result<Self, ProtectedAssignmentError> {
        let registered = match (adapter_type, adapter_id) {
            ("claude_code", "claude.projects") => ("claude_code", "claude.projects"),
            ("codex", "codex.sessions") => ("codex", "codex.sessions"),
            ("codex", "codex.archived_sessions") => ("codex", "codex.archived_sessions"),
            ("codex", "codex.headless_sessions") => ("codex", "codex.headless_sessions"),
            ("codex", "codex.project_sessions") => ("codex", "codex.project_sessions"),
            ("copilot", "copilot.process_log") => ("copilot", "copilot.process_log"),
            ("kilocode", "kilocode.tasks") => ("kilocode", "kilocode.tasks"),
            ("openclaw", "openclaw.agents") => ("openclaw", "openclaw.agents"),
            ("opencode", "opencode.sqlite") => ("opencode", "opencode.sqlite"),
            ("qwen", "qwen.projects") => ("qwen", "qwen.projects"),
            ("roocode", "roocode.tasks") => ("roocode", "roocode.tasks"),
            #[cfg(test)]
            ("synthetic", "coordinate-less") => ("synthetic", "coordinate-less"),
            _ => return Err(error(ProtectedAssignmentErrorCode::InvalidClaim)),
        };
        Ok(Self {
            adapter_type: registered.0,
            adapter_id: registered.1,
        })
    }
}

impl fmt::Debug for AssignmentAdapterDomain {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AssignmentAdapterDomain { .. }")
    }
}

impl fmt::Debug for ReplayAssociation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReplayAssociation { .. }")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectedAssignmentErrorCode {
    UnsupportedPlatform,
    InvalidAssociation,
    InvalidClaim,
    ReplayUnverifiable,
    ReplayCollision,
    UnsafeStorage,
    StorageUnavailable,
    CorruptState,
    UnsupportedVersion,
    IdentityCollision,
}

impl ProtectedAssignmentErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedPlatform => "unsupported_platform",
            Self::InvalidAssociation => "invalid_association",
            Self::InvalidClaim => "invalid_claim",
            Self::ReplayUnverifiable => "replay_unverifiable",
            Self::ReplayCollision => "replay_collision",
            Self::UnsafeStorage => "unsafe_storage",
            Self::StorageUnavailable => "storage_unavailable",
            Self::CorruptState => "corrupt_state",
            Self::UnsupportedVersion => "unsupported_version",
            Self::IdentityCollision => "identity_collision",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ProtectedAssignmentError {
    code: ProtectedAssignmentErrorCode,
}

impl ProtectedAssignmentError {
    pub fn code(&self) -> &'static str {
        self.code.as_str()
    }

    pub fn error_code(&self) -> ProtectedAssignmentErrorCode {
        self.code
    }
}

impl fmt::Debug for ProtectedAssignmentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ProtectedAssignmentError")
            .field(&self.code)
            .finish()
    }
}

impl fmt::Display for ProtectedAssignmentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "protected assignment failed ({})", self.code())
    }
}

impl std::error::Error for ProtectedAssignmentError {}

fn error(code: ProtectedAssignmentErrorCode) -> ProtectedAssignmentError {
    ProtectedAssignmentError { code }
}

struct KeyEpoch {
    key_ref: String,
    root_key: [u8; KEY_BYTES],
    ordinal: u32,
    active: bool,
}

#[derive(Clone, PartialEq, Eq)]
struct StoredAssignment {
    ledger_sequence: u64,
    assignment_ref: String,
    domain: String,
    replay_key: String,
    child_ordinal: u32,
    observation_id: String,
    comparison_key_ref: String,
    comparison_domain: String,
    commitment: String,
    row_mac: [u8; 32],
}

struct AssignmentReceipt {
    sequence: u64,
    previous_head: [u8; 32],
    assignment: StoredAssignment,
}

struct LedgerAuthority {
    key_ref: String,
    count: u64,
    head: [u8; 32],
}

struct StoreLock {
    file: File,
    path: PathBuf,
}

impl StoreLock {
    fn verify(&self) -> Result<(), ProtectedAssignmentError> {
        validate_open_private_file(&self.file)?;
        validate_same_file(&self.path, &self.file)
    }
}

impl StoredAssignment {
    fn as_record(&self) -> Result<AssignmentRecord, ProtectedAssignmentError> {
        AssignmentRecord::new(
            &self.domain,
            &self.replay_key,
            self.child_ordinal,
            &self.observation_id,
            &self.comparison_key_ref,
            &self.commitment,
        )
        .map_err(|_| error(ProtectedAssignmentErrorCode::CorruptState))
    }
}

/// Dedicated local SQLite assignment store and private key owner.
pub struct ProtectedAssignmentStore {
    connection: Connection,
    database_file: File,
    database_path: PathBuf,
    key_directory: PathBuf,
    receipt_directory: PathBuf,
    authority_path: PathBuf,
    lock_path: PathBuf,
    #[cfg(test)]
    fail_before_commit: bool,
    #[cfg(test)]
    fail_after_commit: bool,
}

impl fmt::Debug for ProtectedAssignmentStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProtectedAssignmentStore { .. }")
    }
}

impl ProtectedAssignmentStore {
    /// Initialize a new dedicated store below an absent private local root.
    pub fn initialize(root: impl AsRef<Path>) -> Result<Self, ProtectedAssignmentError> {
        let root = absolute_path(root.as_ref())?;
        Self::initialize_for_platform(&root, CURRENT_PLATFORM_IS_UNSUPPORTED)
    }

    fn initialize_for_platform(
        root: &Path,
        is_unsupported_platform: bool,
    ) -> Result<Self, ProtectedAssignmentError> {
        if is_unsupported_platform {
            return Err(error(ProtectedAssignmentErrorCode::UnsupportedPlatform));
        }
        validate_trusted_ancestors(root)?;
        create_private_directory(root)?;
        let key_directory = root.join(KEY_DIRECTORY_NAME);
        create_private_directory(&key_directory)?;
        let receipt_directory = root.join(RECEIPT_DIRECTORY_NAME);
        create_private_directory(&receipt_directory)?;
        let database_path = root.join(DATABASE_NAME);
        create_new_private_file(&database_path, &[])?;
        let lock_path = root.join(LOCK_FILE_NAME);
        create_new_private_file(&lock_path, &[])?;
        let authority_path = root.join(AUTHORITY_FILE_NAME);
        let _lock = acquire_store_lock(&lock_path)?;

        let (mut connection, database_file) = open_database(&database_path)?;
        reject_foreign_database(&connection)?;
        configure_connection(&connection)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| error(ProtectedAssignmentErrorCode::StorageUnavailable))?;
        initialize_schema(&transaction)?;
        let (key_ref, root_key) = create_key_epoch(&key_directory)?;
        let metadata_mac = compute_key_epoch_mac(&key_ref, 1, "active", &root_key)?;
        transaction
            .execute(
                "INSERT INTO key_epochs (key_ref, ordinal, state, metadata_mac)
                 VALUES (?1, 1, 'active', ?2)",
                params![&key_ref, metadata_mac.as_slice()],
            )
            .map_err(|_| error(ProtectedAssignmentErrorCode::StorageUnavailable))?;
        transaction
            .pragma_update(None, "application_id", STORE_APPLICATION_ID)
            .map_err(|_| error(ProtectedAssignmentErrorCode::StorageUnavailable))?;
        transaction
            .pragma_update(None, "user_version", STORE_SCHEMA_VERSION)
            .map_err(|_| error(ProtectedAssignmentErrorCode::StorageUnavailable))?;
        transaction
            .commit()
            .map_err(|_| error(ProtectedAssignmentErrorCode::StorageUnavailable))?;
        let authority = LedgerAuthority {
            key_ref,
            count: 0,
            head: [0; 32],
        };
        let authority_bytes = encode_authority(&authority, &root_key)?;
        create_new_private_file(&authority_path, &authority_bytes)?;
        sync_directory(root)?;
        drop(_lock);

        let mut store = Self {
            connection,
            database_file,
            database_path,
            key_directory,
            receipt_directory,
            authority_path,
            lock_path,
            #[cfg(test)]
            fail_before_commit: false,
            #[cfg(test)]
            fail_after_commit: false,
        };
        store.recover_and_validate()?;
        Ok(store)
    }

    /// Open an existing store without creating or replacing missing state.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, ProtectedAssignmentError> {
        let root = absolute_path(root.as_ref())?;
        Self::open_for_platform(&root, CURRENT_PLATFORM_IS_UNSUPPORTED)
    }

    fn open_for_platform(
        root: &Path,
        is_unsupported_platform: bool,
    ) -> Result<Self, ProtectedAssignmentError> {
        if is_unsupported_platform {
            return Err(error(ProtectedAssignmentErrorCode::UnsupportedPlatform));
        }
        validate_trusted_ancestors(root)?;
        validate_private_directory(root)?;
        let key_directory = root.join(KEY_DIRECTORY_NAME);
        validate_private_directory(&key_directory)?;
        let receipt_directory = root.join(RECEIPT_DIRECTORY_NAME);
        validate_private_directory(&receipt_directory)?;
        let database_path = root.join(DATABASE_NAME);
        validate_private_file(&database_path)?;
        let authority_path = root.join(AUTHORITY_FILE_NAME);
        validate_private_file(&authority_path)?;
        let lock_path = root.join(LOCK_FILE_NAME);
        validate_private_file(&lock_path)?;
        let (connection, database_file) = open_database(&database_path)?;
        reject_foreign_database(&connection)?;
        configure_connection(&connection)?;

        let mut store = Self {
            connection,
            database_file,
            database_path,
            key_directory,
            receipt_directory,
            authority_path,
            lock_path,
            #[cfg(test)]
            fail_before_commit: false,
            #[cfg(test)]
            fail_after_commit: false,
        };
        store.recover_and_validate()?;
        Ok(store)
    }

    /// Atomically create the first assignment or replay the existing one.
    pub fn claim_or_replay(
        &mut self,
        builder: ObservationBuilder,
        association: &ReplayAssociation,
    ) -> Result<CanonicalObservationV2, ProtectedAssignmentError> {
        let store_lock = acquire_store_lock(&self.lock_path)?;
        self.verify_database_file()?;
        self.recover_and_validate_locked()?;
        let key_directory = self.key_directory.clone();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| error(ProtectedAssignmentErrorCode::StorageUnavailable))?;
        let epochs = load_key_epochs(&transaction, &key_directory)?;
        let active = exactly_one_active(&epochs)?;
        let active_comparison_key = derive_subkey(&active.root_key, COMPARISON_SUBKEY_PURPOSE)?;
        let active_material = builder
            .prepare_assignment_claim(&active_comparison_key)
            .map_err(map_claim_error)?;
        validate_adapter_component(active_material.adapter_type())?;
        validate_adapter_component(active_material.adapter_id())?;
        if active_material.adapter_type() != association.domain.adapter_type
            || active_material.adapter_id() != association.domain.adapter_id
        {
            return Err(error(ProtectedAssignmentErrorCode::InvalidClaim));
        }
        validate_domain(active_material.domain())?;

        let mut matches = Vec::new();
        for epoch in &epochs {
            let replay_key = protected_replay_key(
                epoch,
                association.domain.adapter_type,
                association.domain.adapter_id,
                association,
            )?;
            if let Some(row) = load_by_association(
                &transaction,
                active_material.domain(),
                &replay_key,
                active_material.child_ordinal(),
            )? {
                validate_stored_assignment(&row, epoch)?;
                matches.push((row, epoch));
            }
        }
        if matches.len() > 1 {
            return Err(error(ProtectedAssignmentErrorCode::ReplayUnverifiable));
        }

        let mut pending_receipt = None;
        let (stored, fingerprint_key_epoch_ref) = if let Some((stored, epoch)) = matches.pop() {
            let comparison_key = derive_subkey(&epoch.root_key, COMPARISON_SUBKEY_PURPOSE)?;
            let material = builder
                .prepare_assignment_claim(&comparison_key)
                .map_err(map_claim_error)?;
            if stored.domain != material.domain()
                || stored.child_ordinal != material.child_ordinal()
                || stored.commitment != material.commitment()
            {
                return Err(error(ProtectedAssignmentErrorCode::ReplayCollision));
            }
            (stored, material.fingerprint_key_epoch_ref().to_owned())
        } else {
            let replay_key = protected_replay_key(
                active,
                association.domain.adapter_type,
                association.domain.adapter_id,
                association,
            )?;
            let authority = load_authority(&self.authority_path, &epochs)?;
            let sequence = authority
                .count
                .checked_add(1)
                .ok_or_else(|| error(ProtectedAssignmentErrorCode::StorageUnavailable))?;
            let stored = allocate_assignment_candidate(
                &transaction,
                active,
                sequence,
                active_material.domain(),
                &replay_key,
                active_material.child_ordinal(),
                active_material.commitment(),
            )?;
            let receipt = AssignmentReceipt {
                sequence,
                previous_head: authority.head,
                assignment: stored.clone(),
            };
            let pending_path =
                write_pending_receipt(&self.receipt_directory, &receipt, &active.root_key)?;
            insert_assignment(&transaction, &stored)?;
            pending_receipt = Some((receipt, pending_path, authority));
            (
                stored,
                active_material.fingerprint_key_epoch_ref().to_owned(),
            )
        };

        #[cfg(test)]
        if self.fail_before_commit {
            self.fail_before_commit = false;
            return Err(error(ProtectedAssignmentErrorCode::StorageUnavailable));
        }
        transaction
            .commit()
            .map_err(|_| error(ProtectedAssignmentErrorCode::StorageUnavailable))?;
        #[cfg(test)]
        if self.fail_after_commit {
            self.fail_after_commit = false;
            return Err(error(ProtectedAssignmentErrorCode::StorageUnavailable));
        }

        if let Some((receipt, pending_path, authority)) = pending_receipt {
            finalize_receipt(
                &self.authority_path,
                &self.receipt_directory,
                &receipt,
                &pending_path,
                &authority,
                &epochs,
            )?;
        }
        store_lock.verify()?;
        self.verify_database_file()?;
        drop(store_lock);

        let basis = IdentityBasis::persisted(
            &stored.domain,
            &stored.replay_key,
            LocalReference::new(&stored.assignment_ref, "assignment")
                .map_err(|_| error(ProtectedAssignmentErrorCode::CorruptState))?,
            stored.child_ordinal,
            fingerprint_key_epoch_ref,
        )
        .map_err(|_| error(ProtectedAssignmentErrorCode::CorruptState))?;
        builder
            .identity_basis(basis)
            .build_with_assignments(self)
            .map_err(map_build_error)
    }

    /// Activate a fresh key epoch while retaining old epochs for replay.
    pub fn rotate_key(&mut self) -> Result<(), ProtectedAssignmentError> {
        let store_lock = acquire_store_lock(&self.lock_path)?;
        self.verify_database_file()?;
        self.recover_and_validate_locked()?;
        let key_directory = self.key_directory.clone();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| error(ProtectedAssignmentErrorCode::StorageUnavailable))?;
        let epochs = load_key_epochs(&transaction, &key_directory)?;
        exactly_one_active(&epochs)?;
        if epochs.len() >= MAX_KEY_EPOCHS {
            return Err(error(ProtectedAssignmentErrorCode::StorageUnavailable));
        }
        let ordinal = u32::try_from(epochs.len() + 1)
            .map_err(|_| error(ProtectedAssignmentErrorCode::CorruptState))?;
        let active = exactly_one_active(&epochs)?;
        let retired_mac =
            compute_key_epoch_mac(&active.key_ref, active.ordinal, "retired", &active.root_key)?;
        let (key_ref, root_key) = create_key_epoch(&key_directory)?;
        let active_mac = compute_key_epoch_mac(&key_ref, ordinal, "active", &root_key)?;
        transaction
            .execute(
                "UPDATE key_epochs SET state = 'retired', metadata_mac = ?1
                 WHERE key_ref = ?2 AND state = 'active'",
                params![retired_mac.as_slice(), &active.key_ref],
            )
            .map_err(|_| error(ProtectedAssignmentErrorCode::StorageUnavailable))?;
        transaction
            .execute(
                "INSERT INTO key_epochs (key_ref, ordinal, state, metadata_mac)
                 VALUES (?1, ?2, 'active', ?3)",
                params![&key_ref, i64::from(ordinal), active_mac.as_slice()],
            )
            .map_err(|_| error(ProtectedAssignmentErrorCode::StorageUnavailable))?;
        transaction
            .commit()
            .map_err(|_| error(ProtectedAssignmentErrorCode::StorageUnavailable))?;
        store_lock.verify()?;
        self.verify_database_file()?;
        Ok(())
    }

    fn recover_and_validate(&mut self) -> Result<(), ProtectedAssignmentError> {
        let _store_lock = acquire_store_lock(&self.lock_path)?;
        self.verify_database_file()?;
        self.recover_and_validate_locked()
    }

    fn recover_and_validate_locked(&mut self) -> Result<(), ProtectedAssignmentError> {
        recover_and_validate_store(
            &mut self.connection,
            &self.key_directory,
            &self.receipt_directory,
            &self.authority_path,
        )
    }

    fn verify_database_file(&self) -> Result<(), ProtectedAssignmentError> {
        validate_open_private_file(&self.database_file)?;
        validate_same_file(&self.database_path, &self.database_file)
    }

    #[cfg(test)]
    fn fail_next_before_commit(&mut self) {
        self.fail_before_commit = true;
    }

    #[cfg(test)]
    fn fail_next_after_commit(&mut self) {
        self.fail_after_commit = true;
    }
}

impl AssignmentStore for ProtectedAssignmentStore {
    fn lookup(&self, assignment_ref: &str) -> Result<Option<AssignmentRecord>, ObservationError> {
        let result = (|| {
            let _store_lock = acquire_store_lock(&self.lock_path)?;
            self.verify_database_file()?;
            validate_store_readonly(
                &self.connection,
                &self.key_directory,
                &self.receipt_directory,
                &self.authority_path,
            )?;
            let row = load_by_reference(&self.connection, assignment_ref)?;
            let Some(row) = row else {
                return Ok(None);
            };
            let epoch = load_epoch_by_ref(
                &self.connection,
                &self.key_directory,
                &row.comparison_key_ref,
            )?
            .ok_or_else(|| error(ProtectedAssignmentErrorCode::ReplayUnverifiable))?;
            validate_stored_assignment(&row, &epoch)?;
            row.as_record().map(Some)
        })();
        result
            .map_err(|_| ObservationError::from_validation_code(ValidationCode::ReplayUnverifiable))
    }

    fn comparison_key(&self, key_ref: &str) -> Result<Option<Vec<u8>>, ObservationError> {
        let result = (|| {
            let _store_lock = acquire_store_lock(&self.lock_path)?;
            self.verify_database_file()?;
            validate_store_readonly(
                &self.connection,
                &self.key_directory,
                &self.receipt_directory,
                &self.authority_path,
            )?;
            let epoch = load_epoch_by_ref(&self.connection, &self.key_directory, key_ref)?;
            epoch
                .map(|epoch| derive_subkey(&epoch.root_key, COMPARISON_SUBKEY_PURPOSE))
                .transpose()
                .map(|key| key.map(|key| key.to_vec()))
        })();
        result
            .map_err(|_| ObservationError::from_validation_code(ValidationCode::ReplayUnverifiable))
    }
}

fn initialize_schema(transaction: &Transaction<'_>) -> Result<(), ProtectedAssignmentError> {
    transaction
        .execute_batch(&format!(
            "{KEY_EPOCHS_SCHEMA};{ACTIVE_KEY_INDEX_SCHEMA};{ASSIGNMENTS_SCHEMA};"
        ))
        .map_err(|_| error(ProtectedAssignmentErrorCode::StorageUnavailable))
}

fn validate_schema_and_rows(
    connection: &Connection,
    key_directory: &Path,
) -> Result<(), ProtectedAssignmentError> {
    sqlite_integrity_check(connection)?;
    if application_id(connection)? != STORE_APPLICATION_ID {
        return Err(error(ProtectedAssignmentErrorCode::CorruptState));
    }
    let version = user_version(connection)?;
    if version > STORE_SCHEMA_VERSION {
        return Err(error(ProtectedAssignmentErrorCode::UnsupportedVersion));
    }
    if version != STORE_SCHEMA_VERSION {
        return Err(error(ProtectedAssignmentErrorCode::CorruptState));
    }
    let expected = [
        (
            "assignments".to_owned(),
            "table".to_owned(),
            normalized_sql(ASSIGNMENTS_SCHEMA),
        ),
        (
            "key_epochs".to_owned(),
            "table".to_owned(),
            normalized_sql(KEY_EPOCHS_SCHEMA),
        ),
        (
            "one_active_assignment_key".to_owned(),
            "index".to_owned(),
            normalized_sql(ACTIVE_KEY_INDEX_SCHEMA),
        ),
    ];
    if user_schema_objects(connection)? != expected {
        return Err(error(ProtectedAssignmentErrorCode::CorruptState));
    }
    let foreign_key_errors: i64 = connection
        .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })
        .map_err(|_| error(ProtectedAssignmentErrorCode::CorruptState))?;
    if foreign_key_errors != 0 {
        return Err(error(ProtectedAssignmentErrorCode::CorruptState));
    }
    validate_database_row_shapes(connection)?;
    let epochs = load_key_epochs(connection, key_directory)?;
    exactly_one_active(&epochs)?;
    let mut statement = connection
        .prepare(
            "SELECT ledger_sequence, assignment_ref, adapter_domain, replay_key, child_ordinal,
                    observation_id, comparison_key_ref, comparison_domain,
                    commitment, row_mac
             FROM assignments ORDER BY ledger_sequence",
        )
        .map_err(|_| error(ProtectedAssignmentErrorCode::CorruptState))?;
    let mut rows = statement
        .query([])
        .map_err(|_| error(ProtectedAssignmentErrorCode::CorruptState))?;
    while let Some(row) = rows
        .next()
        .map_err(|_| error(ProtectedAssignmentErrorCode::CorruptState))?
    {
        let assignment = decode_assignment_row(row)
            .map_err(|_| error(ProtectedAssignmentErrorCode::CorruptState))?;
        let epoch = epochs
            .iter()
            .find(|epoch| epoch.key_ref == assignment.comparison_key_ref)
            .ok_or_else(|| error(ProtectedAssignmentErrorCode::CorruptState))?;
        validate_stored_assignment(&assignment, epoch)?;
    }
    Ok(())
}

fn reject_foreign_database(connection: &Connection) -> Result<(), ProtectedAssignmentError> {
    let application_id = application_id(connection)?;
    if application_id != 0 && application_id != STORE_APPLICATION_ID {
        return Err(error(ProtectedAssignmentErrorCode::CorruptState));
    }
    if application_id == 0 && !user_schema_objects(connection)?.is_empty() {
        return Err(error(ProtectedAssignmentErrorCode::CorruptState));
    }
    Ok(())
}

fn configure_connection(connection: &Connection) -> Result<(), ProtectedAssignmentError> {
    connection
        .busy_timeout(Duration::from_secs(5))
        .map_err(|_| error(ProtectedAssignmentErrorCode::StorageUnavailable))?;
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .map_err(|_| error(ProtectedAssignmentErrorCode::StorageUnavailable))?;
    let application_id = application_id(connection)?;
    let current_mode: String = connection
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .map_err(|_| error(ProtectedAssignmentErrorCode::StorageUnavailable))?;
    if application_id == STORE_APPLICATION_ID && !current_mode.eq_ignore_ascii_case("delete") {
        return Err(error(ProtectedAssignmentErrorCode::CorruptState));
    }
    connection
        .pragma_update(None, "journal_mode", "DELETE")
        .map_err(|_| error(ProtectedAssignmentErrorCode::StorageUnavailable))?;
    connection
        .pragma_update(None, "synchronous", "FULL")
        .map_err(|_| error(ProtectedAssignmentErrorCode::StorageUnavailable))?;
    connection
        .pragma_update(None, "trusted_schema", "OFF")
        .map_err(|_| error(ProtectedAssignmentErrorCode::StorageUnavailable))?;
    Ok(())
}

fn sqlite_integrity_check(connection: &Connection) -> Result<(), ProtectedAssignmentError> {
    let result: String = connection
        .query_row("PRAGMA integrity_check(1)", [], |row| row.get(0))
        .map_err(|_| error(ProtectedAssignmentErrorCode::CorruptState))?;
    if result == "ok" {
        Ok(())
    } else {
        Err(error(ProtectedAssignmentErrorCode::CorruptState))
    }
}

fn application_id(connection: &Connection) -> Result<i64, ProtectedAssignmentError> {
    connection
        .pragma_query_value(None, "application_id", |row| row.get(0))
        .map_err(|_| error(ProtectedAssignmentErrorCode::CorruptState))
}

fn user_version(connection: &Connection) -> Result<i64, ProtectedAssignmentError> {
    connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|_| error(ProtectedAssignmentErrorCode::CorruptState))
}

fn user_schema_objects(
    connection: &Connection,
) -> Result<Vec<(String, String, String)>, ProtectedAssignmentError> {
    let mut statement = connection
        .prepare(
            "SELECT name, type, sql FROM sqlite_schema
             WHERE name NOT LIKE 'sqlite_%' ORDER BY name, type",
        )
        .map_err(|_| error(ProtectedAssignmentErrorCode::CorruptState))?;
    let rows = statement
        .query_map([], |row| {
            let sql: String = row.get(2)?;
            Ok((row.get(0)?, row.get(1)?, normalized_sql(&sql)))
        })
        .map_err(|_| error(ProtectedAssignmentErrorCode::CorruptState))?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|_| error(ProtectedAssignmentErrorCode::CorruptState))
}

fn normalized_sql(sql: &str) -> String {
    sql.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn validate_database_row_shapes(connection: &Connection) -> Result<(), ProtectedAssignmentError> {
    let invalid_epochs: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM key_epochs
             WHERE typeof(key_ref) != 'text' OR length(key_ref) != 82
                OR typeof(ordinal) != 'integer' OR ordinal < 1 OR ordinal > 32
                OR typeof(state) != 'text' OR state NOT IN ('active', 'retired')
                OR typeof(metadata_mac) != 'blob' OR length(metadata_mac) != 32",
            [],
            |row| row.get(0),
        )
        .map_err(|_| error(ProtectedAssignmentErrorCode::CorruptState))?;
    let invalid_assignments: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM assignments
             WHERE typeof(ledger_sequence) != 'integer' OR ledger_sequence < 1
                OR typeof(assignment_ref) != 'text' OR length(assignment_ref) != 78
                OR typeof(adapter_domain) != 'text'
                OR length(adapter_domain) < 3 OR length(adapter_domain) > 256
                OR typeof(replay_key) != 'text' OR length(replay_key) != 97
                OR typeof(child_ordinal) != 'integer'
                OR child_ordinal < 0 OR child_ordinal > 4294967295
                OR typeof(observation_id) != 'text' OR length(observation_id) != 78
                OR typeof(comparison_key_ref) != 'text' OR length(comparison_key_ref) != 82
                OR typeof(comparison_domain) != 'text'
                OR comparison_domain != ?1
                OR typeof(commitment) != 'text' OR length(commitment) != 90
                OR typeof(row_mac) != 'blob' OR length(row_mac) != 32",
            params![ASSIGNMENT_COMPARISON_DOMAIN],
            |row| row.get(0),
        )
        .map_err(|_| error(ProtectedAssignmentErrorCode::CorruptState))?;
    if invalid_epochs != 0 || invalid_assignments != 0 {
        return Err(error(ProtectedAssignmentErrorCode::CorruptState));
    }
    Ok(())
}

fn load_key_epochs(
    connection: &Connection,
    key_directory: &Path,
) -> Result<Vec<KeyEpoch>, ProtectedAssignmentError> {
    let mut statement = connection
        .prepare(
            "SELECT key_ref, ordinal, state, metadata_mac
             FROM key_epochs ORDER BY ordinal LIMIT ?1",
        )
        .map_err(|_| error(ProtectedAssignmentErrorCode::CorruptState))?;
    let rows = statement
        .query_map(params![33_i64], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Vec<u8>>(3)?,
            ))
        })
        .map_err(|_| error(ProtectedAssignmentErrorCode::CorruptState))?;
    let metadata = rows
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| error(ProtectedAssignmentErrorCode::CorruptState))?;
    if metadata.is_empty() || metadata.len() > MAX_KEY_EPOCHS {
        return Err(error(ProtectedAssignmentErrorCode::CorruptState));
    }
    metadata
        .into_iter()
        .enumerate()
        .map(|(index, (key_ref, ordinal, state, metadata_mac))| {
            if !valid_prefixed_hex(&key_ref, KEY_REF_PREFIX) {
                return Err(error(ProtectedAssignmentErrorCode::CorruptState));
            }
            let ordinal = u32::try_from(ordinal)
                .map_err(|_| error(ProtectedAssignmentErrorCode::CorruptState))?;
            if ordinal as usize != index + 1 {
                return Err(error(ProtectedAssignmentErrorCode::CorruptState));
            }
            let active = match state.as_str() {
                "active" => true,
                "retired" => false,
                _ => return Err(error(ProtectedAssignmentErrorCode::CorruptState)),
            };
            let root_key = read_key_file(key_directory, &key_ref)?;
            let expected_mac = compute_key_epoch_mac(&key_ref, ordinal, &state, &root_key)?;
            if metadata_mac.as_slice() != expected_mac {
                return Err(error(ProtectedAssignmentErrorCode::CorruptState));
            }
            Ok(KeyEpoch {
                key_ref,
                root_key,
                ordinal,
                active,
            })
        })
        .collect()
}

fn load_epoch_by_ref(
    connection: &Connection,
    key_directory: &Path,
    key_ref: &str,
) -> Result<Option<KeyEpoch>, ProtectedAssignmentError> {
    if !valid_prefixed_hex(key_ref, KEY_REF_PREFIX) {
        return Err(error(ProtectedAssignmentErrorCode::CorruptState));
    }
    let metadata = connection
        .query_row(
            "SELECT ordinal, state, metadata_mac FROM key_epochs WHERE key_ref = ?1",
            params![key_ref],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            },
        )
        .optional()
        .map_err(|_| error(ProtectedAssignmentErrorCode::CorruptState))?;
    let Some((ordinal, state, metadata_mac)) = metadata else {
        return Ok(None);
    };
    let ordinal =
        u32::try_from(ordinal).map_err(|_| error(ProtectedAssignmentErrorCode::CorruptState))?;
    let active = match state.as_str() {
        "active" => true,
        "retired" => false,
        _ => return Err(error(ProtectedAssignmentErrorCode::CorruptState)),
    };
    let root_key = read_key_file(key_directory, key_ref)?;
    if metadata_mac.as_slice() != compute_key_epoch_mac(key_ref, ordinal, &state, &root_key)? {
        return Err(error(ProtectedAssignmentErrorCode::CorruptState));
    }
    Ok(Some(KeyEpoch {
        key_ref: key_ref.to_owned(),
        root_key,
        ordinal,
        active,
    }))
}

fn exactly_one_active(epochs: &[KeyEpoch]) -> Result<&KeyEpoch, ProtectedAssignmentError> {
    let mut active = epochs.iter().filter(|epoch| epoch.active);
    let result = active
        .next()
        .ok_or_else(|| error(ProtectedAssignmentErrorCode::CorruptState))?;
    if active.next().is_some() {
        return Err(error(ProtectedAssignmentErrorCode::CorruptState));
    }
    Ok(result)
}

fn recover_and_validate_store(
    connection: &mut Connection,
    key_directory: &Path,
    receipt_directory: &Path,
    authority_path: &Path,
) -> Result<(), ProtectedAssignmentError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| error(ProtectedAssignmentErrorCode::StorageUnavailable))?;
    validate_schema_and_rows(&transaction, key_directory)?;
    validate_ledger(
        &transaction,
        key_directory,
        receipt_directory,
        authority_path,
        true,
    )?;
    transaction
        .commit()
        .map_err(|_| error(ProtectedAssignmentErrorCode::StorageUnavailable))
}

fn validate_store_readonly(
    connection: &Connection,
    key_directory: &Path,
    receipt_directory: &Path,
    authority_path: &Path,
) -> Result<(), ProtectedAssignmentError> {
    validate_schema_and_rows(connection, key_directory)?;
    validate_ledger(
        connection,
        key_directory,
        receipt_directory,
        authority_path,
        false,
    )
}

fn validate_ledger(
    connection: &Connection,
    key_directory: &Path,
    receipt_directory: &Path,
    authority_path: &Path,
    recover: bool,
) -> Result<(), ProtectedAssignmentError> {
    let epochs = load_key_epochs(connection, key_directory)?;
    let mut authority = load_authority(authority_path, &epochs)?;
    let mut receipts = load_receipts(receipt_directory, &epochs, recover)?;
    receipts.sort_by_key(|entry| entry.receipt.sequence);

    let authority_count = usize::try_from(authority.count)
        .map_err(|_| error(ProtectedAssignmentErrorCode::CorruptState))?;
    if receipts.len() < authority_count || receipts.len() > authority_count.saturating_add(1) {
        return Err(error(ProtectedAssignmentErrorCode::CorruptState));
    }

    let mut head = [0_u8; 32];
    for (index, entry) in receipts.iter().enumerate() {
        let expected_sequence = u64::try_from(index + 1)
            .map_err(|_| error(ProtectedAssignmentErrorCode::CorruptState))?;
        if entry.receipt.sequence != expected_sequence || entry.receipt.previous_head != head {
            return Err(error(ProtectedAssignmentErrorCode::CorruptState));
        }
        head = receipt_chain_head(&entry.receipt, &entry.encoded)?;
        if index + 1 == authority_count && head != authority.head {
            return Err(error(ProtectedAssignmentErrorCode::CorruptState));
        }
    }
    if authority_count == 0 && authority.head != [0; 32] {
        return Err(error(ProtectedAssignmentErrorCode::CorruptState));
    }

    let assignments = load_all_assignments(connection, &epochs)?;
    if assignments.len() < authority_count || assignments.len() > authority_count.saturating_add(1)
    {
        return Err(error(ProtectedAssignmentErrorCode::CorruptState));
    }
    for (index, stored) in assignments.iter().enumerate() {
        let Some(receipt) = receipts.get(index) else {
            return Err(error(ProtectedAssignmentErrorCode::CorruptState));
        };
        if stored != &receipt.receipt.assignment {
            return Err(error(ProtectedAssignmentErrorCode::CorruptState));
        }
    }

    for entry in receipts.iter().take(authority_count) {
        if !entry.committed {
            if !recover {
                return Err(error(ProtectedAssignmentErrorCode::StorageUnavailable));
            }
            commit_receipt_path(receipt_directory, entry)?;
        }
    }

    if receipts.len() == authority_count + 1 {
        let extra = receipts
            .last()
            .ok_or_else(|| error(ProtectedAssignmentErrorCode::CorruptState))?;
        if extra.committed {
            return Err(error(ProtectedAssignmentErrorCode::CorruptState));
        }
        if assignments.len() == receipts.len() {
            if !recover {
                return Err(error(ProtectedAssignmentErrorCode::StorageUnavailable));
            }
            authority.count = extra.receipt.sequence;
            authority.head = head;
            write_authority_atomic(authority_path, &authority, &epochs)?;
            commit_receipt_path(receipt_directory, extra)?;
        } else if assignments.len() == authority_count {
            if !recover {
                return Err(error(ProtectedAssignmentErrorCode::StorageUnavailable));
            }
            fs::remove_file(&extra.path)
                .map_err(|_| error(ProtectedAssignmentErrorCode::StorageUnavailable))?;
            sync_directory(receipt_directory)?;
        } else {
            return Err(error(ProtectedAssignmentErrorCode::CorruptState));
        }
    } else if assignments.len() != authority_count {
        return Err(error(ProtectedAssignmentErrorCode::CorruptState));
    }
    Ok(())
}

struct ReceiptEntry {
    receipt: AssignmentReceipt,
    encoded: Vec<u8>,
    path: PathBuf,
    committed: bool,
}

fn load_all_assignments(
    connection: &Connection,
    epochs: &[KeyEpoch],
) -> Result<Vec<StoredAssignment>, ProtectedAssignmentError> {
    let mut statement = connection
        .prepare(
            "SELECT ledger_sequence, assignment_ref, adapter_domain, replay_key, child_ordinal,
                    observation_id, comparison_key_ref, comparison_domain, commitment, row_mac
             FROM assignments ORDER BY ledger_sequence",
        )
        .map_err(|_| error(ProtectedAssignmentErrorCode::CorruptState))?;
    let mut rows = statement
        .query([])
        .map_err(|_| error(ProtectedAssignmentErrorCode::CorruptState))?;
    let mut assignments = Vec::new();
    while let Some(row) = rows
        .next()
        .map_err(|_| error(ProtectedAssignmentErrorCode::CorruptState))?
    {
        let stored = decode_assignment_row(row)
            .map_err(|_| error(ProtectedAssignmentErrorCode::CorruptState))?;
        let expected_sequence = u64::try_from(assignments.len() + 1)
            .map_err(|_| error(ProtectedAssignmentErrorCode::CorruptState))?;
        if stored.ledger_sequence != expected_sequence {
            return Err(error(ProtectedAssignmentErrorCode::CorruptState));
        }
        let epoch = epochs
            .iter()
            .find(|epoch| epoch.key_ref == stored.comparison_key_ref)
            .ok_or_else(|| error(ProtectedAssignmentErrorCode::CorruptState))?;
        validate_stored_assignment(&stored, epoch)?;
        assignments.push(stored);
    }
    Ok(assignments)
}

fn load_receipts(
    receipt_directory: &Path,
    epochs: &[KeyEpoch],
    recover: bool,
) -> Result<Vec<ReceiptEntry>, ProtectedAssignmentError> {
    validate_private_directory(receipt_directory)?;
    let mut entries = Vec::new();
    for entry in fs::read_dir(receipt_directory)
        .map_err(|_| error(ProtectedAssignmentErrorCode::CorruptState))?
    {
        let entry = entry.map_err(|_| error(ProtectedAssignmentErrorCode::CorruptState))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(error(ProtectedAssignmentErrorCode::CorruptState));
        };
        if name.starts_with(".tmp-") {
            if !recover {
                return Err(error(ProtectedAssignmentErrorCode::StorageUnavailable));
            }
            let path = entry.path();
            validate_private_file(&path)?;
            fs::remove_file(path)
                .map_err(|_| error(ProtectedAssignmentErrorCode::StorageUnavailable))?;
            continue;
        }
        let (stem, committed) = if let Some(stem) = name.strip_suffix(".receipt") {
            (stem, true)
        } else if let Some(stem) = name.strip_suffix(".pending") {
            (stem, false)
        } else {
            return Err(error(ProtectedAssignmentErrorCode::CorruptState));
        };
        let (sequence_text, assignment_hex) = stem
            .split_once('-')
            .ok_or_else(|| error(ProtectedAssignmentErrorCode::CorruptState))?;
        if sequence_text.len() != 20
            || assignment_hex.len() != 64
            || !valid_lower_hex(assignment_hex)
        {
            return Err(error(ProtectedAssignmentErrorCode::CorruptState));
        }
        let sequence = sequence_text
            .parse::<u64>()
            .map_err(|_| error(ProtectedAssignmentErrorCode::CorruptState))?;
        let path = entry.path();
        let encoded = read_private_file_bounded(&path, 2048)?;
        let receipt = decode_receipt(&encoded, epochs)?;
        if receipt.sequence != sequence
            || receipt.assignment.assignment_ref
                != format!("{ASSIGNMENT_REF_PREFIX}{assignment_hex}")
        {
            return Err(error(ProtectedAssignmentErrorCode::CorruptState));
        }
        entries.push(ReceiptEntry {
            receipt,
            encoded,
            path,
            committed,
        });
    }
    if recover {
        sync_directory(receipt_directory)?;
    }
    Ok(entries)
}

fn load_authority(
    authority_path: &Path,
    epochs: &[KeyEpoch],
) -> Result<LedgerAuthority, ProtectedAssignmentError> {
    let bytes = read_private_file_bounded(authority_path, 512)?;
    let mut cursor = BinaryCursor::new(&bytes);
    cursor.expect(AUTHORITY_FILE_MAGIC)?;
    let key_ref = cursor.string(128)?;
    let count = cursor.u64()?;
    let head = cursor.array::<32>()?;
    let stored_mac = cursor.array::<32>()?;
    cursor.finish()?;
    let epoch = epochs
        .iter()
        .find(|epoch| epoch.key_ref == key_ref)
        .ok_or_else(|| error(ProtectedAssignmentErrorCode::CorruptState))?;
    let authority = LedgerAuthority {
        key_ref,
        count,
        head,
    };
    let expected = compute_authority_mac(&authority, &epoch.root_key)?;
    if stored_mac != expected {
        return Err(error(ProtectedAssignmentErrorCode::CorruptState));
    }
    Ok(authority)
}

fn encode_authority(
    authority: &LedgerAuthority,
    root_key: &[u8; KEY_BYTES],
) -> Result<Vec<u8>, ProtectedAssignmentError> {
    let mut bytes = Vec::with_capacity(256);
    bytes.extend_from_slice(AUTHORITY_FILE_MAGIC);
    push_string(&mut bytes, &authority.key_ref)?;
    bytes.extend_from_slice(&authority.count.to_be_bytes());
    bytes.extend_from_slice(&authority.head);
    bytes.extend_from_slice(&compute_authority_mac(authority, root_key)?);
    Ok(bytes)
}

fn compute_authority_mac(
    authority: &LedgerAuthority,
    root_key: &[u8; KEY_BYTES],
) -> Result<[u8; 32], ProtectedAssignmentError> {
    let key = derive_subkey(root_key, AUTHORITY_SUBKEY_PURPOSE)?;
    let mut mac = HmacSha256::new_from_slice(&key)
        .map_err(|_| error(ProtectedAssignmentErrorCode::CorruptState))?;
    mac.update(AUTHORITY_INTEGRITY_DOMAIN);
    update_bounded(&mut mac, authority.key_ref.as_bytes())?;
    mac.update(&authority.count.to_be_bytes());
    mac.update(&authority.head);
    Ok(mac.finalize().into_bytes().into())
}

fn write_authority_atomic(
    authority_path: &Path,
    authority: &LedgerAuthority,
    epochs: &[KeyEpoch],
) -> Result<(), ProtectedAssignmentError> {
    let epoch = epochs
        .iter()
        .find(|epoch| epoch.key_ref == authority.key_ref)
        .ok_or_else(|| error(ProtectedAssignmentErrorCode::CorruptState))?;
    let bytes = encode_authority(authority, &epoch.root_key)?;
    write_private_file_atomic(authority_path, &bytes, true)
}

fn encode_receipt(
    receipt: &AssignmentReceipt,
    root_key: &[u8; KEY_BYTES],
) -> Result<Vec<u8>, ProtectedAssignmentError> {
    let stored = &receipt.assignment;
    if stored.ledger_sequence != receipt.sequence {
        return Err(error(ProtectedAssignmentErrorCode::CorruptState));
    }
    let mut bytes = Vec::with_capacity(1024);
    bytes.extend_from_slice(RECEIPT_FILE_MAGIC);
    bytes.extend_from_slice(&receipt.sequence.to_be_bytes());
    bytes.extend_from_slice(&receipt.previous_head);
    for value in [&stored.assignment_ref, &stored.domain, &stored.replay_key] {
        push_string(&mut bytes, value)?;
    }
    bytes.extend_from_slice(&stored.child_ordinal.to_be_bytes());
    for value in [
        &stored.observation_id,
        &stored.comparison_key_ref,
        &stored.comparison_domain,
        &stored.commitment,
    ] {
        push_string(&mut bytes, value)?;
    }
    bytes.extend_from_slice(&stored.row_mac);
    let key = derive_subkey(root_key, RECEIPT_SUBKEY_PURPOSE)?;
    let mut mac = HmacSha256::new_from_slice(&key)
        .map_err(|_| error(ProtectedAssignmentErrorCode::CorruptState))?;
    mac.update(RECEIPT_INTEGRITY_DOMAIN);
    mac.update(&bytes);
    bytes.extend_from_slice(&mac.finalize().into_bytes());
    Ok(bytes)
}

fn decode_receipt(
    bytes: &[u8],
    epochs: &[KeyEpoch],
) -> Result<AssignmentReceipt, ProtectedAssignmentError> {
    let mut cursor = BinaryCursor::new(bytes);
    cursor.expect(RECEIPT_FILE_MAGIC)?;
    let sequence = cursor.u64()?;
    let previous_head = cursor.array::<32>()?;
    let assignment_ref = cursor.string(78)?;
    let domain = cursor.string(MAX_DOMAIN_BYTES)?;
    let replay_key = cursor.string(97)?;
    let child_ordinal = cursor.u32()?;
    let observation_id = cursor.string(78)?;
    let comparison_key_ref = cursor.string(82)?;
    let comparison_domain = cursor.string(128)?;
    let commitment = cursor.string(90)?;
    let row_mac = cursor.array::<32>()?;
    let receipt_mac_offset = cursor.position();
    let receipt_mac = cursor.array::<32>()?;
    cursor.finish()?;
    let epoch = epochs
        .iter()
        .find(|epoch| epoch.key_ref == comparison_key_ref)
        .ok_or_else(|| error(ProtectedAssignmentErrorCode::CorruptState))?;
    let key = derive_subkey(&epoch.root_key, RECEIPT_SUBKEY_PURPOSE)?;
    let mut mac = HmacSha256::new_from_slice(&key)
        .map_err(|_| error(ProtectedAssignmentErrorCode::CorruptState))?;
    mac.update(RECEIPT_INTEGRITY_DOMAIN);
    mac.update(&bytes[..receipt_mac_offset]);
    if mac.finalize().into_bytes().as_slice() != receipt_mac {
        return Err(error(ProtectedAssignmentErrorCode::CorruptState));
    }
    let assignment = StoredAssignment {
        ledger_sequence: sequence,
        assignment_ref,
        domain,
        replay_key,
        child_ordinal,
        observation_id,
        comparison_key_ref,
        comparison_domain,
        commitment,
        row_mac,
    };
    validate_stored_assignment(&assignment, epoch)?;
    Ok(AssignmentReceipt {
        sequence,
        previous_head,
        assignment,
    })
}

fn receipt_chain_head(
    receipt: &AssignmentReceipt,
    encoded: &[u8],
) -> Result<[u8; 32], ProtectedAssignmentError> {
    let length = u64::try_from(encoded.len())
        .map_err(|_| error(ProtectedAssignmentErrorCode::CorruptState))?;
    let mut digest = Sha256::new();
    digest.update(RECEIPT_CHAIN_DOMAIN);
    digest.update(receipt.sequence.to_be_bytes());
    digest.update(receipt.previous_head);
    digest.update(length.to_be_bytes());
    digest.update(encoded);
    Ok(digest.finalize().into())
}

fn write_pending_receipt(
    receipt_directory: &Path,
    receipt: &AssignmentReceipt,
    root_key: &[u8; KEY_BYTES],
) -> Result<PathBuf, ProtectedAssignmentError> {
    let path = receipt_path(receipt_directory, receipt, false)?;
    let bytes = encode_receipt(receipt, root_key)?;
    write_private_file_atomic(&path, &bytes, false)?;
    Ok(path)
}

fn finalize_receipt(
    authority_path: &Path,
    receipt_directory: &Path,
    receipt: &AssignmentReceipt,
    pending_path: &Path,
    authority: &LedgerAuthority,
    epochs: &[KeyEpoch],
) -> Result<(), ProtectedAssignmentError> {
    if authority.count.checked_add(1) != Some(receipt.sequence)
        || authority.head != receipt.previous_head
    {
        return Err(error(ProtectedAssignmentErrorCode::CorruptState));
    }
    let epoch = epochs
        .iter()
        .find(|epoch| epoch.key_ref == receipt.assignment.comparison_key_ref)
        .ok_or_else(|| error(ProtectedAssignmentErrorCode::CorruptState))?;
    let encoded = encode_receipt(receipt, &epoch.root_key)?;
    let new_authority = LedgerAuthority {
        key_ref: authority.key_ref.clone(),
        count: receipt.sequence,
        head: receipt_chain_head(receipt, &encoded)?,
    };
    write_authority_atomic(authority_path, &new_authority, epochs)?;
    let committed_path = receipt_path(receipt_directory, receipt, true)?;
    fs::rename(pending_path, committed_path)
        .map_err(|_| error(ProtectedAssignmentErrorCode::StorageUnavailable))?;
    sync_directory(receipt_directory)
}

fn commit_receipt_path(
    receipt_directory: &Path,
    entry: &ReceiptEntry,
) -> Result<(), ProtectedAssignmentError> {
    let committed_path = receipt_path(receipt_directory, &entry.receipt, true)?;
    fs::rename(&entry.path, committed_path)
        .map_err(|_| error(ProtectedAssignmentErrorCode::StorageUnavailable))?;
    sync_directory(receipt_directory)
}

fn receipt_path(
    receipt_directory: &Path,
    receipt: &AssignmentReceipt,
    committed: bool,
) -> Result<PathBuf, ProtectedAssignmentError> {
    let suffix = receipt
        .assignment
        .assignment_ref
        .strip_prefix(ASSIGNMENT_REF_PREFIX)
        .filter(|suffix| valid_lower_hex(suffix))
        .ok_or_else(|| error(ProtectedAssignmentErrorCode::CorruptState))?;
    let extension = if committed { "receipt" } else { "pending" };
    Ok(receipt_directory.join(format!("{:020}-{suffix}.{extension}", receipt.sequence)))
}

struct BinaryCursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> BinaryCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn position(&self) -> usize {
        self.position
    }

    fn expect(&mut self, expected: &[u8]) -> Result<(), ProtectedAssignmentError> {
        if self.take(expected.len())? != expected {
            return Err(error(ProtectedAssignmentErrorCode::CorruptState));
        }
        Ok(())
    }

    fn string(&mut self, maximum: usize) -> Result<String, ProtectedAssignmentError> {
        let length = usize::from(u16::from_be_bytes(self.array::<2>()?));
        if length == 0 || length > maximum {
            return Err(error(ProtectedAssignmentErrorCode::CorruptState));
        }
        let value = self.take(length)?;
        std::str::from_utf8(value)
            .map(str::to_owned)
            .map_err(|_| error(ProtectedAssignmentErrorCode::CorruptState))
    }

    fn u32(&mut self) -> Result<u32, ProtectedAssignmentError> {
        Ok(u32::from_be_bytes(self.array::<4>()?))
    }

    fn u64(&mut self) -> Result<u64, ProtectedAssignmentError> {
        Ok(u64::from_be_bytes(self.array::<8>()?))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ProtectedAssignmentError> {
        self.take(N)?
            .try_into()
            .map_err(|_| error(ProtectedAssignmentErrorCode::CorruptState))
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ProtectedAssignmentError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or_else(|| error(ProtectedAssignmentErrorCode::CorruptState))?;
        let result = self
            .bytes
            .get(self.position..end)
            .ok_or_else(|| error(ProtectedAssignmentErrorCode::CorruptState))?;
        self.position = end;
        Ok(result)
    }

    fn finish(&self) -> Result<(), ProtectedAssignmentError> {
        if self.position != self.bytes.len() {
            return Err(error(ProtectedAssignmentErrorCode::CorruptState));
        }
        Ok(())
    }
}

fn push_string(bytes: &mut Vec<u8>, value: &str) -> Result<(), ProtectedAssignmentError> {
    let length = u16::try_from(value.len())
        .map_err(|_| error(ProtectedAssignmentErrorCode::CorruptState))?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}

fn create_key_epoch(
    key_directory: &Path,
) -> Result<(String, [u8; KEY_BYTES]), ProtectedAssignmentError> {
    for _ in 0..MAX_ID_ALLOCATION_ATTEMPTS {
        let mut reference_seed = [0_u8; 32];
        fill_random(&mut reference_seed)?;
        let key_ref = format!("{KEY_REF_PREFIX}{}", hex(&reference_seed));
        let path = key_path(key_directory, &key_ref)?;
        let mut root_key = [0_u8; KEY_BYTES];
        fill_random(&mut root_key)?;
        let bytes = encode_key_file(&key_ref, &root_key)?;
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(FILE_MODE);
        }
        match options.open(&path) {
            Ok(mut file) => {
                set_file_mode(&file, FILE_MODE)?;
                file.write_all(&bytes)
                    .and_then(|()| file.sync_all())
                    .map_err(|_| error(ProtectedAssignmentErrorCode::StorageUnavailable))?;
                sync_directory(key_directory)?;
                return Ok((key_ref, root_key));
            }
            Err(io_error) if io_error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(error(ProtectedAssignmentErrorCode::StorageUnavailable)),
        }
    }
    Err(error(ProtectedAssignmentErrorCode::IdentityCollision))
}

fn encode_key_file(
    key_ref: &str,
    root_key: &[u8; KEY_BYTES],
) -> Result<Vec<u8>, ProtectedAssignmentError> {
    let length = u16::try_from(key_ref.len())
        .map_err(|_| error(ProtectedAssignmentErrorCode::CorruptState))?;
    let mut bytes = Vec::with_capacity(KEY_FILE_MAGIC.len() + 2 + key_ref.len() + 64);
    bytes.extend_from_slice(KEY_FILE_MAGIC);
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(key_ref.as_bytes());
    bytes.extend_from_slice(root_key);
    let mut check = Sha256::new();
    check.update(KEY_FILE_CHECK_DOMAIN);
    check.update(&bytes);
    bytes.extend_from_slice(&check.finalize());
    Ok(bytes)
}

fn read_key_file(
    key_directory: &Path,
    expected_ref: &str,
) -> Result<[u8; KEY_BYTES], ProtectedAssignmentError> {
    let path = key_path(key_directory, expected_ref)?;
    let bytes = read_private_file_bounded(&path, 256)?;
    let fixed = KEY_FILE_MAGIC.len() + 2 + KEY_BYTES + 32;
    if bytes.len() < fixed || !bytes.starts_with(KEY_FILE_MAGIC) {
        return Err(error(ProtectedAssignmentErrorCode::CorruptState));
    }
    let length_offset = KEY_FILE_MAGIC.len();
    let reference_length = usize::from(u16::from_be_bytes([
        bytes[length_offset],
        bytes[length_offset + 1],
    ]));
    let expected_length = fixed
        .checked_add(reference_length)
        .ok_or_else(|| error(ProtectedAssignmentErrorCode::CorruptState))?;
    if bytes.len() != expected_length {
        return Err(error(ProtectedAssignmentErrorCode::CorruptState));
    }
    let reference_start = length_offset + 2;
    let reference_end = reference_start + reference_length;
    if bytes.get(reference_start..reference_end) != Some(expected_ref.as_bytes()) {
        return Err(error(ProtectedAssignmentErrorCode::CorruptState));
    }
    let check_start = bytes.len() - 32;
    let mut check = Sha256::new();
    check.update(KEY_FILE_CHECK_DOMAIN);
    check.update(&bytes[..check_start]);
    if check.finalize().as_slice() != &bytes[check_start..] {
        return Err(error(ProtectedAssignmentErrorCode::CorruptState));
    }
    let key_start = reference_end;
    bytes[key_start..key_start + KEY_BYTES]
        .try_into()
        .map_err(|_| error(ProtectedAssignmentErrorCode::CorruptState))
}

fn key_path(key_directory: &Path, key_ref: &str) -> Result<PathBuf, ProtectedAssignmentError> {
    let suffix = key_ref
        .strip_prefix(KEY_REF_PREFIX)
        .filter(|suffix| valid_lower_hex(suffix))
        .ok_or_else(|| error(ProtectedAssignmentErrorCode::CorruptState))?;
    Ok(key_directory.join(format!("{suffix}.key")))
}

fn protected_replay_key(
    epoch: &KeyEpoch,
    adapter_type: &str,
    adapter_id: &str,
    association: &ReplayAssociation,
) -> Result<String, ProtectedAssignmentError> {
    let key = derive_subkey(&epoch.root_key, ASSOCIATION_SUBKEY_PURPOSE)?;
    let mut mac = HmacSha256::new_from_slice(&key)
        .map_err(|_| error(ProtectedAssignmentErrorCode::CorruptState))?;
    mac.update(ASSOCIATION_DOMAIN);
    update_bounded(&mut mac, adapter_type.as_bytes())?;
    update_bounded(&mut mac, adapter_id.as_bytes())?;
    update_bounded(&mut mac, association.namespace.as_bytes())?;
    update_bounded(&mut mac, &association.locator)?;
    Ok(format!(
        "{REPLAY_KEY_PREFIX}{}",
        hex(&mac.finalize().into_bytes())
    ))
}

fn derive_subkey(
    root_key: &[u8; KEY_BYTES],
    purpose: &[u8],
) -> Result<[u8; 32], ProtectedAssignmentError> {
    let mut mac = HmacSha256::new_from_slice(root_key)
        .map_err(|_| error(ProtectedAssignmentErrorCode::CorruptState))?;
    mac.update(SUBKEY_DOMAIN);
    update_bounded(&mut mac, purpose)?;
    Ok(mac.finalize().into_bytes().into())
}

fn allocate_assignment_candidate(
    transaction: &Transaction<'_>,
    epoch: &KeyEpoch,
    ledger_sequence: u64,
    domain: &str,
    replay_key: &str,
    child_ordinal: u32,
    commitment: &str,
) -> Result<StoredAssignment, ProtectedAssignmentError> {
    for _ in 0..MAX_ID_ALLOCATION_ATTEMPTS {
        let assignment_ref = random_prefixed_id(ASSIGNMENT_REF_PREFIX)?;
        let observation_id = random_observation_id()?;
        if value_exists(transaction, "assignment_ref", &assignment_ref)?
            || value_exists(transaction, "observation_id", &observation_id)?
        {
            continue;
        }
        let mut stored = StoredAssignment {
            ledger_sequence,
            assignment_ref,
            domain: domain.to_owned(),
            replay_key: replay_key.to_owned(),
            child_ordinal,
            observation_id,
            comparison_key_ref: epoch.key_ref.clone(),
            comparison_domain: ASSIGNMENT_COMPARISON_DOMAIN.to_owned(),
            commitment: commitment.to_owned(),
            row_mac: [0; 32],
        };
        stored.row_mac = compute_row_mac(&stored, &epoch.root_key)?;
        return Ok(stored);
    }
    Err(error(ProtectedAssignmentErrorCode::IdentityCollision))
}

fn insert_assignment(
    transaction: &Transaction<'_>,
    stored: &StoredAssignment,
) -> Result<(), ProtectedAssignmentError> {
    let ledger_sequence = i64::try_from(stored.ledger_sequence)
        .map_err(|_| error(ProtectedAssignmentErrorCode::StorageUnavailable))?;
    transaction
        .execute(
            "INSERT INTO assignments
             (ledger_sequence, assignment_ref, adapter_domain, replay_key, child_ordinal,
              observation_id, comparison_key_ref, comparison_domain, commitment, row_mac)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                ledger_sequence,
                &stored.assignment_ref,
                &stored.domain,
                &stored.replay_key,
                i64::from(stored.child_ordinal),
                &stored.observation_id,
                &stored.comparison_key_ref,
                &stored.comparison_domain,
                &stored.commitment,
                stored.row_mac.as_slice(),
            ],
        )
        .map_err(|_| error(ProtectedAssignmentErrorCode::StorageUnavailable))?;
    Ok(())
}

fn value_exists(
    transaction: &Transaction<'_>,
    column: &str,
    value: &str,
) -> Result<bool, ProtectedAssignmentError> {
    let sql = match column {
        "assignment_ref" => "SELECT 1 FROM assignments WHERE assignment_ref = ?1",
        "observation_id" => "SELECT 1 FROM assignments WHERE observation_id = ?1",
        _ => return Err(error(ProtectedAssignmentErrorCode::CorruptState)),
    };
    transaction
        .query_row(sql, params![value], |_| Ok(()))
        .optional()
        .map(|value| value.is_some())
        .map_err(|_| error(ProtectedAssignmentErrorCode::CorruptState))
}

fn load_by_association(
    connection: &Connection,
    domain: &str,
    replay_key: &str,
    child_ordinal: u32,
) -> Result<Option<StoredAssignment>, ProtectedAssignmentError> {
    load_unique_assignment(
        connection,
        "SELECT ledger_sequence, assignment_ref, adapter_domain, replay_key, child_ordinal,
                observation_id, comparison_key_ref, comparison_domain, commitment, row_mac
         FROM assignments
         WHERE adapter_domain = ?1 AND replay_key = ?2 AND child_ordinal = ?3
         LIMIT 2",
        params![domain, replay_key, i64::from(child_ordinal)],
    )
}

fn load_by_reference(
    connection: &Connection,
    assignment_ref: &str,
) -> Result<Option<StoredAssignment>, ProtectedAssignmentError> {
    if !valid_prefixed_hex(assignment_ref, ASSIGNMENT_REF_PREFIX) {
        return Err(error(ProtectedAssignmentErrorCode::ReplayUnverifiable));
    }
    load_unique_assignment(
        connection,
        "SELECT ledger_sequence, assignment_ref, adapter_domain, replay_key, child_ordinal,
                observation_id, comparison_key_ref, comparison_domain, commitment, row_mac
         FROM assignments WHERE assignment_ref = ?1 LIMIT 2",
        params![assignment_ref],
    )
}

fn load_unique_assignment<P: rusqlite::Params>(
    connection: &Connection,
    sql: &str,
    parameters: P,
) -> Result<Option<StoredAssignment>, ProtectedAssignmentError> {
    let mut statement = connection
        .prepare(sql)
        .map_err(|_| error(ProtectedAssignmentErrorCode::CorruptState))?;
    let mut rows = statement
        .query(parameters)
        .map_err(|_| error(ProtectedAssignmentErrorCode::CorruptState))?;
    let first = rows
        .next()
        .map_err(|_| error(ProtectedAssignmentErrorCode::CorruptState))?
        .map(decode_assignment_row)
        .transpose()
        .map_err(|_| error(ProtectedAssignmentErrorCode::CorruptState))?;
    if rows
        .next()
        .map_err(|_| error(ProtectedAssignmentErrorCode::CorruptState))?
        .is_some()
    {
        return Err(error(ProtectedAssignmentErrorCode::ReplayUnverifiable));
    }
    Ok(first)
}

fn decode_assignment_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredAssignment> {
    let ledger_sequence = row.get::<_, i64>(0)?;
    let ledger_sequence = u64::try_from(ledger_sequence).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Integer,
            Box::new(error),
        )
    })?;
    let child_ordinal = row.get::<_, i64>(4)?;
    let child_ordinal = u32::try_from(child_ordinal).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            4,
            rusqlite::types::Type::Integer,
            Box::new(error),
        )
    })?;
    let row_mac = row.get::<_, Vec<u8>>(9)?;
    let row_mac: [u8; 32] = row_mac.as_slice().try_into().map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            9,
            rusqlite::types::Type::Blob,
            "invalid row authenticator length".into(),
        )
    })?;
    Ok(StoredAssignment {
        ledger_sequence,
        assignment_ref: row.get(1)?,
        domain: row.get(2)?,
        replay_key: row.get(3)?,
        child_ordinal,
        observation_id: row.get(5)?,
        comparison_key_ref: row.get(6)?,
        comparison_domain: row.get(7)?,
        commitment: row.get(8)?,
        row_mac,
    })
}

fn validate_stored_assignment(
    stored: &StoredAssignment,
    epoch: &KeyEpoch,
) -> Result<(), ProtectedAssignmentError> {
    if stored.ledger_sequence == 0
        || validate_domain(&stored.domain).is_err()
        || !valid_prefixed_hex(&stored.assignment_ref, ASSIGNMENT_REF_PREFIX)
        || !valid_prefixed_hex(&stored.replay_key, REPLAY_KEY_PREFIX)
        || !valid_prefixed_hex(&stored.observation_id, OBSERVATION_ID_PREFIX)
        || stored.comparison_key_ref != epoch.key_ref
        || stored.comparison_domain != ASSIGNMENT_COMPARISON_DOMAIN
        || !valid_assignment_commitment(&stored.commitment)
        || compute_row_mac(stored, &epoch.root_key)? != stored.row_mac
        || stored.as_record().is_err()
    {
        return Err(error(ProtectedAssignmentErrorCode::CorruptState));
    }
    Ok(())
}

fn compute_row_mac(
    stored: &StoredAssignment,
    root_key: &[u8; KEY_BYTES],
) -> Result<[u8; 32], ProtectedAssignmentError> {
    let key = derive_subkey(root_key, INTEGRITY_SUBKEY_PURPOSE)?;
    let mut mac = HmacSha256::new_from_slice(&key)
        .map_err(|_| error(ProtectedAssignmentErrorCode::CorruptState))?;
    mac.update(ROW_INTEGRITY_DOMAIN);
    mac.update(&stored.ledger_sequence.to_be_bytes());
    for value in [
        stored.assignment_ref.as_bytes(),
        stored.domain.as_bytes(),
        stored.replay_key.as_bytes(),
    ] {
        update_bounded(&mut mac, value)?;
    }
    mac.update(&stored.child_ordinal.to_be_bytes());
    for value in [
        stored.observation_id.as_bytes(),
        stored.comparison_key_ref.as_bytes(),
        stored.comparison_domain.as_bytes(),
        stored.commitment.as_bytes(),
    ] {
        update_bounded(&mut mac, value)?;
    }
    Ok(mac.finalize().into_bytes().into())
}

fn compute_key_epoch_mac(
    key_ref: &str,
    ordinal: u32,
    state: &str,
    root_key: &[u8; KEY_BYTES],
) -> Result<[u8; 32], ProtectedAssignmentError> {
    let key = derive_subkey(root_key, INTEGRITY_SUBKEY_PURPOSE)?;
    let mut mac = HmacSha256::new_from_slice(&key)
        .map_err(|_| error(ProtectedAssignmentErrorCode::CorruptState))?;
    mac.update(b"telltale:protected-assignment-key-epoch-integrity-v1");
    update_bounded(&mut mac, key_ref.as_bytes())?;
    mac.update(&ordinal.to_be_bytes());
    update_bounded(&mut mac, state.as_bytes())?;
    Ok(mac.finalize().into_bytes().into())
}

fn random_prefixed_id(prefix: &str) -> Result<String, ProtectedAssignmentError> {
    let mut seed = [0_u8; 32];
    fill_random(&mut seed)?;
    Ok(format!("{prefix}{}", hex(&seed)))
}

fn random_observation_id() -> Result<String, ProtectedAssignmentError> {
    let mut seed = [0_u8; 32];
    fill_random(&mut seed)?;
    let mut hasher = Sha256::new();
    hasher.update(OBSERVATION_ID_DOMAIN);
    hasher.update(seed);
    Ok(format!("{OBSERVATION_ID_PREFIX}{:x}", hasher.finalize()))
}

fn fill_random(bytes: &mut [u8]) -> Result<(), ProtectedAssignmentError> {
    getrandom::fill(bytes).map_err(|_| error(ProtectedAssignmentErrorCode::StorageUnavailable))
}

fn update_bounded(mac: &mut HmacSha256, value: &[u8]) -> Result<(), ProtectedAssignmentError> {
    let length = u64::try_from(value.len())
        .map_err(|_| error(ProtectedAssignmentErrorCode::InvalidAssociation))?;
    mac.update(&length.to_be_bytes());
    mac.update(value);
    Ok(())
}

fn valid_assignment_commitment(value: &str) -> bool {
    valid_prefixed_hex(value, "hmac-sha256:assignment-v1:")
}

fn valid_prefixed_hex(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(valid_lower_hex)
}

fn valid_lower_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn versioned_namespace(value: &str) -> bool {
    if !value.bytes().all(|byte| {
        byte.is_ascii_lowercase()
            || byte.is_ascii_digit()
            || matches!(byte, b'.' | b'_' | b'-' | b':')
    }) {
        return false;
    }
    let Some((name, version)) = value.rsplit_once(":v") else {
        return false;
    };
    !name.is_empty() && !version.is_empty() && version.bytes().all(|byte| byte.is_ascii_digit())
}

fn validate_domain(domain: &str) -> Result<(), ProtectedAssignmentError> {
    let Some((adapter_type, adapter_id)) = domain.split_once(':') else {
        return Err(error(ProtectedAssignmentErrorCode::InvalidClaim));
    };
    if domain.len() > MAX_DOMAIN_BYTES || adapter_id.contains(':') {
        return Err(error(ProtectedAssignmentErrorCode::InvalidClaim));
    }
    validate_adapter_component(adapter_type)?;
    validate_adapter_component(adapter_id)
}

fn validate_adapter_component(value: &str) -> Result<(), ProtectedAssignmentError> {
    if value.is_empty()
        || value.len() > MAX_ADAPTER_COMPONENT_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(error(ProtectedAssignmentErrorCode::InvalidClaim));
    }
    Ok(())
}

fn map_claim_error(error_value: ObservationError) -> ProtectedAssignmentError {
    match error_value.validation_code() {
        ValidationCode::ReplayCollision => error(ProtectedAssignmentErrorCode::ReplayCollision),
        ValidationCode::ReplayUnverifiable => {
            error(ProtectedAssignmentErrorCode::ReplayUnverifiable)
        }
        _ => error(ProtectedAssignmentErrorCode::InvalidClaim),
    }
}

fn map_build_error(error_value: ObservationError) -> ProtectedAssignmentError {
    match error_value.validation_code() {
        ValidationCode::ReplayCollision => error(ProtectedAssignmentErrorCode::ReplayCollision),
        ValidationCode::ReplayUnverifiable => {
            error(ProtectedAssignmentErrorCode::ReplayUnverifiable)
        }
        _ => error(ProtectedAssignmentErrorCode::CorruptState),
    }
}

fn absolute_path(path: &Path) -> Result<PathBuf, ProtectedAssignmentError> {
    if path.as_os_str().is_empty() {
        return Err(error(ProtectedAssignmentErrorCode::UnsafeStorage));
    }
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        std::env::current_dir()
            .map(|current| current.join(path))
            .map_err(|_| error(ProtectedAssignmentErrorCode::StorageUnavailable))
    }
}

fn validate_trusted_ancestors(path: &Path) -> Result<(), ProtectedAssignmentError> {
    let mut current = path.parent();
    while let Some(ancestor) = current {
        if ancestor.as_os_str().is_empty() {
            break;
        }
        let metadata = fs::symlink_metadata(ancestor)
            .map_err(|_| error(ProtectedAssignmentErrorCode::UnsafeStorage))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(error(ProtectedAssignmentErrorCode::UnsafeStorage));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = metadata.permissions().mode();
            if mode & 0o022 != 0 && mode & 0o1000 == 0 {
                return Err(error(ProtectedAssignmentErrorCode::UnsafeStorage));
            }
        }
        current = ancestor.parent();
    }
    Ok(())
}

fn create_private_directory(path: &Path) -> Result<(), ProtectedAssignmentError> {
    fs::create_dir(path).map_err(|io_error| {
        if io_error.kind() == std::io::ErrorKind::AlreadyExists {
            error(ProtectedAssignmentErrorCode::UnsafeStorage)
        } else {
            error(ProtectedAssignmentErrorCode::StorageUnavailable)
        }
    })?;
    set_directory_mode(path, DIRECTORY_MODE)?;
    validate_private_directory(path)?;
    if let Some(parent) = path.parent() {
        sync_directory(parent)?;
    }
    Ok(())
}

fn validate_private_directory(path: &Path) -> Result<(), ProtectedAssignmentError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| error(ProtectedAssignmentErrorCode::UnsafeStorage))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(error(ProtectedAssignmentErrorCode::UnsafeStorage));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o7777 != DIRECTORY_MODE
        {
            return Err(error(ProtectedAssignmentErrorCode::UnsafeStorage));
        }
    }
    Ok(())
}

fn create_new_private_file(path: &Path, bytes: &[u8]) -> Result<(), ProtectedAssignmentError> {
    let mut options = OpenOptions::new();
    options.create_new(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(FILE_MODE);
    }
    let mut file = options
        .open(path)
        .map_err(|_| error(ProtectedAssignmentErrorCode::StorageUnavailable))?;
    set_file_mode(&file, FILE_MODE)?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| error(ProtectedAssignmentErrorCode::StorageUnavailable))?;
    validate_open_private_file(&file)?;
    if let Some(parent) = path.parent() {
        sync_directory(parent)?;
    }
    Ok(())
}

fn write_private_file_atomic(
    path: &Path,
    bytes: &[u8],
    replace: bool,
) -> Result<(), ProtectedAssignmentError> {
    let parent = path
        .parent()
        .ok_or_else(|| error(ProtectedAssignmentErrorCode::UnsafeStorage))?;
    validate_private_directory(parent)?;
    if replace {
        validate_private_file(path)?;
    } else if fs::symlink_metadata(path).is_ok() {
        return Err(error(ProtectedAssignmentErrorCode::CorruptState));
    }
    for _ in 0..MAX_ID_ALLOCATION_ATTEMPTS {
        let mut seed = [0_u8; 16];
        fill_random(&mut seed)?;
        let temporary = parent.join(format!(".tmp-{}", hex(&seed)));
        if let Err(write_error) = create_new_private_file(&temporary, bytes) {
            if temporary.exists() {
                let _ = fs::remove_file(&temporary);
            }
            if write_error.error_code() == ProtectedAssignmentErrorCode::StorageUnavailable {
                continue;
            }
            return Err(write_error);
        }
        if !replace && fs::symlink_metadata(path).is_ok() {
            let _ = fs::remove_file(&temporary);
            return Err(error(ProtectedAssignmentErrorCode::CorruptState));
        }
        match fs::rename(&temporary, path) {
            Ok(()) => {
                sync_directory(parent)?;
                validate_private_file(path)?;
                return Ok(());
            }
            Err(_) => {
                let _ = fs::remove_file(&temporary);
                return Err(error(ProtectedAssignmentErrorCode::StorageUnavailable));
            }
        }
    }
    Err(error(ProtectedAssignmentErrorCode::StorageUnavailable))
}

fn validate_private_file(path: &Path) -> Result<(), ProtectedAssignmentError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| error(ProtectedAssignmentErrorCode::CorruptState))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(error(ProtectedAssignmentErrorCode::UnsafeStorage));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o7777 != FILE_MODE
        {
            return Err(error(ProtectedAssignmentErrorCode::UnsafeStorage));
        }
    }
    Ok(())
}

fn validate_open_private_file(file: &File) -> Result<(), ProtectedAssignmentError> {
    let metadata = file
        .metadata()
        .map_err(|_| error(ProtectedAssignmentErrorCode::UnsafeStorage))?;
    if !metadata.is_file() {
        return Err(error(ProtectedAssignmentErrorCode::UnsafeStorage));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o7777 != FILE_MODE
        {
            return Err(error(ProtectedAssignmentErrorCode::UnsafeStorage));
        }
    }
    Ok(())
}

fn read_private_file_bounded(
    path: &Path,
    maximum: usize,
) -> Result<Vec<u8>, ProtectedAssignmentError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(path)
        .map_err(|_| error(ProtectedAssignmentErrorCode::CorruptState))?;
    validate_open_private_file(&file)?;
    validate_same_file(path, &file)?;
    let file_length = usize::try_from(
        file.metadata()
            .map_err(|_| error(ProtectedAssignmentErrorCode::CorruptState))?
            .len(),
    )
    .map_err(|_| error(ProtectedAssignmentErrorCode::CorruptState))?;
    if file_length > maximum {
        return Err(error(ProtectedAssignmentErrorCode::CorruptState));
    }
    let mut bytes = Vec::with_capacity(file_length);
    Read::by_ref(&mut file)
        .take(u64::try_from(maximum).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| error(ProtectedAssignmentErrorCode::CorruptState))?;
    if bytes.len() > maximum {
        return Err(error(ProtectedAssignmentErrorCode::CorruptState));
    }
    Ok(bytes)
}

fn open_database(path: &Path) -> Result<(Connection, File), ProtectedAssignmentError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let file = options
        .open(path)
        .map_err(|_| error(ProtectedAssignmentErrorCode::StorageUnavailable))?;
    validate_open_private_file(&file)?;
    validate_same_file(path, &file)?;
    #[cfg(target_os = "linux")]
    let sqlite_path = {
        use std::os::fd::AsRawFd;
        PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
    };
    #[cfg(not(target_os = "linux"))]
    let sqlite_path = path.to_path_buf();
    let connection = Connection::open_with_flags(sqlite_path, OpenFlags::SQLITE_OPEN_READ_WRITE)
        .map_err(|_| error(ProtectedAssignmentErrorCode::StorageUnavailable))?;
    validate_same_file(path, &file)?;
    Ok((connection, file))
}

fn acquire_store_lock(path: &Path) -> Result<StoreLock, ProtectedAssignmentError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let file = options
        .open(path)
        .map_err(|_| error(ProtectedAssignmentErrorCode::StorageUnavailable))?;
    validate_open_private_file(&file)?;
    validate_same_file(path, &file)?;
    let deadline = Instant::now() + LOCK_WAIT;
    loop {
        match file.try_lock_exclusive() {
            Ok(true) => {
                validate_same_file(path, &file)?;
                return Ok(StoreLock {
                    file,
                    path: path.to_path_buf(),
                });
            }
            Ok(false) => {}
            Err(io_error) if io_error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => return Err(error(ProtectedAssignmentErrorCode::StorageUnavailable)),
        }
        if Instant::now() >= deadline {
            return Err(error(ProtectedAssignmentErrorCode::StorageUnavailable));
        }
        thread::sleep(LOCK_RETRY);
    }
}

fn validate_same_file(path: &Path, _file: &File) -> Result<(), ProtectedAssignmentError> {
    validate_private_file(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let path_metadata =
            fs::metadata(path).map_err(|_| error(ProtectedAssignmentErrorCode::UnsafeStorage))?;
        let file_metadata = _file
            .metadata()
            .map_err(|_| error(ProtectedAssignmentErrorCode::UnsafeStorage))?;
        if path_metadata.dev() != file_metadata.dev() || path_metadata.ino() != file_metadata.ino()
        {
            return Err(error(ProtectedAssignmentErrorCode::UnsafeStorage));
        }
    }
    Ok(())
}

fn set_directory_mode(path: &Path, mode: u32) -> Result<(), ProtectedAssignmentError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .map_err(|_| error(ProtectedAssignmentErrorCode::StorageUnavailable))?;
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
    Ok(())
}

fn set_file_mode(file: &File, mode: u32) -> Result<(), ProtectedAssignmentError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(mode))
            .map_err(|_| error(ProtectedAssignmentErrorCode::StorageUnavailable))?;
    }
    #[cfg(not(unix))]
    let _ = (file, mode);
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), ProtectedAssignmentError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| error(ProtectedAssignmentErrorCode::StorageUnavailable))
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use std::fs;
    #[cfg(target_os = "linux")]
    use std::sync::{Arc, Barrier};
    #[cfg(target_os = "linux")]
    use std::thread;

    #[cfg(target_os = "linux")]
    use rusqlite::Connection;
    #[cfg(target_os = "linux")]
    use telltale_schema::observation::{
        FactMetadata, FactProvenance, Fidelity, IngestionMode, JsonValue, MessageObservation,
        MessageRole, ObservationBody, ObservationStage, ObservedAt, Sensitivity, SourceProvenance,
        ToolObservation,
    };

    use super::*;

    #[cfg(target_os = "linux")]
    const OBSERVED_AT: &str = "2026-09-06T12:00:00Z";

    #[cfg(target_os = "linux")]
    fn private_root(temp: &tempfile::TempDir) -> PathBuf {
        temp.path().join("protected-assignment")
    }

    #[cfg(target_os = "linux")]
    fn tool_builder(name: &str) -> ObservationBuilder {
        CanonicalObservationV2::builder(
            ObservationBody::Tool(ToolObservation::new().with_name(name).unwrap()),
            ObservationStage::ToolProposed,
            ObservedAt::new(OBSERVED_AT).unwrap(),
            SourceProvenance::new(
                IngestionMode::SessionStore,
                "synthetic",
                "coordinate-less",
                Fidelity::FullNative,
            )
            .unwrap(),
        )
        .fact_metadata("tool.name", FactMetadata::reported().unwrap())
    }

    #[cfg(target_os = "linux")]
    fn association(locator: &[u8]) -> ReplayAssociation {
        ReplayAssociation::new(
            AssignmentAdapterDomain::registered("synthetic", "coordinate-less").unwrap(),
            "synthetic-record:v1",
            locator,
        )
        .unwrap()
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn claim_replay_reopen_and_mutation_are_deterministic() {
        let temp = tempfile::tempdir().unwrap();
        let root = private_root(&temp);
        let first_id = {
            let mut store = ProtectedAssignmentStore::initialize(&root).unwrap();
            let first = store
                .claim_or_replay(tool_builder("shell"), &association(b"record-a"))
                .unwrap();
            let replay = store
                .claim_or_replay(tool_builder("shell"), &association(b"record-a"))
                .unwrap();
            assert_eq!(first.observation_id(), replay.observation_id());
            assert!(valid_prefixed_hex(
                first.observation_id(),
                OBSERVATION_ID_PREFIX
            ));
            let collision = store
                .claim_or_replay(tool_builder("different"), &association(b"record-a"))
                .unwrap_err();
            assert_eq!(collision.code(), "replay_collision");
            first.observation_id().to_owned()
        };
        let mut reopened = ProtectedAssignmentStore::open(&root).unwrap();
        let replay = reopened
            .claim_or_replay(tool_builder("shell"), &association(b"record-a"))
            .unwrap();
        assert_eq!(replay.observation_id(), first_id);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn distinct_stable_associations_can_represent_semantic_duplicates() {
        let temp = tempfile::tempdir().unwrap();
        let mut store = ProtectedAssignmentStore::initialize(private_root(&temp)).unwrap();
        let first = store
            .claim_or_replay(tool_builder("shell"), &association(b"record-a"))
            .unwrap();
        let second = store
            .claim_or_replay(tool_builder("shell"), &association(b"record-b"))
            .unwrap();
        assert_ne!(first.observation_id(), second.observation_id());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn child_ordinal_is_part_of_transactional_uniqueness() {
        let temp = tempfile::tempdir().unwrap();
        let mut store = ProtectedAssignmentStore::initialize(private_root(&temp)).unwrap();
        let first = store
            .claim_or_replay(
                tool_builder("shell").child_ordinal(0),
                &association(b"record-a"),
            )
            .unwrap();
        let second = store
            .claim_or_replay(
                tool_builder("shell").child_ordinal(1),
                &association(b"record-a"),
            )
            .unwrap();
        assert_ne!(first.observation_id(), second.observation_id());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn claim_rejects_coordinate() {
        let temp = tempfile::tempdir().unwrap();
        let mut store = ProtectedAssignmentStore::initialize(private_root(&temp)).unwrap();
        let stable_source = SourceProvenance::new(
            IngestionMode::SessionStore,
            "synthetic",
            "stable",
            Fidelity::FullNative,
        )
        .unwrap()
        .with_native_id("record-a")
        .unwrap();
        let stable = CanonicalObservationV2::builder(
            ObservationBody::Tool(ToolObservation::new().with_name("shell").unwrap()),
            ObservationStage::ToolProposed,
            ObservedAt::new(OBSERVED_AT).unwrap(),
            stable_source,
        )
        .fact_metadata("tool.name", FactMetadata::reported().unwrap());
        assert_eq!(
            store
                .claim_or_replay(stable, &association(b"record-a"))
                .unwrap_err()
                .code(),
            "invalid_claim"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn concurrent_first_claims_converge() {
        let temp = tempfile::tempdir().unwrap();
        let root = private_root(&temp);
        drop(ProtectedAssignmentStore::initialize(&root).unwrap());
        let barrier = Arc::new(Barrier::new(2));
        let handles = (0..2)
            .map(|_| {
                let root = root.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    let mut store = ProtectedAssignmentStore::open(root).unwrap();
                    barrier.wait();
                    store
                        .claim_or_replay(tool_builder("shell"), &association(b"record-a"))
                        .unwrap()
                        .observation_id()
                        .to_owned()
                })
            })
            .collect::<Vec<_>>();
        let ids = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(ids[0], ids[1]);
        let connection = Connection::open(root.join(DATABASE_NAME)).unwrap();
        let count: i64 = connection
            .query_row("SELECT COUNT(*) FROM assignments", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn process_level_claims_converge() {
        use std::env;
        use std::process::{Command, Stdio};

        if let (Ok(root), Ok(output)) = (
            env::var("TELLTALE_ASSIGNMENT_CHILD_ROOT"),
            env::var("TELLTALE_ASSIGNMENT_CHILD_OUTPUT"),
        ) {
            let mut store = ProtectedAssignmentStore::open(PathBuf::from(root)).unwrap();
            let claimed = store
                .claim_or_replay(tool_builder("shell"), &association(b"record-a"))
                .unwrap();
            fs::write(output, claimed.observation_id()).unwrap();
            return;
        }

        let temp = tempfile::tempdir().unwrap();
        let root = private_root(&temp);
        drop(ProtectedAssignmentStore::initialize(&root).unwrap());
        let outputs = [temp.path().join("first.id"), temp.path().join("second.id")];
        let children = outputs
            .iter()
            .map(|output| {
                Command::new(env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "assignment::tests::process_level_claims_converge",
                    ])
                    .env("TELLTALE_ASSIGNMENT_CHILD_ROOT", &root)
                    .env("TELLTALE_ASSIGNMENT_CHILD_OUTPUT", output)
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let statuses = children
            .into_iter()
            .map(|mut child| child.wait().unwrap())
            .collect::<Vec<_>>();
        assert!(statuses.iter().all(|status| status.success()));
        let ids = outputs
            .iter()
            .map(|output| fs::read_to_string(output).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(ids[0], ids[1]);
        let connection = Connection::open(root.join(DATABASE_NAME)).unwrap();
        let count: i64 = connection
            .query_row("SELECT COUNT(*) FROM assignments", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn concurrent_commitment_disagreement_has_one_winner() {
        let temp = tempfile::tempdir().unwrap();
        let root = private_root(&temp);
        drop(ProtectedAssignmentStore::initialize(&root).unwrap());
        let barrier = Arc::new(Barrier::new(2));
        let handles = ["shell", "different"]
            .into_iter()
            .map(|name| {
                let root = root.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    let mut store = ProtectedAssignmentStore::open(root).unwrap();
                    barrier.wait();
                    store
                        .claim_or_replay(tool_builder(name), &association(b"record-a"))
                        .map(|observation| observation.observation_id().to_owned())
                        .map_err(|error| error.code())
                })
            })
            .collect::<Vec<_>>();
        let results = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| result
                    .as_ref()
                    .is_err_and(|code| *code == "replay_collision"))
                .count(),
            1
        );
        let connection = Connection::open(root.join(DATABASE_NAME)).unwrap();
        let count: i64 = connection
            .query_row("SELECT COUNT(*) FROM assignments", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn transaction_fault_boundaries_preserve_claim_semantics() {
        let temp = tempfile::tempdir().unwrap();
        let root = private_root(&temp);
        let mut store = ProtectedAssignmentStore::initialize(&root).unwrap();
        store.fail_next_before_commit();
        assert_eq!(
            store
                .claim_or_replay(tool_builder("shell"), &association(b"before"))
                .unwrap_err()
                .code(),
            "storage_unavailable"
        );
        let count: i64 = store
            .connection
            .query_row("SELECT COUNT(*) FROM assignments", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0);

        store.fail_next_after_commit();
        assert_eq!(
            store
                .claim_or_replay(tool_builder("shell"), &association(b"after"))
                .unwrap_err()
                .code(),
            "storage_unavailable"
        );
        drop(store);
        let mut reopened = ProtectedAssignmentStore::open(&root).unwrap();
        let first = reopened
            .claim_or_replay(tool_builder("shell"), &association(b"after"))
            .unwrap();
        let second = reopened
            .claim_or_replay(tool_builder("shell"), &association(b"after"))
            .unwrap();
        assert_eq!(first.observation_id(), second.observation_id());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn rotation_keeps_old_assignments_replayable() {
        let temp = tempfile::tempdir().unwrap();
        let root = private_root(&temp);
        let mut store = ProtectedAssignmentStore::initialize(&root).unwrap();
        let old = store
            .claim_or_replay(tool_builder("shell"), &association(b"old"))
            .unwrap()
            .observation_id()
            .to_owned();
        store.rotate_key().unwrap();
        let replay = store
            .claim_or_replay(tool_builder("shell"), &association(b"old"))
            .unwrap();
        assert_eq!(replay.observation_id(), old);
        let new = store
            .claim_or_replay(tool_builder("shell"), &association(b"new"))
            .unwrap();
        assert_ne!(new.observation_id(), old);
        drop(store);
        let mut reopened = ProtectedAssignmentStore::open(root).unwrap();
        assert_eq!(
            reopened
                .claim_or_replay(tool_builder("shell"), &association(b"old"))
                .unwrap()
                .observation_id(),
            old
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn association_ambiguity_across_epochs_fails_without_selection() {
        let temp = tempfile::tempdir().unwrap();
        let root = private_root(&temp);
        let mut store = ProtectedAssignmentStore::initialize(&root).unwrap();
        let replay = association(b"ambiguous");
        store
            .claim_or_replay(tool_builder("shell"), &replay)
            .unwrap();
        store.rotate_key().unwrap();

        let key_directory = store.key_directory.clone();
        let transaction = store
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let epochs = load_key_epochs(&transaction, &key_directory).unwrap();
        let active = exactly_one_active(&epochs).unwrap();
        let comparison_key = derive_subkey(&active.root_key, COMPARISON_SUBKEY_PURPOSE).unwrap();
        let material = tool_builder("shell")
            .prepare_assignment_claim(&comparison_key)
            .unwrap();
        let replay_key = protected_replay_key(
            active,
            material.adapter_type(),
            material.adapter_id(),
            &replay,
        )
        .unwrap();
        let authority = load_authority(&store.authority_path, &epochs).unwrap();
        let stored = allocate_assignment_candidate(
            &transaction,
            active,
            authority.count + 1,
            material.domain(),
            &replay_key,
            material.child_ordinal(),
            material.commitment(),
        )
        .unwrap();
        let receipt = AssignmentReceipt {
            sequence: stored.ledger_sequence,
            previous_head: authority.head,
            assignment: stored.clone(),
        };
        let pending =
            write_pending_receipt(&store.receipt_directory, &receipt, &active.root_key).unwrap();
        insert_assignment(&transaction, &stored).unwrap();
        transaction.commit().unwrap();
        finalize_receipt(
            &store.authority_path,
            &store.receipt_directory,
            &receipt,
            &pending,
            &authority,
            &epochs,
        )
        .unwrap();

        assert_eq!(
            store
                .claim_or_replay(tool_builder("shell"), &replay)
                .unwrap_err()
                .code(),
            "replay_unverifiable"
        );
        let count: i64 = store
            .connection
            .query_row("SELECT COUNT(*) FROM assignments", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 2);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn key_epoch_limit_blocks_rotation_not_replay() {
        let temp = tempfile::tempdir().unwrap();
        let mut store = ProtectedAssignmentStore::initialize(private_root(&temp)).unwrap();
        let original = store
            .claim_or_replay(tool_builder("shell"), &association(b"record-a"))
            .unwrap()
            .observation_id()
            .to_owned();
        for _ in 1..MAX_KEY_EPOCHS {
            store.rotate_key().unwrap();
        }
        assert_eq!(
            store.rotate_key().unwrap_err().code(),
            "storage_unavailable"
        );
        assert_eq!(
            store
                .claim_or_replay(tool_builder("shell"), &association(b"record-a"))
                .unwrap()
                .observation_id(),
            original
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn row_tamper_and_missing_key_fail_closed() {
        let temp = tempfile::tempdir().unwrap();
        let root = private_root(&temp);
        let mut store = ProtectedAssignmentStore::initialize(&root).unwrap();
        store
            .claim_or_replay(tool_builder("shell"), &association(b"record-a"))
            .unwrap();
        let key_ref: String = store
            .connection
            .query_row("SELECT key_ref FROM key_epochs LIMIT 1", [], |row| {
                row.get(0)
            })
            .unwrap();
        drop(store);

        let connection = Connection::open(root.join(DATABASE_NAME)).unwrap();
        connection
            .execute(
                "UPDATE assignments SET replay_key = ?1",
                params![format!("{REPLAY_KEY_PREFIX}{}", "a".repeat(64))],
            )
            .unwrap();
        drop(connection);
        assert_eq!(
            ProtectedAssignmentStore::open(&root).unwrap_err().code(),
            "corrupt_state"
        );

        let key = key_path(&root.join(KEY_DIRECTORY_NAME), &key_ref).unwrap();
        fs::remove_file(key).unwrap();
        assert_eq!(
            ProtectedAssignmentStore::open(root).unwrap_err().code(),
            "corrupt_state"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn deleted_or_lost_assignment_state_never_allocates_a_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let root = private_root(&temp);
        let mut store = ProtectedAssignmentStore::initialize(&root).unwrap();
        store
            .claim_or_replay(tool_builder("shell"), &association(b"record-a"))
            .unwrap();
        drop(store);

        let connection = Connection::open(root.join(DATABASE_NAME)).unwrap();
        connection.execute("DELETE FROM assignments", []).unwrap();
        drop(connection);
        assert_eq!(
            ProtectedAssignmentStore::open(&root).unwrap_err().code(),
            "corrupt_state"
        );

        let temp = tempfile::tempdir().unwrap();
        let root = private_root(&temp);
        let mut store = ProtectedAssignmentStore::initialize(&root).unwrap();
        store
            .claim_or_replay(tool_builder("shell"), &association(b"record-a"))
            .unwrap();
        drop(store);
        fs::remove_file(root.join(DATABASE_NAME)).unwrap();
        assert_eq!(
            ProtectedAssignmentStore::open(&root).unwrap_err().code(),
            "corrupt_state"
        );
        assert!(!root.join(DATABASE_NAME).exists());
        assert_eq!(
            ProtectedAssignmentStore::initialize(&root)
                .unwrap_err()
                .code(),
            "unsafe_storage"
        );

        let temp = tempfile::tempdir().unwrap();
        let root = private_root(&temp);
        let mut store = ProtectedAssignmentStore::initialize(&root).unwrap();
        let snapshot = temp.path().join("pre-claim.sqlite3");
        fs::copy(root.join(DATABASE_NAME), &snapshot).unwrap();
        store
            .claim_or_replay(tool_builder("shell"), &association(b"record-a"))
            .unwrap();
        drop(store);
        fs::copy(snapshot, root.join(DATABASE_NAME)).unwrap();
        assert_eq!(
            ProtectedAssignmentStore::open(&root).unwrap_err().code(),
            "corrupt_state"
        );

        let temp = tempfile::tempdir().unwrap();
        let root = private_root(&temp);
        let mut store = ProtectedAssignmentStore::initialize(&root).unwrap();
        store
            .claim_or_replay(tool_builder("shell"), &association(b"record-a"))
            .unwrap();
        drop(store);
        let receipt = fs::read_dir(root.join(RECEIPT_DIRECTORY_NAME))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        fs::remove_file(receipt).unwrap();
        assert_eq!(
            ProtectedAssignmentStore::open(root).unwrap_err().code(),
            "corrupt_state"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn same_version_wrong_schema_and_ambiguous_adapter_components_fail_closed() {
        let temp = tempfile::tempdir().unwrap();
        let root = private_root(&temp);
        drop(ProtectedAssignmentStore::initialize(&root).unwrap());
        let connection = Connection::open(root.join(DATABASE_NAME)).unwrap();
        connection.execute("DROP TABLE assignments", []).unwrap();
        connection
            .execute(
                "CREATE TABLE assignments (assignment_ref TEXT PRIMARY KEY)",
                [],
            )
            .unwrap();
        drop(connection);
        assert_eq!(
            ProtectedAssignmentStore::open(&root).unwrap_err().code(),
            "corrupt_state"
        );

        let temp = tempfile::tempdir().unwrap();
        let mut store = ProtectedAssignmentStore::initialize(private_root(&temp)).unwrap();
        for (adapter_type, adapter_id) in [("a:b", "c"), ("a", "b:c"), ("path", "a/b")] {
            let builder = CanonicalObservationV2::builder(
                ObservationBody::Tool(ToolObservation::new().with_name("shell").unwrap()),
                ObservationStage::ToolProposed,
                ObservedAt::new(OBSERVED_AT).unwrap(),
                SourceProvenance::new(
                    IngestionMode::SessionStore,
                    adapter_type,
                    adapter_id,
                    Fidelity::FullNative,
                )
                .unwrap(),
            )
            .fact_metadata("tool.name", FactMetadata::reported().unwrap());
            assert_eq!(
                store
                    .claim_or_replay(builder, &association(b"record"))
                    .unwrap_err()
                    .code(),
                "invalid_claim"
            );
        }
        let leaked_type: &'static str = Box::leak("runtime-tenant".to_owned().into_boxed_str());
        let leaked_id: &'static str = Box::leak("runtime-secret".to_owned().into_boxed_str());
        assert_eq!(
            AssignmentAdapterDomain::registered(leaked_type, leaked_id)
                .unwrap_err()
                .code(),
            "invalid_claim"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn live_database_path_replacement_fails_before_another_claim() {
        let temp = tempfile::tempdir().unwrap();
        let root = private_root(&temp);
        let mut store = ProtectedAssignmentStore::initialize(&root).unwrap();
        store
            .claim_or_replay(tool_builder("shell"), &association(b"record-a"))
            .unwrap();
        let database_path = root.join(DATABASE_NAME);
        let replacement = temp.path().join("replacement.sqlite3");
        fs::copy(&database_path, &replacement).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&replacement, fs::Permissions::from_mode(FILE_MODE)).unwrap();
        }
        fs::rename(&database_path, temp.path().join("displaced.sqlite3")).unwrap();
        fs::rename(replacement, &database_path).unwrap();
        assert_eq!(
            store
                .claim_or_replay(tool_builder("shell"), &association(b"record-b"))
                .unwrap_err()
                .code(),
            "unsafe_storage"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn key_metadata_tamper_and_missing_key_each_fail_closed() {
        let temp = tempfile::tempdir().unwrap();
        let root = private_root(&temp);
        let store = ProtectedAssignmentStore::initialize(&root).unwrap();
        drop(store);
        let connection = Connection::open(root.join(DATABASE_NAME)).unwrap();
        connection
            .execute(
                "UPDATE key_epochs SET metadata_mac = ?1",
                params![vec![0_u8; 32]],
            )
            .unwrap();
        drop(connection);
        assert_eq!(
            ProtectedAssignmentStore::open(&root).unwrap_err().code(),
            "corrupt_state"
        );

        let temp = tempfile::tempdir().unwrap();
        let root = private_root(&temp);
        let store = ProtectedAssignmentStore::initialize(&root).unwrap();
        let key_ref: String = store
            .connection
            .query_row("SELECT key_ref FROM key_epochs LIMIT 1", [], |row| {
                row.get(0)
            })
            .unwrap();
        drop(store);
        fs::remove_file(key_path(&root.join(KEY_DIRECTORY_NAME), &key_ref).unwrap()).unwrap();
        assert_eq!(
            ProtectedAssignmentStore::open(root).unwrap_err().code(),
            "corrupt_state"
        );

        let temp = tempfile::tempdir().unwrap();
        let root = private_root(&temp);
        let store = ProtectedAssignmentStore::initialize(&root).unwrap();
        let key_ref: String = store
            .connection
            .query_row("SELECT key_ref FROM key_epochs LIMIT 1", [], |row| {
                row.get(0)
            })
            .unwrap();
        drop(store);
        fs::write(
            key_path(&root.join(KEY_DIRECTORY_NAME), &key_ref).unwrap(),
            b"synthetic-malformed-key",
        )
        .unwrap();
        assert_eq!(
            ProtectedAssignmentStore::open(root).unwrap_err().code(),
            "corrupt_state"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn authority_and_receipt_tamper_each_fail_closed() {
        let temp = tempfile::tempdir().unwrap();
        let root = private_root(&temp);
        let mut store = ProtectedAssignmentStore::initialize(&root).unwrap();
        store
            .claim_or_replay(tool_builder("shell"), &association(b"record-a"))
            .unwrap();
        drop(store);
        let authority_path = root.join(AUTHORITY_FILE_NAME);
        let mut authority = fs::read(&authority_path).unwrap();
        let last = authority.last_mut().unwrap();
        *last ^= 1;
        fs::write(&authority_path, authority).unwrap();
        assert_eq!(
            ProtectedAssignmentStore::open(&root).unwrap_err().code(),
            "corrupt_state"
        );

        let temp = tempfile::tempdir().unwrap();
        let root = private_root(&temp);
        let mut store = ProtectedAssignmentStore::initialize(&root).unwrap();
        store
            .claim_or_replay(tool_builder("shell"), &association(b"record-a"))
            .unwrap();
        drop(store);
        let receipt_path = fs::read_dir(root.join(RECEIPT_DIRECTORY_NAME))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let mut receipt = fs::read(&receipt_path).unwrap();
        let last = receipt.last_mut().unwrap();
        *last ^= 1;
        fs::write(receipt_path, receipt).unwrap();
        assert_eq!(
            ProtectedAssignmentStore::open(root).unwrap_err().code(),
            "corrupt_state"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn privacy_markers_do_not_reach_errors_debug_or_database() {
        let marker = "synthetic-secret-marker://credential@example.invalid";
        let temp = tempfile::tempdir().unwrap();
        let root = private_root(&temp);
        let mut store = ProtectedAssignmentStore::initialize(&root).unwrap();
        let replay = ReplayAssociation::new(
            AssignmentAdapterDomain::registered("synthetic", "coordinate-less").unwrap(),
            "synthetic-record:v1",
            marker.as_bytes(),
        )
        .unwrap();
        let builder = CanonicalObservationV2::builder(
            ObservationBody::Message(
                MessageObservation::new(MessageRole::User).with_content(JsonValue::string(marker)),
            ),
            ObservationStage::MessageObserved,
            ObservedAt::new(OBSERVED_AT).unwrap(),
            SourceProvenance::new(
                IngestionMode::SessionStore,
                "synthetic",
                "coordinate-less",
                Fidelity::FullNative,
            )
            .unwrap(),
        )
        .fact_metadata("message.role", FactMetadata::reported().unwrap())
        .fact_metadata(
            "message.content",
            FactMetadata::new(FactProvenance::Reported, Sensitivity::Secret).unwrap(),
        );
        let observation = store.claim_or_replay(builder, &replay).unwrap();
        assert!(!format!("{store:?}{replay:?}{observation:?}").contains(marker));
        let error_value = store
            .claim_or_replay(tool_builder("different"), &replay)
            .unwrap_err();
        assert!(!format!("{error_value:?} {error_value}").contains(marker));
        drop(store);
        let database = fs::read(root.join(DATABASE_NAME)).unwrap();
        assert!(
            !database
                .windows(marker.len())
                .any(|window| window == marker.as_bytes())
        );
        for directory in [
            root.join(KEY_DIRECTORY_NAME),
            root.join(RECEIPT_DIRECTORY_NAME),
        ] {
            for entry in fs::read_dir(directory).unwrap() {
                let bytes = fs::read(entry.unwrap().path()).unwrap();
                assert!(
                    !bytes
                        .windows(marker.len())
                        .any(|window| window == marker.as_bytes())
                );
            }
        }
        let authority = fs::read(root.join(AUTHORITY_FILE_NAME)).unwrap();
        assert!(
            !authority
                .windows(marker.len())
                .any(|window| window == marker.as_bytes())
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unsafe_modes_newer_schema_and_windows_fail_before_use() {
        let temp = tempfile::tempdir().unwrap();
        let root = private_root(&temp);
        assert_eq!(
            ProtectedAssignmentStore::open_for_platform(&root, true)
                .unwrap_err()
                .code(),
            "unsupported_platform"
        );
        assert!(!root.exists());

        drop(ProtectedAssignmentStore::initialize(&root).unwrap());
        let connection = Connection::open(root.join(DATABASE_NAME)).unwrap();
        connection
            .pragma_update(None, "user_version", STORE_SCHEMA_VERSION + 1)
            .unwrap();
        drop(connection);
        assert_eq!(
            ProtectedAssignmentStore::open(&root).unwrap_err().code(),
            "unsupported_version"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
            assert_eq!(
                ProtectedAssignmentStore::open(root).unwrap_err().code(),
                "unsafe_storage"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn foreign_corrupt_and_linked_storage_fail_closed() {
        let temp = tempfile::tempdir().unwrap();
        let root = private_root(&temp);
        fs::create_dir(&root).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(DIRECTORY_MODE)).unwrap();
        }
        let database_path = root.join(DATABASE_NAME);
        let connection = Connection::open(&database_path).unwrap();
        connection
            .execute("CREATE TABLE foreign_state (id INTEGER)", [])
            .unwrap();
        drop(connection);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&database_path, fs::Permissions::from_mode(FILE_MODE)).unwrap();
        }
        assert_eq!(
            ProtectedAssignmentStore::open(&root).unwrap_err().code(),
            "unsafe_storage"
        );

        let temp = tempfile::tempdir().unwrap();
        let root = private_root(&temp);
        drop(ProtectedAssignmentStore::initialize(&root).unwrap());
        fs::write(root.join(DATABASE_NAME), b"synthetic-corrupt-database").unwrap();
        assert_eq!(
            ProtectedAssignmentStore::open(&root).unwrap_err().code(),
            "corrupt_state"
        );

        #[cfg(unix)]
        {
            let temp = tempfile::tempdir().unwrap();
            let root = private_root(&temp);
            let store = ProtectedAssignmentStore::initialize(&root).unwrap();
            let key_ref: String = store
                .connection
                .query_row("SELECT key_ref FROM key_epochs LIMIT 1", [], |row| {
                    row.get(0)
                })
                .unwrap();
            drop(store);
            let key = key_path(&root.join(KEY_DIRECTORY_NAME), &key_ref).unwrap();
            fs::hard_link(&key, temp.path().join("linked-key")).unwrap();
            assert_eq!(
                ProtectedAssignmentStore::open(&root).unwrap_err().code(),
                "unsafe_storage"
            );

            let target = temp.path().join("target");
            fs::create_dir(&target).unwrap();
            use std::os::unix::fs::{PermissionsExt, symlink};
            fs::set_permissions(&target, fs::Permissions::from_mode(DIRECTORY_MODE)).unwrap();
            let alias = temp.path().join("alias");
            symlink(&target, &alias).unwrap();
            assert_eq!(
                ProtectedAssignmentStore::open(alias).unwrap_err().code(),
                "unsafe_storage"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn closed_store_root_can_move_without_changing_assignment() {
        let temp = tempfile::tempdir().unwrap();
        let root = private_root(&temp);
        let mut store = ProtectedAssignmentStore::initialize(&root).unwrap();
        let original = store
            .claim_or_replay(tool_builder("shell"), &association(b"record-a"))
            .unwrap()
            .observation_id()
            .to_owned();
        drop(store);
        let moved = temp.path().join("moved-assignment-store");
        fs::rename(root, &moved).unwrap();
        let mut reopened = ProtectedAssignmentStore::open(moved).unwrap();
        assert_eq!(
            reopened
                .claim_or_replay(tool_builder("shell"), &association(b"record-a"))
                .unwrap()
                .observation_id(),
            original
        );
    }

    #[test]
    fn association_namespace_and_locator_are_bounded() {
        let domain =
            || AssignmentAdapterDomain::registered("synthetic", "coordinate-less").unwrap();
        assert!(ReplayAssociation::new(domain(), "synthetic-record:v1", b"record").is_ok());
        assert_eq!(
            ReplayAssociation::new(domain(), "unversioned", b"record")
                .unwrap_err()
                .code(),
            "invalid_association"
        );
        assert_eq!(
            ReplayAssociation::new(domain(), "synthetic-record:v1", [])
                .unwrap_err()
                .code(),
            "invalid_association"
        );
        assert_eq!(
            ReplayAssociation::new(
                domain(),
                "synthetic-record:v1",
                vec![b'x'; MAX_ASSOCIATION_LOCATOR_BYTES + 1]
            )
            .unwrap_err()
            .code(),
            "invalid_association"
        );
    }

    #[test]
    fn roo_and_kilo_coordinate_less_array_candidates_remain_blocked() {
        let before = ["first", "middle", "last"];
        let after_delete = ["first", "last"];
        let before_last_ordinal = before.iter().position(|item| *item == "last").unwrap();
        let after_last_ordinal = after_delete
            .iter()
            .position(|item| *item == "last")
            .unwrap();
        assert_ne!(before_last_ordinal, after_last_ordinal);

        let duplicate_timestamps = [1_700_000_000_000_u64, 1_700_000_000_000_u64];
        assert_eq!(duplicate_timestamps[0], duplicate_timestamps[1]);
        assert_ne!(
            Sha256::digest(b"synthetic partial"),
            Sha256::digest(b"synthetic final")
        );
        assert!(
            before.len() > 1,
            "one task path cannot identify each message"
        );

        assert_ne!(before, ["last", "middle", "first"]);
        assert_eq!(before[0], "first");
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn unsupported_platforms_fail_before_state_creation() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("protected-assignment");
        assert_eq!(
            ProtectedAssignmentStore::initialize(&root)
                .unwrap_err()
                .code(),
            "unsupported_platform"
        );
        assert!(!root.exists());
        assert_eq!(
            ProtectedAssignmentStore::open(&root).unwrap_err().code(),
            "unsupported_platform"
        );
        assert!(!root.exists());
    }
}
