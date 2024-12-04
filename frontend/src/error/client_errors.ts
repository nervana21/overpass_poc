export enum ChannelErrorType {
    InvalidTransaction,
    InvalidNonce,
    InvalidSequence,
    InvalidAmount,
    InsufficientBalance,
    SpendingLimitExceeded,
    NoRootCell,
    InvalidOperation,
    InvalidArgument,
    NotFound,
    InvalidProof
}
export enum ClientErrorType {
    InvalidTransaction,
    InvalidNonce,
    InvalidSequence,
    InvalidAmount,
    InsufficientBalance,
    SpendingLimitExceeded,
    NoRootCell,
    InvalidOperation,
    InvalidArgument,
    NotFound,
    InvalidProof
}

export class ChannelError extends Error {
    constructor(
        public errorType: ChannelErrorType,
        public message: string
    ) {
        super(`${errorType}: ${message}`);
        this.name = 'ChannelError';
    }
}

export enum SystemErrorType {
    InvalidTransaction,
    InvalidSignature,
    InvalidPublicKey,
    DecryptionError,
    InvalidAddress,
    ProofGenerationError,
    InvalidHash,
    InvalidNonce,
    InvalidSequence,
    StateUpdateError,
    InsufficientCharge,
    VerificationError,
    DataConversionError,
    InvalidInput,
    InvalidState,
    NoProof,
    CryptoError,
    ResourceUnavailable,
    NetworkError,
    ResourceLimitReached,
    NoRoots,
    CircuitError,
    ProofError,
    OperationDisabled,
    StorageError,
    LockAcquisitionError,
    InvalidReference,
    InvalidData,
    InvalidAmount,
    StateDataMismatch,
    SerializationError,
    InvalidProof,
    PeerUpdateError,
    InsufficientBalance,
    SpendingLimitExceeded,
    NoRootCell,
    InvalidOperation,
    NotFound,
}

export class SystemError extends Error {
    constructor(
        public errorType: SystemErrorType,
        public message: string
    ) {
        super(`${errorType}: ${message}`);
        this.name = 'SystemError';
    }
}

export enum CellErrorType {
    DataTooLarge = 'Cell data is too large',
    TooManyReferences = 'Too many references in cell',
    InvalidData = 'Invalid cell data',
    IoError = 'IO error',
}

export class CellError extends Error {
    constructor(
        public errorType: CellErrorType,
        public details?: string
    ) {
        super(details ? `${errorType}: ${details}` : errorType);
        this.name = 'CellError';
    }
}

export enum ZkProofErrorType {
    InvalidProof = 'Invalid proof',
    InvalidProofData = 'Invalid proof data',
    InvalidProofDataLength = 'Invalid proof data length',
    InvalidProofDataFormat = 'Invalid proof data format',
    InvalidProofDataSignature = 'Invalid proof data signature',
    InvalidProofDataPublicKey = 'Invalid proof data public key',
    InvalidProofDataHash = 'Invalid proof data hash',
}

export class ZkProofError extends Error {
    constructor(public errorType: ZkProofErrorType) {
        super(errorType);
        this.name = 'ZkProofError';
    }
}

export enum StateBocErrorType {
    TooManyCells = 'Too many cells',
    NoRoots = 'No roots',
    TotalSizeTooLarge = 'Total size too large',
    CellDataTooLarge = 'Cell data too large',
    TooManyReferences = 'Too many references',
    InvalidMerkleProof = 'Invalid Merkle proof',
    InvalidPrunedBranch = 'Invalid pruned branch',
    CycleDetected = 'Cycle detected',
    MaxDepthExceeded = 'Max depth exceeded',
}

export class StateBocError extends Error {
    constructor(
        public errorType: StateBocErrorType,
        public details?: string
    ) {
        super(details ? `${errorType}: ${details}` : errorType);
        this.name = 'StateBocError';
    }
}



export class ClientError extends Error {
    constructor(
        public errorType: ClientErrorType,
        public details?: string
    ) {
        super(details ? `${errorType.toString()}: ${details}` : errorType.toString());
        this.name = 'ClientError';
    }
}

export type Result<T> = T | Error;