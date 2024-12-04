import { SystemError, SystemErrorType } from '../error/client_errors';

// Represents a state init object.
export interface StateInit {
    // The code of the contract.
    code?: Uint8Array;
    // The data of the contract.
    data?: Uint8Array;
    // The library of the contract.
    library?: Uint8Array;
}

// Slice of a cell
export interface Slice {
    start: number;
    end: number;
}

// Cell type
export enum CellType {
    Ordinary,
    MerkleProof,
}

// Cell
export interface Cell {
    cellType: CellType;
    data: Uint8Array;
    references: number[];
    slice?: Slice;
}

// State BOC
export interface StateBOC {
    stateCells: Cell[];
    references: Uint8Array[];
    roots: Uint8Array[];
    hash?: Uint8Array;
}

export class StateBOCImpl implements StateBOC {
    stateCells: Cell[] = [];
    references: Uint8Array[] = [];
    roots: Uint8Array[] = [];
    hash?: Uint8Array;

    constructor() {
        this.stateCells = [];
        this.references = [];
        this.roots = [];
        this.hash = undefined;
    }

    addCell(cell: Cell): void {
        this.stateCells.push(cell);
    }
}

export class STATEBOC {
    private stateCells: Uint8Array[];
    private references: Uint8Array[];
    private roots: Uint8Array[];
    private hashValue?: Uint8Array;

    constructor() {
        this.stateCells = [];
        this.references = [];
        this.roots = [];
        this.hashValue = undefined;
    }

    withHash(hash: Uint8Array): STATEBOC {
        this.hashValue = hash;
        return this;
    }

    withStateCells(stateCells: Uint8Array[]): STATEBOC {
        this.stateCells = stateCells;
        return this;
    }

    withReferences(references: Uint8Array[]): STATEBOC {
        this.references = references;
        return this;
    }

    withRoots(roots: Uint8Array[]): STATEBOC {
        this.roots = roots;
        return this;
    }

    getHash(): Uint8Array {
        return this.hashValue || new Uint8Array(32);
    }

    getStateCells(): Uint8Array[] {
        return this.stateCells;
    }

    getReferences(): Uint8Array[] {
        return this.references;
    }

    getRoots(): Uint8Array[] {
        return this.roots;
    }

    setHash(hash: Uint8Array): void {
        this.hashValue = hash;
    }

    setStateCells(stateCells: Uint8Array[]): void {
        this.stateCells = stateCells;
    }

    setReferences(references: Uint8Array[]): void {
        this.references = references;
    }

    setRoots(roots: Uint8Array[]): void {
        this.roots = roots;
    }

    serializeToVec(): Promise<Uint8Array> {
        return new Promise((resolve, reject) => {
            try {
                const data = {
                    stateCells: this.stateCells,
                    references: this.references,
                    roots: this.roots,
                    hash: this.hashValue
                };
                const jsonString = JSON.stringify(data);
                const encoder = new TextEncoder();
                resolve(encoder.encode(jsonString));
            } catch (e: unknown) {
                reject(new SystemError(SystemErrorType.SerializationError, (e as Error).message));
            }
        });
    }

    static deserialize(data: Uint8Array): Promise<STATEBOC> {
        return new Promise((resolve, reject) => {
            try {
                const decoder = new TextDecoder();
                const jsonString = decoder.decode(data);
                const parsed = JSON.parse(jsonString);
                const stateBoc = new STATEBOC()
                    .withStateCells(parsed.stateCells)
                    .withReferences(parsed.references)
                    .withRoots(parsed.roots);
                if (parsed.hash) {
                    stateBoc.withHash(parsed.hash);
                }
                resolve(stateBoc);
            } catch (e: unknown) {
                reject(new SystemError(SystemErrorType.SerializationError, (e as Error).message));
            }
        });
    }

    async computeHash(): Promise<Uint8Array> {
        const data = new Uint8Array([
            ...this.stateCells.reduce((acc: number[], curr) => [...acc, ...Array.from(curr)], []),
            ...this.references.reduce((acc: number[], curr) => [...acc, ...Array.from(curr)], []),
            ...this.roots.reduce((acc: number[], curr) => [...acc, ...Array.from(curr)], [])
        ]);
        
        // Web Crypto API for SHA-256
        const buffer = await crypto.subtle.digest('SHA-256', data);
        return new Uint8Array(buffer);
    }
}