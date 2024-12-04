// src/types/cell_builder.ts

import { Result, SystemError, SystemErrorType } from '../error/client_errors';

// Represents a state initialization object.
export interface StateInit {
    // The code of the contract.
    code?: Uint8Array;
    // The data of the contract.
    data?: Uint8Array;
    // The library of the contract.
    library?: Uint8Array;
}

// Slice of a cell.
export interface Slice {
    start: number;
    end: number;
}

// Cell type.
export enum CellType {
    Ordinary,
    MerkleProof,
}

// Cell structure with necessary fields.
export interface Cell {
    nonce: number;
    balance: number;
    cell_type: CellType;
    data: Uint8Array;
    references: number[];
    slice?: Slice;
}

export class CellBuilder {
    private cells: Map<number, Cell>;
    private size: number;

    constructor() {
        this.cells = new Map();
        this.size = 0;
    }

    // Adds a cell to the builder.
    public addCell(cell: Cell): Result<void> {
        const cellId = cell.nonce;
        if (this.cells.has(cellId)) {
            return new SystemError(
                SystemErrorType.InvalidTransaction,
                "Cell already exists"
            );
        }
        this.size += cell.balance;
        this.cells.set(cellId, cell);
        return;
    }

    // Adds multiple cells to the builder.
    public addCells(cells: Cell[]): Result<void> {
        for (const cell of cells) {
            const result = this.addCell(cell);
            if (result instanceof SystemError) {
                return result;
            }
        }
        return;
    }

    // Builds the cells from the builder.
    public buildCells(): Result<Cell[]> {
        const cells: Cell[] = [];
        for (const [id, cell] of this.cells) {
            const newCell = { ...cell, nonce: id };
            cells.push(newCell);
        }
        return cells;
    }
}