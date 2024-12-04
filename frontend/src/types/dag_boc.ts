// Types for DAG BOC

interface DagCell {
    balance: number;
    nonce: number;
}

interface DAGBOCData {
    dagCells: Uint8Array[];
    references: [number, number][];
    roots: Uint8Array[];
    hash?: Uint8Array;
    stateMapping: Map<Uint8Array, number>;
}

class DAGBOC implements DAGBOCData {
    readonly dagCells: Uint8Array[];
    readonly references: [number, number][];
    readonly roots: Uint8Array[];
    hash?: Uint8Array;
    readonly stateMapping: Map<Uint8Array, number>;

    constructor() {
        this.dagCells = [];
        this.references = [];
        this.roots = [];
        this.hash = undefined;
        this.stateMapping = new Map();
    }

    getStateCells(): ReadonlyArray<Uint8Array> {
        return [...this.dagCells];
    }

    addCell(cellData: Readonly<Uint8Array>): number {
        const id = this.dagCells.length;
        this.dagCells.push(new Uint8Array(cellData));
        return id;
    }

    updateStateMapping(key: Readonly<Uint8Array>, value: number): void {
        this.stateMapping.set(new Uint8Array(key), value);
    }

    processOpCode(opCode: Readonly<any>): void {
        switch (opCode.type) {
            case 'Add':
                this.addCell(opCode.cell);
                break;
            case 'SetCode': {
                const codeIndex = this.dagCells.findIndex(c => arrayEquals(c, opCode.code));
                if (codeIndex !== -1) {
                    this.dagCells[codeIndex] = new Uint8Array(opCode.newCode);
                } else {
                    throw new Error('Code not found');
                }
                break;
            }
            case 'SetData': {
                const cellIndex = this.dagCells.findIndex(c => arrayEquals(c, opCode.cell));
                if (cellIndex !== -1) {
                    this.dagCells[cellIndex] = new Uint8Array(opCode.newData);
                } else {
                    throw new Error('Cell not found');
                }
                break;
            }
            case 'AddReference':
                this.references.push([opCode.from, opCode.to]);
                break;
            case 'SetRoot':
                if (this.dagCells[opCode.index]) {
                    this.roots.push(new Uint8Array(this.dagCells[opCode.index]));
                } else {
                    throw new Error('Index out of bounds');
                }
                break;
            case 'Remove': {
                const removeIndex = this.dagCells.findIndex(c => arrayEquals(c, opCode.cell));
                if (removeIndex !== -1) {
                    this.dagCells.splice(removeIndex, 1);
                } else {
                    throw new Error('Cell not found');
                }
                break;
            }
            case 'RemoveReference': {
                const refIndex = this.references.findIndex(([f, t]) => f === opCode.from && t === opCode.to);
                if (refIndex !== -1) {
                    this.references.splice(refIndex, 1);
                } else {
                    throw new Error('Reference not found');
                }
                break;
            }
            default:
                throw new Error('Unsupported operation');
        }
    }

    serialize(): Uint8Array {
        return new TextEncoder().encode(JSON.stringify({
            dagCells: Array.from(this.dagCells),
            references: this.references,
            roots: Array.from(this.roots),
            hash: this.hash,
            stateMapping: Array.from(this.stateMapping.entries())
        }));
    }

    static deserialize(data: Readonly<Uint8Array>): DAGBOC {
        const text = new TextDecoder().decode(data);
        const obj = JSON.parse(text);
        const dagBoc = new DAGBOC();
        dagBoc.dagCells.push(...obj.dagCells.map((cell: Uint8Array) => new Uint8Array(cell)));
        dagBoc.references.push(...obj.references);
        dagBoc.roots.push(...obj.roots.map((root: Uint8Array) => new Uint8Array(root)));
        dagBoc.hash = obj.hash ? new Uint8Array(obj.hash) : undefined;
        obj.stateMapping.forEach(([key, value]: [Uint8Array, number]) => {
            dagBoc.stateMapping.set(new Uint8Array(key), value);
        });
        return dagBoc;
    }

    async computeHash(): Promise<Uint8Array> {
        const data = new Uint8Array([
            ...this.dagCells.flatMap(cell => [...cell]),
            ...this.references.flatMap(([from, to]) => [...new Uint32Array([from, to])]),
            ...this.roots.flatMap(root => [...root])
        ]);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        return new Uint8Array(hashBuffer);
    }

    clone(): DAGBOC {
        const cloned = new DAGBOC();
        cloned.dagCells.push(...this.dagCells.map(cell => new Uint8Array(cell)));
        cloned.references.push(...this.references);
        cloned.roots.push(...this.roots.map(root => new Uint8Array(root)));
        cloned.hash = this.hash ? new Uint8Array(this.hash) : undefined;
        this.stateMapping.forEach((value, key) => {
            cloned.stateMapping.set(new Uint8Array(key), value);
        });
        return cloned;
    }

    withDagCells(dagCells: ReadonlyArray<Uint8Array>): DAGBOC {
        const cloned = this.clone();
        cloned.dagCells.length = 0;
        cloned.dagCells.push(...dagCells.map(cell => new Uint8Array(cell)));
        return cloned;
    }

    withReferences(references: ReadonlyArray<[number, number]>): DAGBOC {
        const cloned = this.clone();
        cloned.references.length = 0;
        cloned.references.push(...references);
        return cloned;
    }

    withRoots(roots: ReadonlyArray<Uint8Array>): DAGBOC {
        const cloned = this.clone();
        cloned.roots.length = 0;
        cloned.roots.push(...roots.map(root => new Uint8Array(root)));
        return cloned;
    }
}

function arrayEquals(a: Readonly<Uint8Array>, b: Readonly<Uint8Array>): boolean {
    return a.length === b.length && a.every((val, index) => val === b[index]);
}