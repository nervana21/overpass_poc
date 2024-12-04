import { OpCode } from "@/types/ops";
import { STATEBOC, DAGBOC } from "@/wasm";

// Remove the import for Result from postcss
// import { Result } from "postcss";
export class StateContract {
    private merkleRoot: Uint8Array;
    private nonce: bigint;
    private stateBoc: STATEBOC;
    private dagBoc: DAGBOC;

    constructor() {
        this.merkleRoot = new Uint8Array(32);
        this.nonce = BigInt(0);
        this.stateBoc = new STATEBOC();
        this.dagBoc = new DAGBOC();
    }

    public async updateState(operation: any): Promise<Result<any>> {
        const opCode: OpCode = await operation.intoSerde();
        if (!opCode) {
            return Err(`Failed to deserialize operation`);
        }

        // Process operation
        try {
            this.dagBoc.processOpCode(opCode);
        } catch (e: unknown) {
            return Err((e as Error).toString());
        }

        // Update state
        const cells = this.dagBoc.getStateCells();
        this.stateBoc.setStateCells(cells);
        
        // Update merkle root
        this.merkleRoot = await this.stateBoc.computeHash();
        this.nonce += BigInt(1);

        return Ok("State updated successfully");
    }

    public async verifyState(stateBytes: Uint8Array): Promise<Result<boolean>> {
        let submittedState: STATEBOC;
        try {
            submittedState = await STATEBOC.deserialize(stateBytes);
        } catch (e: unknown) {
           return Err(false);
        }

        const currentHash = await this.stateBoc.computeHash();
        const submittedHash = await submittedState.computeHash();

        return Ok(currentHash.every((value, index) => value === submittedHash[index]));
    }
    public getMerkleRoot(): Uint8Array {
        return this.merkleRoot;
    }

    public getNonce(): bigint {
        return this.nonce;
    }
}

function Ok<T>(value: T): Result<T> {
    return { ok: true, value };
}

function Err<T>(error: T): Result<T> {
    return { ok: false, error };
}

type Result<T> =
    | {
          ok: true;
          value: T;
      }
    | {
          ok: false;
          error: T;
      };
