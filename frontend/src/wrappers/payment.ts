import { STATEBOC, DAGBOC } from "@/wasm";
import { Result } from "@/wasm/index";

export interface IPaymentChannelContract {
    participants: [Uint8Array, Uint8Array];
    balances: [bigint, bigint];
    nonce: bigint;
    state_boc: STATEBOC;
    dag_boc: DAGBOC;
}

export class PaymentChannelContract implements IPaymentChannelContract {
    participants: [Uint8Array, Uint8Array];
    balances: [bigint, bigint];
    nonce: bigint;
    state_boc: STATEBOC;
    dag_boc: DAGBOC;

    constructor(alice: Uint8Array, bob: Uint8Array, deposit: bigint) {
      this.state_boc = new STATEBOC();
      this.dag_boc = new DAGBOC();

      this.participants = [alice, bob];
      this.balances = [deposit, deposit];
      this.nonce = 0n;
    }

    transfer(from: number, to: number, amount: bigint): Result {
      if (from >= 2 || to >= 2) {
        return { success: false, error: "Invalid participant index" };
      }

      if (this.balances[from] < amount) {
        return { success: false, error: "Insufficient balance" };
      }

      this.balances[from] -= amount;
      this.balances[to] += amount;
      this.nonce += 1n;

      return { success: true, error: undefined };
    }
    settle(): Result {
      try {
        return { success: true, error: undefined };
      } catch (e: unknown) {
        return { success: false, error: (e as Error).message };
      }
    }}