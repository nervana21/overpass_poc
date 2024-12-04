import { WalletState } from "../types";

export class WalletWrapper {
  private contract: any;

  constructor(contract: any) {
      this.contract = contract;
  }

  async createWallet(config: any): Promise<WalletState> {
      const state = await this.contract.create_wallet(config);
      return state;
  }
  async updateState(config: any): Promise<WalletState> {
      const state = await this.contract.update_state(config);
      return state;
  }
  async transfer(config: any): Promise<WalletState> {
      const state = await this.contract.transfer(config);
      return state;
  }
  async getState(): Promise<WalletState> {
      const state = await this.contract.get_state();
      return state;
  }
  async verifyState(config: any): Promise<boolean> {
      const state = await this.contract.verify_state(config);
      return state;
  }
}