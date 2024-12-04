// ./wrappers/htlc.ts

import { ChannelConfig } from "../types";

// This module provides a wrapper for the HTLC contract

interface HTLCConfig {
// Add necessary properties for HTLCConfig
}

interface HTLCState {
// Add necessary properties for HTLCState
}

export class HTLCWrapper {
  private contract: any;

  constructor(contract: any) {
      this.contract = contract;
  }

  async createHTLC(config: HTLCConfig): Promise<HTLCState> {
      const state = await this.contract.create_htlc_state(config);
      return state;
  }

  async updateHTLC(config: HTLCConfig): Promise<HTLCState> {
      const state = await this.contract.update_state(config);
      return state;
  }

  async finalizeHTLC(config: HTLCConfig): Promise<HTLCState> {
      const state = await this.contract.finalize_state(config);
      return state;
  }

  async disputeHTLC(config: HTLCConfig): Promise<HTLCState> {
      const state = await this.contract.dispute_state(config);
      return state;
  }

  async initChannel(config: ChannelConfig): Promise<void> {
      await this.contract.init_channel(config);
  }
}
