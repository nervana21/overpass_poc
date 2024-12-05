// src/wasm/index.ts - Main WASM exports and types
// src/wasm/index.ts
export * from './types';
export * from './bridge';
export interface ChannelConfig {
    network: 'mainnet' | 'testnet' | 'regtest';
    initial_balance: number;
    security_bits: number;
  }
  
  export type Result = {
    success: boolean;
    data?: any;
    error?: string;
  };
  
  export interface StateUpdate {
    nonce: number;
    balance: bigint;
    merkle_root: Uint8Array;
    cell_hash: Uint8Array;
  }
  
  let wasmModule: any = null;
  
  export async function initWasm() {
    if (!wasmModule) {
      const wasm = await import('@/pkg/overpass_wasm');
      if (typeof wasm.init === 'function') {
        await wasm.init();
      }
      wasmModule = wasm;
    }
    return wasmModule;
  }
  
  export class Channel {
    private channel: any;
  
    constructor(config: ChannelConfig) {
      if (!wasmModule) {
        throw new Error('WASM not initialized. Call initWasm() first');
      }
      this.channel = new wasmModule.Channel(JSON.stringify(config));
    }
  
    async updateState(amount: bigint, data: Uint8Array): Promise<StateUpdate> {
      return await this.channel.update_state(amount, data);
    }
  
    async finalize(): Promise<Uint8Array> {
      return await this.channel.finalize_state();
    }
  
    destroy() {
      if (this.channel) {
        this.channel.free();
      }
    }
  }
  
  // src/lib/channel.ts - Channel manager implementation 
  import { initWasm as initWasmModule } from '@/wasm';
  
  export class ChannelManager {
    private initialized = false;
  
    async initialize(): Promise<void> {
      if (!this.initialized) {
        await initWasmModule();
        this.initialized = true;
      }
    }
  
    // ... rest of implementation
  }