export enum OpCode {
    Add = 0x01,
    Remove = 0x02,
    Update = 0x03,
    SetCode = 0x04,
    SetData = 0x05,
    SetLibraries = 0x06,
    SetVersion = 0x07,
    Deploy = 0x01,
    Call = 0x02,
    UpdateState = 0x03,
    AddReference = 0x04,
    RemoveReference = 0x05,
    SetRoot = 0x06,
    Custom = 0xFF
}

export enum ContractOpCode {
    CreatePayment = 0xA0,
    UpdateState = 0xA1,
    FinalizeState = 0xA2,
    DisputeState = 0xA3,
    InitChannel = 0xA4,
}

export enum ChannelOpCode {
    CreatePayment = 0xA0,
    UpdateState = 0xA1,
    FinalizeState = 0xA2,
    DisputeState = 0xA3,
    InitChannel = 0xA4,
}

export enum WalletOpCode {
    CreateChannel = 0x70,
    UpdateChannel = 0x71,
    CloseChannel = 0x72,
    UpdateWalletState = 0x90,
    CreateTransaction = 0xC0,
    ProcessTransaction = 0xC2,
}

export enum IntermediateOpCode {
    RequestChannelOpen = 0x20,
    RequestChannelClose = 0x22,
    RequestManualRebalance = 0x24,
    RegisterWallet = 0x30,
    UpdateWalletRoot = 0x31,
    StoreWalletState = 0x43,
}

export interface Operation {
    opCode: OpCode;
    validate(): boolean;
    execute(): Promise<void>;
}

export interface OperationResult {
    success: boolean;
    opCode: OpCode;
    message?: string;
    data?: Uint8Array;
}

export type OpCodePayload = {
    Add: { cell: Uint8Array };
    Remove: { cell: Uint8Array };
    Update: { cell: Uint8Array };
    SetCode: {
        code: Uint8Array;
        newCode: Uint8Array;
        newData: Uint8Array;
        newLibraries: Uint8Array;
        newVersion: number;
    };
    SetData: {
        cell: Uint8Array;
        newData: Uint8Array;
    };
    SetLibraries: {
        cell: Uint8Array;
        newLibraries: Uint8Array;
    };
    SetVersion: {
        cell: Uint8Array;
        newVersion: number;
    };
    Deploy: {
        code: Uint8Array;
        initialState: Uint8Array;
    };
    Call: {
        contractId: number;
        function: Uint8Array;
        args: Uint8Array;
    };
    UpdateState: {
        key: Uint8Array;
        value: Uint8Array;
    };
    AddReference: {
        from: number;
        to: number;
    };
    RemoveReference: {
        from: number;
        to: number;
    };
    SetRoot: {
        index: number;
    };
}