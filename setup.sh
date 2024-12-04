#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_header() {
    echo -e "\n${YELLOW}=== $1 ===${NC}\n"
}

print_status() {
    echo -e "${BLUE}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_error() {
    echo -e "${RED}[-]${NC} $1"
}

create_demo_components() {
    print_header "Creating Demo Components"

    # Create demo directory
    mkdir -p src/demo
    
    # Create demonstration wallet setup
    cat > src/demo/wallet-demo.ts << 'EOL'
import { OverpassChannel } from '@overpass/client';

export async function demonstrateWallet() {
    console.log("\n🔐 Demonstrating Wallet Creation & Management");
    
    const channel = new OverpassChannel({
        network: 'testnet',
        initial_balance: 1_000_000,
        security_bits: 256
    });

    // Create two wallets for demonstration
    console.log("\nCreating Alice's wallet...");
    const aliceWallet = await channel.createWallet('alice-passphrase');
    console.log("Alice's wallet:", aliceWallet);

    console.log("\nCreating Bob's wallet...");
    const bobWallet = await channel.createWallet('bob-passphrase');
    console.log("Bob's wallet:", bobWallet);

    return { aliceWallet, bobWallet, channel };
}
EOL

    # Create payment channel demo
    cat > src/demo/payment-channel-demo.ts << 'EOL'
import { OverpassChannel } from '@overpass/client';

export async function demonstratePaymentChannel(channel: OverpassChannel) {
    console.log("\n⚡ Demonstrating Payment Channel Operations");
    
    // Simulate a payment channel between Alice and Bob
    console.log("\nInitiating payment channel...");
    const channelState = await channel.transfer(50_000);
    console.log("Channel state:", channelState);

    // Demonstrate multiple transfers
    const transfers = [10000, 20000, 5000];
    console.log("\nPerforming multiple transfers...");
    
    for (const amount of transfers) {
        console.log(`\nTransferring ${amount} satoshis...`);
        const result = await channel.transfer(amount);
        console.log("Transfer result:", result);
    }
}
EOL

    # Create HTLC demo
    cat > src/demo/htlc-demo.ts << 'EOL'
import { OverpassChannel } from '@overpass/client';
import { randomBytes, createHash } from 'crypto';

export async function demonstrateHTLC(channel: OverpassChannel) {
    console.log("\n🔒 Demonstrating Hash Time-Locked Contract (HTLC)");
    
    // Generate random preimage and hash
    const preimage = randomBytes(32);
    const hash = createHash('sha256').update(preimage).digest();
    
    console.log("\nSetting up HTLC...");
    console.log("Hash:", hash.toString('hex'));
    
    // Create HTLC
    const htlcAmount = 25000;
    const timeoutBlocks = 144; // 24 hours in blocks
    
    const htlc = await channel.createHTLC({
        amount: htlcAmount,
        hashLock: hash,
        timeoutBlocks
    });
    
    console.log("\nHTLC created:", htlc);
    
    // Demonstrate HTLC resolution
    console.log("\nResolving HTLC with preimage...");
    const resolution = await channel.resolveHTLC(htlc.id, preimage);
    console.log("HTLC resolution:", resolution);
}
EOL

    # Create main demo runner
    cat > src/demo/run-demo.ts << 'EOL'
import { demonstrateWallet } from './wallet-demo';
import { demonstratePaymentChannel } from './payment-channel-demo';
import { demonstrateHTLC } from './htlc-demo';

async function runFullDemo() {
    console.log("🚀 Starting Overpass Demo");
    
    try {
        // Initialize wallets and channel
        const { channel } = await demonstrateWallet();
        
        // Demonstrate payment channel operations
        await demonstratePaymentChannel(channel);
        
        // Demonstrate HTLC
        await demonstrateHTLC(channel);
        
        console.log("\n✨ Demo completed successfully!");
    } catch (error) {
        console.error("\n❌ Demo failed:", error);
        process.exit(1);
    }
}

runFullDemo().catch(console.error);
EOL

    print_success "Demo components created"
}

update_package_scripts() {
    print_header "Updating package.json scripts"
    
    npm pkg set scripts.demo="ts-node src/demo/run-demo.ts"
    npm pkg set scripts."demo:wallet"="ts-node src/demo/wallet-demo.ts"
    npm pkg set scripts."demo:payment"="ts-node src/demo/payment-channel-demo.ts"
    npm pkg set scripts."demo:htlc"="ts-node src/demo/htlc-demo.ts"
    
    print_success "npm scripts updated"
}


main() {
    print_header "Setting up Overpass Demo Environment"
    
    create_demo_components
    update_package_scripts
    create_readme
    
    echo -e "\n${GREEN}Demo setup complete!${NC}"
    echo -e "\nTo run the demo:"
    echo -e "  ${BLUE}npm run demo${NC}         # Run full demo"
    echo -e "  ${BLUE}npm run demo:wallet${NC}  # Run wallet demo"
    echo -e "  ${BLUE}npm run demo:payment${NC} # Run payment channel demo"
    echo -e "  ${BLUE}npm run demo:htlc${NC}    # Run HTLC demo"
}

main
