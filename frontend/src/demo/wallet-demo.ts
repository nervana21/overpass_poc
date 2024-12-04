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
