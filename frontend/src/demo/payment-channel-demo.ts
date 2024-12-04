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
