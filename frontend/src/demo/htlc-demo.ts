
// Instead of importing from 'crypto', use the browser's crypto API
const getRandomBytes = (length: number): Uint8Array => {
    return crypto.getRandomValues(new Uint8Array(length));
};

const createHash = async (message: string): Promise<string> => {
    const msgBuffer = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
};

export async function demonstrateHTLC(channel: OverpassChannel): Promise<void> {
    try {
        console.log("\n🔒 Demonstrating Hash Time-Locked Contract (HTLC)");

        // Generate a random preimage and compute its hash
        const preimage = getRandomBytes(32); // Generates a 32-byte preimage
        const hash = await createHash(new TextDecoder().decode(preimage));

        console.log("\nSetting up HTLC...");
        console.log("Hash:", hash);

        // Create HTLC with specified amount and timeout
        const htlcAmount = 25000; // Amount in satoshis or your channel's unit
        const timeoutBlocks = 144; // 24 hours in Bitcoin blocks

        const htlc = await channel.createHTLC({
            amount: htlcAmount,
            hashLock: hash,
            timeoutBlocks,
        });

        console.log("\nHTLC created:", htlc);

        // Demonstrate HTLC resolution
        console.log("\nResolving HTLC with preimage...");
        const resolution = await channel.resolveHTLC(htlc.id, preimage);

        console.log("HTLC resolution:", resolution);
    } catch (error) {
        console.error("\n❌ Error during HTLC demonstration:", error);
    }
}