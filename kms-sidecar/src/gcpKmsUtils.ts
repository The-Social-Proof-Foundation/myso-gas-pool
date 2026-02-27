import { KeyManagementServiceClient } from '@google-cloud/kms';
import { Secp256r1PublicKey } from '@socialproof/myso/keypairs/secp256r1';
import { fromBase64, toBase64 } from '@socialproof/myso/utils';
import {
    toSerializedSignature,
    SIGNATURE_FLAG_TO_SCHEME,
    SignatureScheme,
    SignatureFlag,
    messageWithIntent,
} from '@socialproof/myso/cryptography';
import { blake2b } from '@noble/hashes/blake2.js';

// Compress uncompressed public key from raw bytes
function compressPublicKey(uncompressedKey: Uint8Array): Uint8Array {
    if (uncompressedKey.length !== 65) {
        throw new Error(`Unexpected length for an uncompressed public key: ${uncompressedKey.length}, expected 65`);
    }

    // Check if the first byte is 0x04 (uncompressed format)
    if (uncompressedKey[0] !== 0x04) {
        throw new Error(`Public key does not start with 0x04, starts with: 0x${uncompressedKey[0].toString(16).padStart(2, '0')}`);
    }

    // Extract X-coordinate (bytes 1-32)
    const xCoord = uncompressedKey.slice(1, 33);
    
    // Extract Y-coordinate (bytes 33-64) 
    const yCoord = uncompressedKey.slice(33, 65);
    
    // Determine parity byte for compressed format
    const yLastByte = yCoord[31]; // Last byte of Y coordinate
    const parityByte = yLastByte % 2 === 0 ? 0x02 : 0x03;

    return new Uint8Array([parityByte, ...xCoord]);
}

// Cache the GCP KMS client to avoid recreating it for every request
let gcpKmsClient: KeyManagementServiceClient | null = null;

// Cache public keys to avoid repeated API calls
const publicKeyCache = new Map<string, Secp256r1PublicKey>();

// Create Google Cloud KMS client (cached)
function createGCPKMSClient(): KeyManagementServiceClient {
    if (gcpKmsClient) {
        return gcpKmsClient;
    }

    console.log('Creating new GCP KMS client...');

    // Option 1: Base64 encoded JSON credentials (preferred for Railway)
    if (process.env.GOOGLE_APPLICATION_CREDENTIALS_JSON) {
        try {
            const credentialsJson = Buffer.from(process.env.GOOGLE_APPLICATION_CREDENTIALS_JSON, 'base64').toString('utf-8');
            const credentials = JSON.parse(credentialsJson);
            gcpKmsClient = new KeyManagementServiceClient({
                credentials: credentials,
                projectId: credentials.project_id
            });
        } catch (error) {
            console.error('Failed to parse base64 credentials:', error);
            throw new Error(`Invalid GOOGLE_APPLICATION_CREDENTIALS_JSON format: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }
    // Option 2: File path (for local development)
    else if (process.env.GOOGLE_APPLICATION_CREDENTIALS) {
        gcpKmsClient = new KeyManagementServiceClient({
            keyFilename: process.env.GOOGLE_APPLICATION_CREDENTIALS
        });
    }
    // Option 3: Default credentials (fallback)
    else {
        gcpKmsClient = new KeyManagementServiceClient();
    }

    console.log('GCP KMS client created and cached');
    return gcpKmsClient;
}

export async function getPublicKey(keyPath: string): Promise<Secp256r1PublicKey | undefined> {
    // Check cache first
    if (publicKeyCache.has(keyPath)) {
        return publicKeyCache.get(keyPath);
    }

    const client = createGCPKMSClient();

    try {
        const [publicKeyResponse] = await client.getPublicKey({ name: keyPath });
        
        if (!publicKeyResponse.pem) {
            throw new Error('No PEM public key found in response');
        }

        // Parse PEM format to get DER bytes
        const pemContent = publicKeyResponse.pem
            .replace('-----BEGIN PUBLIC KEY-----', '')
            .replace('-----END PUBLIC KEY-----', '')
            .replace(/\n/g, '');
        
        const publicKeyBytes = Buffer.from(pemContent, 'base64');
        
        // Find the BIT STRING (tag 0x03) containing the public key
        let bitStringIndex = -1;
        for (let i = 0; i < publicKeyBytes.length - 1; i++) {
            if (publicKeyBytes[i] === 0x03) {
                // Found BIT STRING tag, next byte should be length
                const length = publicKeyBytes[i + 1];
                if (length === 0x42) { // 66 bytes for SECP256K1 (1 + 1 + 64)
                    bitStringIndex = i;
                    break;
                }
            }
        }
        
        if (bitStringIndex === -1) {
            throw new Error('Could not find BIT STRING with expected length in DER structure');
        }
        
        // Extract the bit string content
        // Skip: tag(1) + length(1) + unused_bits(1) = 3 bytes
        const publicKeyStart = bitStringIndex + 3;
        const publicKeyEnd = publicKeyStart + 65; // 1 + 32 + 32 bytes
        
        if (publicKeyEnd > publicKeyBytes.length) {
            throw new Error('DER structure too short for public key data');
        }
        
        const uncompressedKey = publicKeyBytes.slice(publicKeyStart, publicKeyEnd);
        const compressedKey = compressPublicKey(uncompressedKey);
        const mysPublicKey = new Secp256r1PublicKey(compressedKey);

        // Cache the public key
        publicKeyCache.set(keyPath, mysPublicKey);

        console.log(`Public key retrieved and cached for ${keyPath}`);
        return mysPublicKey;
        
    } catch (error) {
        console.error('Error retrieving public key from GCP KMS:', error instanceof Error ? error.message : error);
        return undefined;
    }
}

// Convert DER signature to concatenated format for MySocial
function getConcatenatedSignature(signature: Uint8Array): Uint8Array {
    // DER signature format for ECDSA:
    // 30 [total-length] 02 [R-length] [R] 02 [S-length] [S]
    
    if (signature[0] !== 0x30) {
        throw new Error('Invalid DER signature: does not start with SEQUENCE tag');
    }
    
    let offset = 2; // Skip SEQUENCE tag and length
    
    // Parse R value
    if (signature[offset] !== 0x02) {
        throw new Error('Invalid DER signature: R value does not start with INTEGER tag');
    }
    
    const rLength = signature[offset + 1];
    offset += 2; // Skip INTEGER tag and length
    
    let rBytes = signature.slice(offset, offset + rLength);
    offset += rLength;
    
    // Remove leading zero if present (DER encoding adds it for positive numbers)
    if (rBytes[0] === 0x00 && rBytes.length > 32) {
        rBytes = rBytes.slice(1);
    }
    
    // Pad to 32 bytes if needed
    if (rBytes.length < 32) {
        const padded = new Uint8Array(32);
        padded.set(rBytes, 32 - rBytes.length);
        rBytes = padded;
    }
    
    // Parse S value
    if (signature[offset] !== 0x02) {
        throw new Error('Invalid DER signature: S value does not start with INTEGER tag');
    }
    
    const sLength = signature[offset + 1];
    offset += 2; // Skip INTEGER tag and length
    
    let sBytes = signature.slice(offset, offset + sLength);
    
    // Remove leading zero if present
    if (sBytes[0] === 0x00 && sBytes.length > 32) {
        sBytes = sBytes.slice(1);
    }
    
    // Pad to 32 bytes if needed
    if (sBytes.length < 32) {
        const padded = new Uint8Array(32);
        padded.set(sBytes, 32 - sBytes.length);
        sBytes = padded;
    }
    
    // CRITICAL FIX: Normalize s to low-s value
    // For secp256r1 (P-256), the curve order n is:
    // n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    const SECP256R1_N = BigInt('0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551');
    const SECP256R1_N_HALF = SECP256R1_N / 2n;
    
    // Convert s to BigInt
    let sBigInt = BigInt('0x' + Array.from(sBytes).map(b => b.toString(16).padStart(2, '0')).join(''));
    
    // If s > n/2, replace with n - s (this makes it "low")
    if (sBigInt > SECP256R1_N_HALF) {
        console.log('Normalizing high-s signature to low-s');
        sBigInt = SECP256R1_N - sBigInt;
        
        // Convert back to bytes
        const sHex = sBigInt.toString(16).padStart(64, '0');
        sBytes = new Uint8Array(32);
        for (let i = 0; i < 32; i++) {
            sBytes[i] = parseInt(sHex.substr(i * 2, 2), 16);
        }
    }
    
    // For P-256 (Secp256r1), just concatenate r and s directly
    // Both r and s should be 32 bytes each for a total of 64 bytes
    const concatenated = new Uint8Array(64);
    concatenated.set(rBytes, 0);
    concatenated.set(sBytes, 32);
    
    return concatenated;
}

// Create serialized signature for MySocial
async function getSerializedSignature(
    signature: Uint8Array,
    mysPublicKey: Secp256r1PublicKey
): Promise<string> {
    // MySocial signature format: [flag][signature][pubkey]
    // Secp256r1: flag = 0x02, signature = 64 bytes, pubkey = 33 bytes
    const flag = 0x02;
    const pubkeyBytes = mysPublicKey.toRawBytes();

    const fullSignature = new Uint8Array(1 + signature.length + pubkeyBytes.length);
    fullSignature[0] = flag;
    fullSignature.set(signature, 1);
    fullSignature.set(pubkeyBytes, 1 + signature.length);

    return toBase64(fullSignature);
}

export async function signAndVerify(txBytes: Uint8Array, keyPath: string): Promise<string | undefined> {
    const startTime = Date.now();

    try {
        const client = createGCPKMSClient();

        // Add intent message to transaction bytes
        const intentMessage = messageWithIntent('TransactionData' as any, txBytes);

        // Create digest using blake2b hash
        const digest = blake2b(intentMessage, { dkLen: 32 });

        // Sign the digest using Google Cloud KMS with retry logic
        const maxRetries = 3;
        let lastError: Error | null = null;

        for (let attempt = 1; attempt <= maxRetries; attempt++) {
            try {
                const signPromise = client.asymmetricSign({
                    name: keyPath,
                    data: digest,
                });

                // Add timeout to prevent hanging
                const timeoutPromise = new Promise((_, reject) => {
                    setTimeout(() => reject(new Error('GCP KMS signing timeout after 15 seconds')), 15000);
                });

                console.log(`GCP KMS signing attempt ${attempt} started...`);
                const [signResponse] = await Promise.race([signPromise, timeoutPromise]) as any;
                console.log(`GCP KMS signing attempt ${attempt} completed`);

                if (!signResponse.signature) {
                    throw new Error('No signature returned from KMS');
                }

                const signature = signResponse.signature instanceof Uint8Array
                    ? signResponse.signature
                    : new Uint8Array(Buffer.from(signResponse.signature as string, 'base64'));

                // Get the public key (cached, should be fast)
                const originalPublicKey = await getPublicKey(keyPath);
                if (!originalPublicKey) {
                    throw new Error('Could not retrieve public key');
                }

                // Convert DER signature to concatenated format
                const concatenatedSignature = getConcatenatedSignature(signature);

                // Create serialized signature for MySocial
                const serializedSignature = await getSerializedSignature(
                    concatenatedSignature,
                    originalPublicKey
                );

                console.log(`Signature created successfully in ${Date.now() - startTime}ms`);
                return serializedSignature;

            } catch (error) {
                lastError = error as Error;
                console.error(`GCP KMS signing attempt ${attempt} failed:`, error instanceof Error ? error.message : error);

                if (attempt < maxRetries) {
                    // Exponential backoff with jitter
                    const baseDelay = 2000; // 2 seconds (increased for GCP KMS)
                    const maxDelay = 10000; // 10 seconds
                    const exponentialDelay = Math.min(baseDelay * Math.pow(2, attempt - 1), maxDelay);
                    const jitter = Math.random() * 2000; // Up to 2 seconds jitter
                    const delay = exponentialDelay + jitter;

                    console.warn(`KMS signing attempt ${attempt} failed, retrying in ${Math.round(delay)}ms`);
                    await new Promise(resolve => setTimeout(resolve, delay));
                }
            }
        }

        // All retries failed
        console.error(`All ${maxRetries} KMS signing attempts failed. Last error:`, lastError?.message);
        return undefined;

    } catch (error) {
        console.error('Critical error in signAndVerify:', error instanceof Error ? error.message : error);
        return undefined;
    }
} 