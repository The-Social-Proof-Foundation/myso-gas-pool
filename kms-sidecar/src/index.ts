import 'dotenv/config';
import express, { Request, Response } from 'express';
import { fromBase64 } from '@socialproof/myso/utils';
import { getPublicKey, signAndVerify } from './gcpKmsUtils.js';

async function main() {
    const app = express();
    app.use(express.json());
    
    const port = process.env.PORT || 3000;
    
    // Environment variables for Google Cloud KMS
    const PROJECT_ID = process.env.GOOGLE_CLOUD_PROJECT_ID;
    const LOCATION = process.env.KMS_LOCATION || 'us-central1';
    const KEYRING = process.env.KMS_KEYRING || 'myso-gas-pool-keyring';
    const KEY_NAME = process.env.KMS_KEY_NAME || 'myso-sponsor-key';
    
    const keyPath = `projects/${PROJECT_ID}/locations/${LOCATION}/keyRings/${KEYRING}/cryptoKeys/${KEY_NAME}/cryptoKeyVersions/1`;
    
    // Health check endpoint
    app.get('/', (req: Request, res: Response) => {
        res.json({ status: 'healthy', service: 'MySocial Gas Pool GCP KMS Sidecar' });
    });
    
    // Get public key and address - matches interface expected by SidecarTxSigner
    app.get('/get-pubkey-address', async (req: Request, res: Response) => {
        try {
            if (!PROJECT_ID) {
                console.error('GOOGLE_CLOUD_PROJECT_ID environment variable is required');
                return res.status(500).json({
                    error: 'Configuration error',
                    details: 'GOOGLE_CLOUD_PROJECT_ID environment variable is required'
                });
            }

            const publicKey = await getPublicKey(keyPath);

            if (!publicKey) {
                console.error('Failed to retrieve public key from GCP KMS');
                return res.status(500).json({
                    error: 'Failed to get public key',
                    details: 'Check GCP KMS configuration and permissions'
                });
            }

            const mysPubkeyAddress = publicKey.toMySoAddress();
            res.json({ mysPubkeyAddress });
        } catch (error) {
            console.error('Error in get-pubkey-address endpoint:', error instanceof Error ? error.message : error);
            res.status(500).json({
                error: 'Internal server error'
            });
        }
    });
    
    // Sign transaction - matches interface expected by SidecarTxSigner
    app.post('/sign-transaction', async (req: Request, res: Response) => {
        try {
            const { txBytes } = req.body;

            if (!txBytes) {
                return res.status(400).json({ error: 'Missing transaction bytes' });
            }

            const txBytesArray = fromBase64(txBytes);
            const signature = await signAndVerify(txBytesArray, keyPath);

            if (!signature) {
                console.error('Failed to create signature for transaction');
                return res.status(500).json({ error: 'Failed to sign transaction' });
            }

            res.json({ signature });
        } catch (error) {
            console.error('Error in sign-transaction endpoint:', error instanceof Error ? error.message : error);
            res.status(500).json({ error: 'Internal server error' });
        }
    });
    
    app.listen(port, () => {
        console.log(`GCP KMS Sidecar listening on port ${port}`);
    });
}

main().catch(console.error); 