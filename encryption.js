import crypto from 'crypto';
import config from './config';

const {secret_key, secret_iv, encryption_method } = config

if(!secret_key || !secret_iv || !encryption_method) {
    throw new Error('secretKey, secretIV, and ecnryptionMethod are required');
}

// Generate secret hash with crypto to use for encryption
const key = crypto
    .createHash('sha512')
    .update(secret_key)
    .digest('hex')
    .substring(0, 32);

const encryptionIV = crypto
    .createHash('sha512')
    .update(secret_iv)
    .digest('hex')
    .substring(0, 16);

    // Encrypt data
export function encryptDara(data) {
    const cipher = crypto.createCipheriv(encryption_method, key, encryptionIV)
    return Buffer.from(
        cipher.update(data, 'utf8', 'hex') + cipher.final('hex')
    ).toString('base64')// Encrypts data and converts to hex and base64
}

// Decrypt data
export function decryptData(encryptedData) {
    const buff = Buffer.from(encryptedData, 'base64');
    const decipher = crypto.createDecipheriv(encryption_method, key, encryptionIV)
    return (
        decipher.update(buff.toString('utf8'), 'hex', 'utf8') + 
        decipher.final('utf8')
    )
}