// utils/urlEncryption.js
// Simple URL parameter encryption using base64 + XOR with a secret key

const crypto = require('crypto');

const SECRET_KEY = process.env.ENCRYPTION_KEY || '349e3756622fd5efb1aa43f50f7f26e74d6ad89da2baec0712fd872dc4fd7883';

// Encrypt parameters
function encryptUrlParams(userId, guildId) {
  try {
    const data = JSON.stringify({ userId, guildId });
    
    // Create hash of secret key for consistent XOR
    const keyHash = crypto.createHash('sha256').update(SECRET_KEY).digest();
    
    // Convert data to buffer
    const dataBuffer = Buffer.from(data, 'utf8');
    
    // XOR with key
    const encrypted = Buffer.alloc(dataBuffer.length);
    for (let i = 0; i < dataBuffer.length; i++) {
      encrypted[i] = dataBuffer[i] ^ keyHash[i % keyHash.length];
    }
    
    // Base64 encode
    const token = encrypted.toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
    
    return token;
  } catch (error) {
    console.error('Encryption error:', error);
    return null;
  }
}

// Decrypt parameters
function decryptUrlParams(token) {
  try {
    // Restore base64 padding
    let padded = token.replace(/-/g, '+').replace(/_/g, '/');
    while (padded.length % 4) padded += '=';
    
    // Base64 decode
    const encrypted = Buffer.from(padded, 'base64');
    
    // Create hash of secret key (same as encryption)
    const keyHash = crypto.createHash('sha256').update(SECRET_KEY).digest();
    
    // XOR with key to decrypt
    const decrypted = Buffer.alloc(encrypted.length);
    for (let i = 0; i < encrypted.length; i++) {
      decrypted[i] = encrypted[i] ^ keyHash[i % keyHash.length];
    }
    
    // Parse JSON
    const data = JSON.parse(decrypted.toString('utf8'));
    return data;
  } catch (error) {
    console.error('Decryption error:', error);
    return null;
  }
}

module.exports = {
  encryptUrlParams,
  decryptUrlParams,
};
