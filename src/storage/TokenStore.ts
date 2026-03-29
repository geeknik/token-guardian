import crypto from 'crypto';
import { TokenConfig } from '../interfaces/TokenConfig';

/**
 * Stored token data structure
 */
interface StoredToken {
  value: string;
  config: TokenConfig;
  expiry: Date | null;
  created: Date;
  lastUsed: Date | null;
}

/**
/**
 * Audit log entry structure
 */
export interface AuditLogEntry {
  tokenName: string;
  action: string;
  timestamp: Date;
  details?: {
    configType?: string;
    hasNewExpiry?: boolean;
    [key: string]: unknown;
  };
}
/**
 * Secure storage for protected tokens
 */
export class TokenStore {
  private tokens: Map<string, StoredToken>;
  private encryptionKey: string;
  private auditLog: AuditLogEntry[];

  /**
   * Creates a new TokenStore
   * @param encryptionKey Key used for encrypting tokens
   */
  constructor(encryptionKey: string) {
    this.tokens = new Map();
    this.encryptionKey = encryptionKey;
    this.auditLog = [];
  }

  /**
   * Stores a token securely
   * @param tokenName The name/identifier of the token
   * @param tokenValue The token value
   * @param config Configuration for the token
   * @returns True if the token was stored successfully
   */
  public storeToken(tokenName: string, tokenValue: string, config: TokenConfig): boolean {
    try {
      // Encrypt the token value
      const encryptedValue = this.encrypt(tokenValue);
      
      // Store the token data
      this.tokens.set(tokenName, {
        value: encryptedValue,
        config,
        expiry: null,
        created: new Date(),
        lastUsed: null
      });
      
      // Log the action
      this.logAction(tokenName, 'store', { configType: config.serviceType });
      
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Updates an existing token
   * @param tokenName The name/identifier of the token
   * @param newValue The new token value
   * @param newExpiry Optional new expiry date
   * @returns True if the token was updated successfully
   */
  public updateToken(tokenName: string, newValue: string, newExpiry: Date | null = null): boolean {
    try {
      const tokenData = this.tokens.get(tokenName);
      if (!tokenData) {
        return false;
      }
      
      // Encrypt the new token value
      const encryptedValue = this.encrypt(newValue);
      
      // Update the token data
      tokenData.value = encryptedValue;
      if (newExpiry) {
        tokenData.expiry = newExpiry;
      }
      
      // Log the action
      this.logAction(tokenName, 'update', { hasNewExpiry: !!newExpiry });
      
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Retrieves a token
   * @param tokenName The name/identifier of the token
   * @returns The decrypted token value, or null if not found
   */
  public getToken(tokenName: string): { value: string; config: TokenConfig } | null {
    const tokenData = this.tokens.get(tokenName);
    if (!tokenData) {
      return null;
    }

    try {
      return {
        value: this.decrypt(tokenData.value),
        config: tokenData.config
      };
    } catch {
      return null;
    }
  }

  /**
   * Gets token data including metadata
   * @param tokenName The name/identifier of the token
   * @returns The token data, or null if not found
   */
  public getTokenData(tokenName: string): StoredToken | null {
    const tokenData = this.tokens.get(tokenName);
    if (!tokenData) {
      return null;
    }

    try {
      return {
        ...tokenData,
        value: this.decrypt(tokenData.value)
      };
    } catch {
      return null;
    }
  }

  /**
   * Records usage of a token for auditing
   * @param tokenName The name/identifier of the token
   */
  public recordTokenUsage(tokenName: string): void {
    const tokenData = this.tokens.get(tokenName);
    if (tokenData) {
      tokenData.lastUsed = new Date();
      this.logAction(tokenName, 'use');
    }
  }

  /**
   * Removes a token
   * @param tokenName The name/identifier of the token
   * @returns True if the token was removed successfully
   */
  public removeToken(tokenName: string): boolean {
    const removed = this.tokens.delete(tokenName);
    if (removed) {
      this.logAction(tokenName, 'remove');
    }
    return removed;
  }

  /**
   * Gets a list of all stored token names
   * @returns Array of token names
   */
  public listTokens(): string[] {
    return Array.from(this.tokens.keys());
  }

  /**
   * Gets the audit log
   * @param tokenName Optional token name to filter logs
   * @returns Array of audit log entries
   */
  public getAuditLog(tokenName?: string): AuditLogEntry[] {
    if (tokenName) {
      return this.auditLog.filter(entry => entry.tokenName === tokenName);
    }
    return this.auditLog;
  }

  /**
   * Logs an action for auditing
   * @param tokenName The name/identifier of the token
   * @param action The action performed
   * @param details Optional details about the action
   */
  private logAction(tokenName: string, action: string, details?: AuditLogEntry['details']): void {
    this.auditLog.push({
      tokenName,
      action,
      timestamp: new Date(),
      details
    });
    
    // Limit the size of the audit log
    if (this.auditLog.length > 1000) {
      this.auditLog = this.auditLog.slice(-1000);
    }
  }

  /**
   * Encrypts a value with the encryption key
   * @param value The value to encrypt
   * @returns Encrypted value
   */
  private encrypt(value: string): string {
    const iv = crypto.randomBytes(12);
    const key = this.deriveKey();
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

    let encrypted = cipher.update(value, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();

    return `v2:${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
  }

  /**
   * Decrypts a value with the encryption key
   * @param encrypted The encrypted value
   * @returns Decrypted value
   */
  private decrypt(encrypted: string): string {
    const parts = encrypted.split(':');

    if (parts[0] === 'v2') {
      const [, ivHex, authTagHex, encryptedValue] = parts;
      if (!ivHex || !authTagHex || !encryptedValue) {
        throw new Error('Invalid encrypted payload format');
      }

      const iv = this.parseHexBuffer(ivHex, 12);
      const authTag = this.parseHexBuffer(authTagHex, 16);
      const decipher = crypto.createDecipheriv('aes-256-gcm', this.deriveKey(), iv);
      decipher.setAuthTag(authTag);

      let decrypted = decipher.update(encryptedValue, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      return decrypted;
    }

    if (parts.length === 2) {
      const [ivHex, encryptedValue] = parts;
      const iv = this.parseHexBuffer(ivHex, 16);
      const decipher = crypto.createDecipheriv('aes-256-cbc', this.deriveKey(), iv);

      let decrypted = decipher.update(encryptedValue, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      return decrypted;
    }

    throw new Error('Invalid encrypted payload format');
  }

  /**
   * Derive a consistent 256-bit encryption key from the configured secret.
   */
  private deriveKey(): Buffer {
    return crypto.createHash('sha256').update(this.encryptionKey).digest().subarray(0, 32);
  }

  /**
   * Decode hex input while enforcing the expected size.
   */
  private parseHexBuffer(value: string, expectedLength: number): Buffer {
    if (!/^[0-9a-f]+$/i.test(value) || value.length % 2 !== 0) {
      throw new Error('Invalid encrypted payload encoding');
    }

    const buffer = Buffer.from(value, 'hex');
    if (buffer.length !== expectedLength) {
      throw new Error('Invalid encrypted payload size');
    }

    return buffer;
  }
}
