import crypto from 'crypto';
import { promises as fs } from 'fs';
import { GuardianConfig } from './interfaces/GuardianConfig';
import { TokenConfig } from './interfaces/TokenConfig';
import { ScanResult } from './interfaces/ScanResult';
import { RotationResult } from './interfaces/RotationResult';
import { PatternScanner } from './scanners/PatternScanner';
import { TokenRotator } from './rotation/TokenRotator';
import { CanaryService } from './canary/CanaryService';
import { TokenStore, AuditLogEntry } from './storage/TokenStore';
import { Logger, LogLevel } from './utils/Logger';
import { TokenPatterns } from './scanners/TokenPatterns';

/**
 * TokenGuardian - Main class that provides token protection functionality
 */
export class TokenGuardian {
  private config: GuardianConfig & { logLevel: LogLevel };
  private scanner: PatternScanner;
  private rotator: TokenRotator;
  private canaryService: CanaryService;
  private tokenStore: TokenStore;
  private logger: Logger;
  private patterns: TokenPatterns[];
  private rotationSchedules: Map<string, NodeJS.Timeout>;

  /**
   * Creates a new TokenGuardian instance
   * @param config Configuration options for TokenGuardian
   */
  constructor(config: Partial<GuardianConfig> = {}) {
    const logLevel = config.logLevel || 'info';
    if (logLevel !== 'debug' && logLevel !== 'info' && logLevel !== 'warn' && logLevel !== 'error') {
      throw new Error('Invalid log level. Must be one of: debug, info, warn, error');
    }

    this.config = {
      services: config.services || ['default'],
      rotationInterval: config.rotationInterval || '30d',
      canaryEnabled: config.canaryEnabled !== undefined ? config.canaryEnabled : true,
      encryptionKey: config.encryptionKey || this.generateEncryptionKey(),
      logLevel
    };

    this.logger = new Logger(this.config.logLevel);
    this.patterns = [new TokenPatterns()];
    this.scanner = new PatternScanner(this.patterns);
    this.tokenStore = new TokenStore(this.config.encryptionKey);
    this.rotator = new TokenRotator();
    this.canaryService = new CanaryService(this.config.canaryEnabled);
    this.rotationSchedules = new Map();
    
    this.logger.info('TokenGuardian initialized');
  }

  /**
   * Generates a secure encryption key
   * @returns A secure encryption key
   */
  private generateEncryptionKey(): string {
    return crypto.randomBytes(32).toString('hex');
  }

  /**
   * Parses an interval string to milliseconds
   * @param interval Interval string (e.g. '30d', '6h')
   * @returns Milliseconds
   */
  private parseIntervalToMs(interval: string): number {
    const unit = interval.slice(-1);
    const value = parseInt(interval.slice(0, -1), 10);
    
    switch (unit) {
      case 'd':
        return value * 24 * 60 * 60 * 1000;
      case 'h':
        return value * 60 * 60 * 1000;
      case 'm':
        return value * 60 * 1000;
      case 's':
        return value * 1000;
      default:
        return 30 * 24 * 60 * 60 * 1000; // Default to 30 days
    }
  }

  /**
   * Schedules automatic rotation for a token
   * @param tokenName The name/identifier of the token
   * @param serviceType The type of service the token is for
   * @param interval Rotation interval (e.g. '30d', '6h')
   */
  private scheduleRotation(tokenName: string, serviceType: string, interval: string): void {
    // Cancel any existing rotation schedule for this token
    this.cancelRotation(tokenName);
    
    // Parse the interval string to milliseconds
    const intervalMs = this.parseIntervalToMs(interval);
    
    // Schedule the rotation
    const timer = setTimeout(async () => {
      await this.rotateToken(tokenName);
      // Reschedule after rotation
      this.scheduleRotation(tokenName, serviceType, interval);
    }, intervalMs);
    
    this.rotationSchedules.set(tokenName, timer);
  }

  /**
   * Cancels a scheduled rotation
   * @param tokenName The name/identifier of the token
   */
  private cancelRotation(tokenName: string): void {
    const timer = this.rotationSchedules.get(tokenName);
    if (timer) {
      clearTimeout(timer);
      this.rotationSchedules.delete(tokenName);
    }
  }

  /**
   * Scans a string for potential tokens or secrets
   * @param input The string to scan
   * @returns Results of the scan
   */
  public scanString(input: string): ScanResult[] {
    this.logger.debug('Scanning string for sensitive data');
    return this.scanner.scan(input, 'memory');
  }

  /**
   * Protects a token by storing it securely and optionally enabling rotation and canary features
   * @param tokenName A name/identifier for the token
   * @param tokenValue The actual token value to protect
   * @param tokenConfig Configuration options for this specific token
   * @returns True if the token was successfully protected
   */
  public protect(tokenName: string, tokenValue: string, tokenConfig: Partial<TokenConfig> = {}): boolean {
    this.logger.info(`Protecting token: ${tokenName}`);
    
    const config: TokenConfig = {
      rotationEnabled: tokenConfig.rotationEnabled !== undefined ? tokenConfig.rotationEnabled : true,
      rotationInterval: tokenConfig.rotationInterval || this.config.rotationInterval,
      canaryEnabled: tokenConfig.canaryEnabled !== undefined ? tokenConfig.canaryEnabled : this.config.canaryEnabled,
      serviceType: tokenConfig.serviceType || 'default',
    };

    // Validate the token format
    const scanResults = this.scanString(tokenValue);
    if (scanResults.length === 0 && config.serviceType === 'default') {
      this.logger.warn(`Token ${tokenName} does not match any known patterns`);
    }

    // Add canary markers if enabled
    let protectedValue = tokenValue;
    if (config.canaryEnabled) {
      protectedValue = this.canaryService.embedCanary(tokenValue, tokenName);
      this.logger.debug(`Canary markers embedded in token ${tokenName}`);
    }

    // Store the token
    const stored = this.tokenStore.storeToken(tokenName, protectedValue, config);
    if (!stored) {
      this.logger.error(`Failed to store token ${tokenName}`);
      return false;
    }

    // Set up rotation if enabled
    if (config.rotationEnabled) {
      this.scheduleRotation(tokenName, config.serviceType, config.rotationInterval);
      this.logger.debug(`Rotation scheduled for token ${tokenName}`);
    }

    this.logger.info(`Token ${tokenName} protected successfully`);
    return true;
  }

  /**
   * Retrieves a protected token
   * @param tokenName The name/identifier of the token to retrieve
   * @returns The token value, or null if not found
   */
  public getToken(tokenName: string): string | null {
    this.logger.debug(`Retrieving token: ${tokenName}`);
    const token = this.tokenStore.getToken(tokenName);
    
    if (!token) {
      this.logger.warn(`Token ${tokenName} not found`);
      return null;
    }
    
    // Record usage for auditing
    this.tokenStore.recordTokenUsage(tokenName);
    
    return token.value;
  }

  /**
   * Forcibly rotates a token immediately
   * @param tokenName The name/identifier of the token to rotate
   * @returns Result of the rotation attempt
   */
  public async rotateToken(tokenName: string): Promise<RotationResult> {
    this.logger.info(`Manually rotating token: ${tokenName}`);
    
    const tokenData = this.tokenStore.getTokenData(tokenName);
    if (!tokenData) {
      this.logger.error(`Token ${tokenName} not found for rotation`);
      return {
        success: false,
        message: `Token ${tokenName} not found`,
        newExpiry: null
      };
    }
    
    const result = await this.rotator.rotateToken(tokenData.value);
    
    if (result.success && result.newToken) {
      // Update the stored token with the new value
      let newValue = result.newToken;
      
      // Re-embed canary if enabled
      if (tokenData.config.canaryEnabled) {
        newValue = this.canaryService.embedCanary(result.newToken, tokenName);
      }
      
      const updated = this.tokenStore.updateToken(tokenName, newValue, result.newExpiry);
      if (!updated) {
        this.logger.error(`Failed to update token ${tokenName} after rotation`);
        return {
          success: false,
          message: 'Rotation succeeded but failed to update stored token',
          newExpiry: result.newExpiry
        };
      }
    } else {
      this.logger.error(`Failed to rotate token ${tokenName}: ${result.message}`);
    }
    
    return result;
  }

  /**
   * Gets a list of all protected token names
   * @returns Array of token names
   */
  public listTokens(): string[] {
    return this.tokenStore.listTokens();
  }

  /**
   * Removes a protected token
   * @param tokenName The name/identifier of the token to remove
   * @returns True if the token was successfully removed
   */
  public removeToken(tokenName: string): boolean {
    this.logger.info(`Removing token: ${tokenName}`);
    
    // Cancel any scheduled rotation
    this.cancelRotation(tokenName);
    
    // Remove from storage
    const removed = this.tokenStore.removeToken(tokenName);
    if (!removed) {
      this.logger.error(`Failed to remove token ${tokenName}`);
      return false;
    }
    
    this.logger.info(`Token ${tokenName} removed successfully`);
    return true;
  }

  /**
   * Gets the audit log for a specific token or all tokens
   * @param tokenName Optional token name to filter the log
   * @returns Array of audit log entries
   */
  public getAuditLog(tokenName?: string): AuditLogEntry[] {
    return this.tokenStore.getAuditLog(tokenName);
  }

  /**
   * Scans a file for potential tokens or secrets
   * @param filepath Path to the file to scan
   * @returns Results of the scan
   */
  public async scanFile(filepath: string): Promise<ScanResult[]> {
    this.logger.debug(`Scanning file: ${filepath}`);
    const content = await fs.readFile(filepath, 'utf8');
    return this.scanContent(content, filepath);
  }

  /**
   * Scans content from a file for potential tokens or secrets
   * @param content Content to scan
   * @param filepath Original file path (for reporting)
   * @returns Results of the scan
   */
  public async scanContent(content: string, filepath: string): Promise<ScanResult[]> {
    return this.scanner.scan(content, filepath);
  }
}
