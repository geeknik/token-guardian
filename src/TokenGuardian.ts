import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { GuardianConfig } from './interfaces/GuardianConfig';
import { TokenConfig } from './interfaces/TokenConfig';
import { ScanResult } from './interfaces/ScanResult';
import { RotationResult } from './interfaces/RotationResult';
import { PatternScanner } from './scanners/PatternScanner';
import { TokenRotator } from './rotation/TokenRotator';
import { CanaryService } from './canary/CanaryService';
import { TokenStore, AuditLogEntry } from './storage/TokenStore';
import { Logger } from './utils/Logger';

/**
 * TokenGuardian - Main class that provides token protection functionality
 */
export class TokenGuardian {
  private config: GuardianConfig;
  private scanner: PatternScanner;
  private rotator: TokenRotator;
  private canaryService: CanaryService;
  private tokenStore: TokenStore;
  private logger: Logger;

  /**
   * Creates a new TokenGuardian instance
   * @param config Configuration options for TokenGuardian
   */
  constructor(config: Partial<GuardianConfig> = {}) {
    this.config = {
      services: config.services || ['default'],
      rotationInterval: config.rotationInterval || '30d',
      canaryEnabled: config.canaryEnabled !== undefined ? config.canaryEnabled : true,
      encryptionKey: config.encryptionKey || this.generateEncryptionKey(),
      logLevel: config.logLevel || 'info',
    };

    this.logger = new Logger(this.config.logLevel);
    this.scanner = new PatternScanner();
    this.tokenStore = new TokenStore(this.config.encryptionKey);
    this.rotator = new TokenRotator(this.config.services);
    this.canaryService = new CanaryService(this.config.canaryEnabled);
    
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
   * Scans a string for potential tokens or secrets
   * @param input The string to scan
   * @returns Results of the scan
   */
  public scanString(input: string): ScanResult {
    this.logger.debug('Scanning string for sensitive data');
    return this.scanner.scan(input);
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
    const scanResult = this.scanString(tokenValue);
    if (!scanResult.matches.length && config.serviceType === 'default') {
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
      this.rotator.scheduleRotation(tokenName, config.serviceType, config.rotationInterval);
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
    
    const result = await this.rotator.rotateToken(tokenName, tokenData.config.serviceType, tokenData.value);
    
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
    
    // Cancel any scheduled rotations
    this.rotator.cancelRotation(tokenName);
    
    // Remove the token from storage
    const removed = this.tokenStore.removeToken(tokenName);
    if (!removed) {
      this.logger.warn(`Failed to remove token ${tokenName}`);
      return false;
    }
    
    this.logger.info(`Token ${tokenName} removed successfully`);
    return true;
  }

  /**
   * Installs git pre-commit hooks to scan for sensitive data
   * @returns True if hooks were installed successfully
   */
  public installGitHooks(): boolean {
    this.logger.info('Installing git pre-commit hooks');
    
    try {
      
      // Find git directory
      let currentDir = process.cwd();
      let gitDir = null;
      
      while (currentDir !== path.parse(currentDir).root) {
        if (fs.existsSync(path.join(currentDir, '.git'))) {
          gitDir = path.join(currentDir, '.git');
          break;
        }
        currentDir = path.dirname(currentDir);
      }
      
      if (!gitDir) {
        this.logger.error('No git repository found');
        return false;
      }
      
      // Create hooks directory if it doesn't exist
      const hooksDir = path.join(gitDir, 'hooks');
      if (!fs.existsSync(hooksDir)) {
        fs.mkdirSync(hooksDir, { recursive: true });
      }
      
      // Create pre-commit hook
      const preCommitPath = path.join(hooksDir, 'pre-commit');
      const preCommitScript = `#!/bin/sh
# TokenGuardian pre-commit hook
# Scans staged files for potential tokens/secrets

# Get staged files
staged_files=$(git diff --cached --name-only --diff-filter=ACMR)

if [ -z "$staged_files" ]; then
  exit 0
fi

# Run TokenGuardian scan
node -e "
const { TokenGuardian } = require('token-guardian');
const fs = require('fs');
const guardian = new TokenGuardian();
let hasLeaks = false;

const files = process.argv[1].split('\\n').filter(Boolean);
for (const file of files) {
  try {
    const content = fs.readFileSync(file, 'utf8');
    const result = guardian.scanString(content);
    if (result.found) {
      console.error('\\x1b[31mPotential secrets found in: ' + file + '\\x1b[0m');
      result.matches.forEach(match => {
        console.error(\`  - \${match.type} (confidence: \${Math.round(match.confidence * 100)}%)\`);
      });
      hasLeaks = true;
    }
  } catch (error) {
    // Skip files that can't be read
  }
}

if (hasLeaks) {
  console.error('\\x1b[31mCommit aborted due to potential secrets in staged files\\x1b[0m');
  console.error('Use \\'git commit --no-verify\\' to bypass this check');
  process.exit(1);
}
" "$staged_files"

exit $?`;
      
      fs.writeFileSync(preCommitPath, preCommitScript);
      fs.chmodSync(preCommitPath, '755'); // Make executable
      
      this.logger.info('Git hooks installed successfully');
      return true;
    } catch (error) {
      this.logger.error(`Failed to install git hooks: ${error instanceof Error ? error.message : 'Unknown error'}`);
      return false;
    }
  }

  /**
   * Gets the audit log for token usage
   * @param tokenName Optional token name to filter logs
   * @returns Array of audit log entries
   */
  public getAuditLog(tokenName?: string): AuditLogEntry[] {
    return this.tokenStore.getAuditLog(tokenName);
  }
}
