import crypto from 'crypto';
import { EventEmitter } from 'events';
import axios from 'axios';
import net from 'net';
import { Logger } from '../utils/Logger';

/**
 * Interface representing the structure of canary token alert data
 */
interface AlertData {
  /**
   * Name of the token that was detected
   */
  tokenName: string;
  /**
   * ISO timestamp when the alert was generated
   */
  timestamp: string;
  /**
   * Method used to detect the canary token
   */
  detectionMethod: string;
  /**
   * Information about the source of the detection
   */
  source: {
    /**
     * IP address where the token was detected
     */
    ipAddress: string;
    /**
     * User agent information
     */
    userAgent: string;
    /**
     * ISO timestamp of the detection
     */
    timestamp: string;
  };
  /**
   * Masked/partial version of the detected token for safe logging
   */
  partialToken: string;
}

/**
 * Represents an error that occurred during canary token operations
 */
interface CanaryError {
  message: string;
  name: string;
}

/**
 * Service for managing canary tokens
 */
export class CanaryService extends EventEmitter {
  private static readonly alertRequestConfig = {
    timeout: 5000,
    maxRedirects: 0,
    maxContentLength: 16 * 1024,
    maxBodyLength: 16 * 1024,
    validateStatus: (status: number) => status >= 200 && status < 300
  };
  private enabled: boolean;
  private canaries: Map<string, string>;
  private webhookUrl: string | null = null;
  private alertEndpoints: Map<string, string> = new Map();
  private readonly logger: Logger = new Logger('info');

  /**
   * Creates a new CanaryService
   * @param enabled Whether canary tokens are enabled
   */
  constructor(enabled: boolean) {
    super();
    this.enabled = enabled;
    this.canaries = new Map();
  }

  /**
   * Configure webhook for canary notifications
   * @param webhookUrl URL to send notifications to
   */
  public configureWebhook(webhookUrl: string): void {
    this.webhookUrl = this.validateAlertUrl(webhookUrl);
  }

  /**
   * Add an alert endpoint for specific tokens
   * @param tokenName Token to monitor
   * @param endpointUrl URL to notify on detection
   */
  public addAlertEndpoint(tokenName: string, endpointUrl: string): void {
    this.alertEndpoints.set(tokenName, this.validateAlertUrl(endpointUrl));
  }

  /**
   * Embeds a canary marker in a token
   * @param token The original token
   * @param tokenName The name/identifier of the token
   * @returns Token with embedded canary marker
   */
  public embedCanary(token: string, tokenValue: string): string {
    if (!this.enabled) {
      return token;
    }

    // JWT payload mutation would invalidate the signature, so leave JWTs untouched.
    if (token.includes('.') && token.split('.').length === 3) {
      this.logger.warn('Skipping canary embedding for JWT token to preserve signature validity');
      return token;
    } else if (token.length > 20) {
      // Generate a unique canary ID for this token
      const canaryId = this.generateCanaryId(tokenValue);

      // Store the canary ID for future reference
      this.canaries.set(canaryId, tokenValue);

      // For long tokens, embed as a subtle modification
      return this.embedInGenericToken(token, canaryId);
    } else {
      // For short tokens, we can't safely modify them
      return token;
    }
  }

  /**
   * Generates a unique canary ID
   * @param tokenName The name/identifier of the token
   * @returns Unique canary ID
   */
  private generateCanaryId(tokenName: string): string {
    const timestamp = Date.now().toString();
    const randomBytes = crypto.randomBytes(4).toString('hex');
    
    return crypto
      .createHash('sha256')
      .update(`${tokenName}:${timestamp}:${randomBytes}`)
      .digest('hex')
      .substring(0, 8);
  }

  /**
   * Embeds a canary ID in a generic token
   * @param token The token
   * @param canaryId The canary ID to embed
   * @returns Modified token with embedded canary
   */
  private embedInGenericToken(token: string, canaryId: string): string {
    // First, determine the token type to choose the best embedding strategy
    if (/^[A-Fa-f0-9]+$/.test(token)) {
      // Looks like hex, use hex embedding technique
      return this.embedHexToken(token, canaryId);
    } else if (/^[A-Za-z0-9+/=]+$/.test(token)) {
      // Looks like base64, use our binary embedding technique
      return this.embedBase64Token(token, canaryId);
    } else {
      // Mixed character token, use unicode embedding
      return this.embedMixedToken(token, canaryId);
    }
  }

  /**
   * Embeds a canary ID in a base64-encoded token
   * @param token The base64 token
   * @param canaryId The canary ID to embed
   * @returns Modified token with embedded canary
   */
  private embedBase64Token(token: string, canaryId: string): string {
    try {
      // Decode token
      const data = Buffer.from(token, 'base64');
      
      // Only continue if token is long enough
      if (data.length < 16) {return token;}
      
      // Insert the canary ID at 1/4 position using LSB embedding
      const insertPos = Math.floor(data.length / 4);
      const canaryData = Buffer.from(canaryId);
      
      // Only modify a few bits to maintain token functionality
      for (let i = 0; i < Math.min(canaryData.length, 8); i++) {
        if (i + insertPos < data.length) {
          // Modify only the least significant bit (LSB steganography)
          data[insertPos + i] = (data[insertPos + i] & 0xFE) | ((canaryData[i] & 0x80) >> 7);
        }
      }
      
      // Convert back to base64
      return data.toString('base64');
    } catch (error) {
      this.logError('Failed to decode base64 token', error);
      // Fall back to simpler approach
      const pos = Math.floor(token.length / 4);
      return token.substring(0, pos) + 
             canaryId.substring(0, 1) + 
             token.substring(pos + 1);
    }
  }

  /**
   * Embeds a canary ID in a hex token
   * @param token The hex token
   * @param canaryId The canary ID to embed
   * @returns Modified token with embedded canary
   */
  private embedHexToken(token: string, canaryId: string): string {
    // For hex tokens, we can replace certain characters
    // Choose position that's 3/4 through the token
    const pos = Math.floor(token.length * 3 / 4);
    
    // Get the canary hex value
    const canaryHex = crypto.createHash('md5')
      .update(canaryId)
      .digest('hex')
      .substring(0, 4);
    
    // Replace 4 characters at the chosen position
    // But maintain case consistency with the original token
    let modifiedToken = token.substring(0, pos);
    
    for (let i = 0; i < 4; i++) {
      if (pos + i < token.length) {
        const originalChar = token.charAt(pos + i);
        const canaryChar = canaryHex.charAt(i);
        
        // Maintain the case of the original character
        if (originalChar >= 'A' && originalChar <= 'F') {
          modifiedToken += canaryChar.toUpperCase();
        } else {
          modifiedToken += canaryChar.toLowerCase();
        }
      }
    }
    
    // Add the rest of the token
    modifiedToken += token.substring(pos + 4);
    
    return modifiedToken;
  }

  /**
   * Embeds a canary ID in a mixed-character token
   * @param token The mixed-character token
   * @param canaryId The canary ID to embed
   * @returns Modified token with embedded canary
   */
  private embedMixedToken(token: string, canaryId: string): string {
    // For mixed character tokens, use a zero-width unicode character approach
    // This is invisible to most systems but can be detected
    
    // Choose position at 2/3 through the token
    const pos = Math.floor(token.length * 2 / 3);
    
    // We'll use zero-width characters to encode a simplified version of the canaryId
    // Convert canaryId to a binary representation using zero-width characters
    let binaryCanary = '';
    for (let i = 0; i < Math.min(canaryId.length, 4); i++) {
      const charCode = canaryId.charCodeAt(i);
      // Use zero-width space for 0 and zero-width non-joiner for 1
      // These are invisible in most contexts
      for (let bit = 0; bit < 8; bit++) {
        binaryCanary += ((charCode >> bit) & 1) ? '\u200C' : '\u200B';
      }
    }
    
    // Insert the zero-width encoded canary ID
    return token.substring(0, pos) + binaryCanary + token.substring(pos);
  }

  /**
   * Checks if a token contains a canary marker
   * @param token The token to check
   * @returns The token name if a canary was found, null otherwise
   */
  public detectCanary(token: string): string | null {
    if (!this.enabled) {
      return null;
    }
    
    // JWT canaries are intentionally not embedded because that would invalidate signatures.
    // Skip JWT detection here to avoid false confidence around unchanged tokens.
    if (token.includes('.') && token.split('.').length === 3) {
      return null;
    }

    if (/^[A-Fa-f0-9]+$/.test(token)) {
      // Try hex token detection
      try {
        const possibleCanary = this.extractHexTokenCanary(token);
        if (possibleCanary && this.canaries.has(possibleCanary)) {
          const tokenName = this.canaries.get(possibleCanary) || null;
          if (tokenName) {
            this.triggerAlert(tokenName, token, 'hex');
          }
          return tokenName;
        }
      } catch (error) {
        this.logError('Failed to extract hex token canary', error);
        // Continue to try other detection methods
      }
    } else if (/^[A-Za-z0-9+/=]+$/.test(token)) {
      // Try base64 token detection
      try {
        const possibleCanary = this.extractBase64TokenCanary(token);
        if (possibleCanary && this.canaries.has(possibleCanary)) {
          const tokenName = this.canaries.get(possibleCanary) || null;
          if (tokenName) {
            this.triggerAlert(tokenName, token, 'base64');
          }
          return tokenName;
        }
      } catch (error) {
        this.logError('Failed to extract base64 token canary', error);
        // Continue to try other detection methods
      }
    } else {
      // Try mixed character token detection (zero-width)
      try {
        const possibleCanary = this.extractMixedTokenCanary(token);
        if (possibleCanary && this.canaries.has(possibleCanary)) {
          const tokenName = this.canaries.get(possibleCanary) || null;
          if (tokenName) {
            this.triggerAlert(tokenName, token, 'mixed');
          }
          return tokenName;
        }
      } catch (error) {
        this.logError('Failed to extract mixed token canary', error);
        // Continue to try other detection methods
      }
    }
    
    return null;
  }

  /**
   * Extract canary ID from a base64 token
   * @param token The base64 token
   * @returns Extracted canary ID or null
   */
  private extractBase64TokenCanary(token: string): string | null {
    try {
      // Decode token
      const data = Buffer.from(token, 'base64');
      
      // Only continue if token is long enough
      if (data.length < 16) {
        return null;
      }
      
      // Extract from 1/4 position
      const extractPos = Math.floor(data.length / 4);
      const canaryData = Buffer.alloc(8);
      
      // Extract the LSB from each byte
      for (let i = 0; i < 8; i++) {
        if (i + extractPos < data.length) {
          // Extract the least significant bit
          canaryData[i] = ((data[extractPos + i] & 0x01) << 7);
        }
      }
      
      // Try to convert to a valid canary ID
      // We check against all our known canary IDs for partial matches
      const extractedBits = canaryData.toString('hex').substring(0, 4);
      
      // Look for partial matches in our canary IDs
      for (const [canaryId] of this.canaries.entries()) {
        const canaryHex = Buffer.from(canaryId).toString('hex').substring(0, 4);
        if (this.hammingDistance(extractedBits, canaryHex) <= 2) {
          return canaryId;
        }
      }
      
      return null;
    } catch (extractError) {
      this.logError('Failed to extract base64 token canary', extractError);
      return null;
    }
  }

  /**
   * Extract canary ID from a hex token
   * @param token The hex token
   * @returns Extracted canary ID or null
   */
  private extractHexTokenCanary(token: string): string | null {
    try {
      // Extract from 3/4 position
      const pos = Math.floor(token.length * 3 / 4);
      
      // Extract 4 characters from the token
      if (pos + 4 > token.length) {return null;}
      
      const extractedHex = token.substring(pos, pos + 4).toLowerCase();
      
      // Check against our canary IDs
      for (const [canaryId] of this.canaries.entries()) {
        const canaryHex = crypto.createHash('md5')
          .update(canaryId)
          .digest('hex')
          .substring(0, 4)
          .toLowerCase();
        
        // Allow for some bit errors (up to 2 characters different)
        if (this.hammingDistance(extractedHex, canaryHex) <= 2) {
          return canaryId;
        }
      }
      
      return null;
    } catch (error) {
      this.logError('Failed to extract hex token canary', error);
      return null;
    }
  }

  /**
   * Extract canary ID from a mixed-character token
   * @param token The mixed-character token
   * @returns Extracted canary ID or null
   */
  private extractMixedTokenCanary(token: string): string | null {
    try {
      // Look for zero-width characters
      const zeroWidthRegex = /[\u200B\u200C]+/;
      const match = token.match(zeroWidthRegex);
      
      if (!match) {return null;}
      
      // Extract the zero-width characters
      const zeroWidthSequence = match[0];
      
      // Convert zero-width sequence to binary, then to a string
      let binaryString = '';
      for (let i = 0; i < zeroWidthSequence.length; i++) {
        binaryString += (zeroWidthSequence[i] === '\u200C') ? '1' : '0';
      }
      
      // Group into bytes
      const bytes = [];
      for (let i = 0; i < binaryString.length; i += 8) {
        if (i + 8 <= binaryString.length) {
          const byte = parseInt(binaryString.substring(i, i + 8), 2);
          bytes.push(byte);
        }
      }
      
      // Convert to a string
      const extractedString = Buffer.from(bytes).toString('utf8');
      
      // Check against our canary IDs for partial matches
      for (const [canaryId] of this.canaries.entries()) {
        // Check for first few characters matching
        if (extractedString && canaryId.startsWith(extractedString.substring(0, 2))) {
          return canaryId;
        }
      }
      
      return null;
    } catch (error) {
      this.logError('Failed to extract mixed token canary', error);
      return null;
    }
  }

  /**
   * Calculate Hamming distance between two strings
   * @param str1 First string
   * @param str2 Second string
   * @returns Number of differing characters
   */
  private hammingDistance(str1: string, str2: string): number {
    let distance = 0;
    const len = Math.min(str1.length, str2.length);
    
    for (let i = 0; i < len; i++) {
      if (str1[i] !== str2[i]) {
        distance++;
      }
    }
    
    // Add difference in length
    distance += Math.abs(str1.length - str2.length);
    
    return distance;
  }

  /**
   * Triggers alert for a detected canary
   * @param tokenName The name of the detected token
   * @param token The actual token that was detected
   * @param detectionMethod How the canary was detected
   */
  private triggerAlert(tokenName: string, token: string, detectionMethod: string): void {
    const alertData = {
      tokenName,
      timestamp: new Date().toISOString(),
      detectionMethod,
      source: this.getSourceInfo(),
      partialToken: this.maskToken(token)
    };
    
    // Emit event
    this.emit('canaryDetected', alertData);
    
    // Send webhook if configured
    if (this.webhookUrl) {
      this.sendWebhookAlert(alertData).catch(error => {
        this.logError('Failed to send canary webhook alert', error);
      });
    }
    
    // Send custom endpoint alert if configured for this token
    const endpoint = this.alertEndpoints.get(tokenName);
    if (endpoint) {
      this.sendEndpointAlert(endpoint, alertData).catch(error => {
        this.logError(`Failed to send canary alert to endpoint ${endpoint}`, error);
      });
    }
  }

  /**
   * Gets source information for alerts
   * @returns Object with source info
   */
  private getSourceInfo(): { ipAddress: string; userAgent: string; timestamp: string; } {
    // Get IP address from environment or request context if available
    const context = global as unknown as {
      requestContext?: {
        ip?: string;
        connection?: { remoteAddress?: string };
        headers?: Record<string, string>;
      };
    };

    const ipAddress = process.env.CLIENT_IP || 
                     context.requestContext?.ip || 
                     context.requestContext?.connection?.remoteAddress ||
                     'unknown';

    // Get user agent from environment or request context if available
    const userAgent = process.env.CLIENT_USER_AGENT || 
                     context.requestContext?.headers?.['user-agent'] ||
                     'unknown';

    return {
      ipAddress,
      userAgent,
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Masks a token for safe logging
   * @param token The token to mask
   * @returns Masked token
   */
  private maskToken(token: string): string {
    if (token.length <= 8) {
      return '****';
    }
    
    return token.substring(0, 4) + '****' + token.substring(token.length - 4);
  }

  /**
   * Sends a webhook alert
   * @param alertData Data to send in the alert
   */
  private async sendWebhookAlert(alertData: AlertData): Promise<void> {
    if (!this.webhookUrl) {return;}
    
    await axios.post(this.webhookUrl, {
      text: `🚨 SECURITY ALERT: Canary token detected!`,
      blocks: [
        {
          type: 'section',
          text: {
            type: 'mrkdwn',
            text: `*SECURITY ALERT: Canary Token Detected*`
          }
        },
        {
          type: 'section',
          fields: [
            {
              type: 'mrkdwn',
              text: `*Token:* ${alertData.tokenName}`
            },
            {
              type: 'mrkdwn',
              text: `*Detected:* ${alertData.timestamp}`
            },
            {
              type: 'mrkdwn',
              text: `*Method:* ${alertData.detectionMethod}`
            }
          ]
        },
        {
          type: 'section',
          text: {
            type: 'mrkdwn',
            text: `*Token Fragment:* \`${alertData.partialToken}\``
          }
        }
      ]
    }, CanaryService.alertRequestConfig);
  }

  /**
   * Sends an alert to a custom endpoint
   * @param endpoint Endpoint URL
   * @param alertData Data to send in the alert
   */
  private async sendEndpointAlert(endpoint: string, alertData: AlertData): Promise<void> {
    await axios.post(endpoint, alertData, CanaryService.alertRequestConfig);
  }

  /**
   * Validate outbound alert destinations before storing or using them.
   */
  private validateAlertUrl(rawUrl: string): string {
    let parsedUrl: URL;

    try {
      parsedUrl = new URL(rawUrl);
    } catch {
      throw new Error('Alert destination must be a valid absolute URL');
    }

    if (parsedUrl.protocol !== 'https:') {
      throw new Error('Alert destinations must use HTTPS');
    }

    if (parsedUrl.username || parsedUrl.password) {
      throw new Error('Alert destinations must not include embedded credentials');
    }

    if (this.isDisallowedAlertHost(parsedUrl.hostname)) {
      throw new Error('Alert destinations must not target localhost or private network addresses');
    }

    return parsedUrl.toString();
  }

  /**
   * Reject obvious local and private-network destinations to reduce SSRF risk.
   */
  private isDisallowedAlertHost(hostname: string): boolean {
    const normalizedHost = hostname.trim().toLowerCase();
    if (normalizedHost === 'localhost') {
      return true;
    }

    const ipVersion = net.isIP(normalizedHost);
    if (ipVersion === 4) {
      return this.isPrivateIpv4(normalizedHost);
    }

    if (ipVersion === 6) {
      return normalizedHost === '::1' ||
        normalizedHost.startsWith('fc') ||
        normalizedHost.startsWith('fd') ||
        normalizedHost.startsWith('fe80:');
    }

    return false;
  }

  /**
   * Detect private, loopback, link-local, and unspecified IPv4 ranges.
   */
  private isPrivateIpv4(ipAddress: string): boolean {
    const octets = ipAddress.split('.').map(value => Number.parseInt(value, 10));
    if (octets.length !== 4 || octets.some(value => !Number.isInteger(value) || value < 0 || value > 255)) {
      return true;
    }

    const [first, second] = octets;
    return first === 0 ||
      first === 10 ||
      first === 127 ||
      (first === 169 && second === 254) ||
      (first === 172 && second >= 16 && second <= 31) ||
      (first === 192 && second === 168);
  }

  /**
   * Registers a callback for canary alerts
   * @param callback Function to call when a canary is triggered
   */
  public onCanaryTriggered(callback: (tokenName: string, context: AlertData) => void): void {
    this.on('canaryDetected', (alertData) => {
      callback(alertData.tokenName, alertData);
    });
  }

  /**
   * Logs an error with context
   * @param message Error context message
   * @param error The caught error
   */
  private logError(message: string, error: unknown): void {
    const errorDetails: CanaryError = {
      message: error instanceof Error ? error.message : String(error),
      name: error instanceof Error ? error.name : 'UnknownError'
    };
    
    // Emit error event for logging/monitoring
    this.emit('error', {
      context: message,
      error: errorDetails,
      timestamp: new Date().toISOString()
    });
    
    this.logger.error(message, { error: errorDetails });
  }
}
