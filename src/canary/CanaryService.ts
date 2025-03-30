import crypto from 'crypto';
import { EventEmitter } from 'events';
import axios from 'axios';

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
 * Service for managing canary tokens
 */
export class CanaryService extends EventEmitter {
  private enabled: boolean;
  private canaries: Map<string, string>;
  private webhookUrl: string | null = null;
  private alertEndpoints: Map<string, string> = new Map();

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
    this.webhookUrl = webhookUrl;
  }

  /**
   * Add an alert endpoint for specific tokens
   * @param tokenName Token to monitor
   * @param endpointUrl URL to notify on detection
   */
  public addAlertEndpoint(tokenName: string, endpointUrl: string): void {
    this.alertEndpoints.set(tokenName, endpointUrl);
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
    
    // Generate a unique canary ID for this token
    const canaryId = this.generateCanaryId(tokenValue);
    
    // Store the canary ID for future reference
    this.canaries.set(canaryId, tokenValue);
    
    // Determine how to embed the canary based on token format
    if (token.includes('.') && token.split('.').length === 3) {
      // Looks like a JWT, embed in the payload
      return this.embedInJWT(token, canaryId);
    } else if (token.length > 20) {
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
   * Embeds a canary ID in a JWT token
   * @param token The JWT token
   * @param canaryId The canary ID to embed
   * @returns Modified JWT with embedded canary
   */
  private embedInJWT(token: string, canaryId: string): string {
    try {
      const [header, payload, signature] = token.split('.');
      
      // Decode the payload
      const decodedPayload = Buffer.from(payload, 'base64').toString('utf-8');
      
      try {
        // Try to parse as JSON
        const payloadObj = JSON.parse(decodedPayload);
        
        // Add the canary as a custom claim
        // Use a name that looks innocuous but unique
        payloadObj._cid = canaryId;
        
        // Encode the modified payload
        const newPayload = Buffer.from(JSON.stringify(payloadObj))
          .toString('base64')
          .replace(/=/g, '')
          .replace(/\+/g, '-')
          .replace(/\//g, '_');
        
        // Return the modified JWT
        // Note: This breaks the signature, but since we're just monitoring for leaks, it's acceptable
        return `${header}.${newPayload}.${signature}`;
      } catch (error) {
        // If JSON parsing fails, try a different approach for non-JSON JWT payloads
        // Add canary marker to raw base64 payload
        const modifiedPayload = this.embedBase64Marker(payload, canaryId);
        return `${header}.${modifiedPayload}.${signature}`;
      }
    } catch (error) {
      // If anything goes wrong, return the original token
      return token;
    }
  }

  /**
   * Embeds a marker in base64 encoded data
   * @param base64Data The base64 data to modify
   * @param marker The marker to embed
   * @returns Modified base64 data
   */
  private embedBase64Marker(base64Data: string, marker: string): string {
    // Decode base64 to binary data
    const binaryData = Buffer.from(base64Data, 'base64');
    const dataLength = binaryData.length;
    
    // Only modify if we have enough data (at least 32 bytes)
    if (dataLength >= 32) {
      // Convert marker to binary
      const markerBinary = Buffer.from(marker, 'utf8');
      
      // Choose a position that's 1/3 into the data
      const position = Math.floor(dataLength / 3);
      
      // Create a new buffer with the marker embedded
      // XOR the marker data with existing data to avoid breaking functionality
      for (let i = 0; i < markerBinary.length && i + position < dataLength; i++) {
        // Subtle XOR that preserves most of the original value
        // Only modifies the 2 least significant bits
        binaryData[position + i] = (binaryData[position + i] & 0xFC) | (markerBinary[i] & 0x03);
      }
      
      // Convert back to base64, ensuring same format as JWT expects
      return binaryData.toString('base64')
        .replace(/=/g, '')
        .replace(/\+/g, '-')
        .replace(/\//g, '_');
    }
    
    return base64Data;
  }

  /**
   * Embeds a canary ID in a generic token
   * @param token The token
   * @param canaryId The canary ID to embed
   * @returns Modified token with embedded canary
   */
  private embedInGenericToken(token: string, canaryId: string): string {
    // First, determine the token type to choose the best embedding strategy
    if (/^[A-Za-z0-9+/=]+$/.test(token)) {
      // Looks like base64, use our binary embedding technique
      return this.embedBase64Token(token, canaryId);
    } else if (/^[A-Fa-f0-9]+$/.test(token)) {
      // Looks like hex, use hex embedding technique
      return this.embedHexToken(token, canaryId);
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
      // If decoding fails, use simpler approach
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
    
    // Check if it's a JWT
    if (token.includes('.') && token.split('.').length === 3) {
      try {
        const payload = token.split('.')[1];
        
        // Try standard JWT approach first
        try {
          const decodedPayload = Buffer.from(payload, 'base64').toString('utf-8');
          const payloadObj = JSON.parse(decodedPayload);
          
          if (payloadObj._cid && this.canaries.has(payloadObj._cid)) {
            // Canary detected!
            const tokenName = this.canaries.get(payloadObj._cid) || null;
            if (tokenName) {
              this.triggerAlert(tokenName, token, 'jwt_standard');
            }
            return tokenName;
          }
        } catch (error) {
          // JWT parsing failed, try binary analysis
          const possibleCanary = this.extractBase64Marker(payload);
          if (possibleCanary && this.canaries.has(possibleCanary)) {
            const tokenName = this.canaries.get(possibleCanary) || null;
            if (tokenName) {
              this.triggerAlert(tokenName, token, 'jwt_binary');
            }
            return tokenName;
          }
        }
      } catch (error) {
        // Ignore parsing errors
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
        // Ignore extraction errors
      }
    } else if (/^[A-Fa-f0-9]+$/.test(token)) {
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
        // Ignore extraction errors
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
        // Ignore extraction errors
      }
    }
    
    return null;
  }

  /**
   * Extract canary marker from base64 data
   * @param base64Data The base64 data to check
   * @returns Extracted canary ID or null
   */
  private extractBase64Marker(base64Data: string): string | null {
    try {
      // Convert to properly padded base64 if needed
      const paddedBase64 = base64Data.replace(/-/g, '+').replace(/_/g, '/');
      const paddedLength = paddedBase64.length;
      const paddingNeeded = paddedLength % 4 ? 4 - (paddedLength % 4) : 0;
      const fullyPadded = paddedBase64 + '='.repeat(paddingNeeded);
      
      // Decode to binary
      const binaryData = Buffer.from(fullyPadded, 'base64');
      
      if (binaryData.length < 32) {return null;}
      
      // Calculate the position where we embedded the marker (1/3 into the data)
      const position = Math.floor(binaryData.length / 3);
      
      // Extract the marker (up to 8 bytes)
      const markerLength = Math.min(8, binaryData.length - position);
      const markerBuffer = Buffer.alloc(markerLength);
      
      // Reverse the XOR operation we did during embedding
      for (let i = 0; i < markerLength; i++) {
        // Extract the 2 least significant bits
        markerBuffer[i] = binaryData[position + i] & 0x03;
      }
      
      // Convert to string and return
      return markerBuffer.toString('utf8').replace(/\0/g, '');
    } catch (error) {
      return null;
    }
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
      if (data.length < 16) {return null;}
      
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
    } catch (error) {
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
        console.error('Failed to send canary webhook alert:', error);
      });
    }
    
    // Send custom endpoint alert if configured for this token
    const endpoint = this.alertEndpoints.get(tokenName);
    if (endpoint) {
      this.sendEndpointAlert(endpoint, alertData).catch(error => {
        console.error(`Failed to send canary alert to endpoint ${endpoint}:`, error);
      });
    }
  }

  /**
   * Gets source information for alerts
   * @returns Object with source info
   */
  private getSourceInfo(): { ipAddress: string; userAgent: string; timestamp: string; } {
    // Get IP address from environment or request context if available
    const ipAddress = process.env.CLIENT_IP || 
                     (global as any).requestContext?.ip || 
                     (global as any).requestContext?.connection?.remoteAddress ||
                     'unknown';

    // Get user agent from environment or request context if available
    const userAgent = process.env.CLIENT_USER_AGENT || 
                     (global as any).requestContext?.headers?.['user-agent'] ||
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
    });
  }

  /**
   * Sends an alert to a custom endpoint
   * @param endpoint Endpoint URL
   * @param alertData Data to send in the alert
   */
  private async sendEndpointAlert(endpoint: string, alertData: AlertData): Promise<void> {
    await axios.post(endpoint, alertData);
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
}
