import crypto from 'crypto';

/**
 * Service for managing canary tokens
 */
export class CanaryService {
  private enabled: boolean;
  private canaries: Map<string, string>;

  /**
   * Creates a new CanaryService
   * @param enabled Whether canary tokens are enabled
   */
  constructor(enabled: boolean) {
    this.enabled = enabled;
    this.canaries = new Map();
  }

  /**
   * Embeds a canary marker in a token
   * @param token The original token
   * @param tokenName The name/identifier of the token
   * @returns Token with embedded canary marker
   */
  public embedCanary(token: string, tokenName: string): string {
    if (!this.enabled) {
      return token;
    }
    
    // Generate a unique canary ID for this token
    const canaryId = this.generateCanaryId(tokenName);
    
    // Store the canary ID for future reference
    this.canaries.set(canaryId, tokenName);
    
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
    return crypto
      .createHash('sha256')
      .update(`${tokenName}:${timestamp}`)
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
      const payloadObj = JSON.parse(decodedPayload);
      
      // Add the canary as a custom claim
      payloadObj._cid = canaryId;
      
      // Encode the modified payload
      const newPayload = Buffer.from(JSON.stringify(payloadObj)).toString('base64')
        .replace(/=/g, '')
        .replace(/\\+/g, '-')
        .replace(/\\//g, '_');
      
      // Return the modified JWT
      // Note: This breaks the signature, but since we're just monitoring for leaks, it's acceptable
      return `${header}.${newPayload}.${signature}`;
    } catch (error) {
      // If anything goes wrong, return the original token
      return token;
    }
  }

  /**
   * Embeds a canary ID in a generic token
   * @param token The token
   * @param canaryId The canary ID to embed
   * @returns Modified token with embedded canary
   */
  private embedInGenericToken(token: string, canaryId: string): string {
    // For demonstration, we'll use a simple embedding technique
    // In a real implementation, this would be more sophisticated and token-format aware
    const pos = Math.floor(token.length / 2);
    
    // Create a visually similar but unique variant of the token
    // This technique heavily depends on the token format and would need to be adapted
    // For example, embedding in Base64 would be different than in a hex string
    
    // For this demo, we'll just add a subtle identifier near the middle
    // In a real implementation, this would be much more sophisticated
    return token.substring(0, pos) + canaryId.substring(0, 1) + token.substring(pos + 1);
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
        const decodedPayload = Buffer.from(payload, 'base64').toString('utf-8');
        const payloadObj = JSON.parse(decodedPayload);
        
        if (payloadObj._cid && this.canaries.has(payloadObj._cid)) {
          return this.canaries.get(payloadObj._cid) || null;
        }
      } catch (error) {
        // Ignore parsing errors
      }
    }
    
    // For other tokens, we'd need more sophisticated detection based on how they were embedded
    // This is highly implementation-specific
    
    return null;
  }

  /**
   * Registers a callback for canary alerts
   * @param callback Function to call when a canary is triggered
   */
  public onCanaryTriggered(callback: (tokenName: string, context: any) => void): void {
    // In a real implementation, this would set up monitoring or webhooks
  }
}
