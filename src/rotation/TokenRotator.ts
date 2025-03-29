import { RotationResult } from '../interfaces/RotationResult';
import { ServiceRotator } from './ServiceRotator';
import { GitHubRotator } from './services/GitHubRotator';
import { AWSRotator } from './services/AWSRotator';
import { DefaultRotator } from './services/DefaultRotator';

/**
 * Handles token rotation for various services
 */
export class TokenRotator {
  private rotators: Map<string, ServiceRotator>;
  private rotationSchedules: Map<string, NodeJS.Timeout>;

  /**
   * Creates a new TokenRotator
   * @param services Array of service types to enable
   */
  constructor(services: string[]) {
    this.rotators = new Map();
    this.rotationSchedules = new Map();
    
    // Register default rotator
    this.rotators.set('default', new DefaultRotator());
    
    // Register service-specific rotators based on enabled services
    if (services.includes('github')) {
      this.rotators.set('github', new GitHubRotator());
    }
    
    if (services.includes('aws')) {
      this.rotators.set('aws', new AWSRotator());
    }
  }

  /**
   * Schedules automatic rotation for a token
   * @param tokenName The name/identifier of the token
   * @param serviceType The type of service the token is for
   * @param interval Rotation interval (e.g. '30d', '6h')
   */
  public scheduleRotation(tokenName: string, serviceType: string, interval: string): void {
    // Cancel any existing rotation schedule for this token
    this.cancelRotation(tokenName);
    
    // Parse the interval string to milliseconds
    const intervalMs = this.parseIntervalToMs(interval);
    
    // Schedule the rotation
    const timer = setTimeout(async () => {
      await this.rotateToken(tokenName, serviceType, '');
      // Reschedule after rotation
      this.scheduleRotation(tokenName, serviceType, interval);
    }, intervalMs);
    
    this.rotationSchedules.set(tokenName, timer);
  }

  /**
   * Cancels a scheduled rotation
   * @param tokenName The name/identifier of the token
   */
  public cancelRotation(tokenName: string): void {
    const timer = this.rotationSchedules.get(tokenName);
    if (timer) {
      clearTimeout(timer);
      this.rotationSchedules.delete(tokenName);
    }
  }

  /**
   * Rotates a token immediately
   * @param tokenName The name/identifier of the token
   * @param serviceType The type of service the token is for
   * @param currentToken The current token value
   * @returns Result of the rotation
   */
  public async rotateToken(tokenName: string, serviceType: string, currentToken: string): Promise<RotationResult> {
    // Get the appropriate rotator for this service type
    const rotator = this.rotators.get(serviceType) || this.rotators.get('default');
    
    if (!rotator) {
      return {
        success: false,
        message: `No rotator found for service type: ${serviceType}`,
        newExpiry: null
      };
    }
    
    return await rotator.rotateToken(tokenName, currentToken);
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
}
