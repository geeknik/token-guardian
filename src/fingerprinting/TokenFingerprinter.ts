import crypto from 'crypto';
import { Logger } from '../utils/Logger';

/**
 * Token usage event
 */
export interface TokenUsageEvent {
  /** Timestamp of the event */
  timestamp: Date;
  /** Type of operation (e.g., 'api_call', 'authentication') */
  operation: string;
  /** Source of the usage (e.g., IP address, service name) */
  source: string;
  /** Success/failure status */
  success: boolean;
  /** Additional context */
  context?: Record<string, any>;
}

/**
 * Token fingerprint data
 */
export interface TokenFingerprint {
  /** Unique fingerprint hash */
  hash: string;
  /** Token name/identifier */
  tokenName: string;
  /** First seen timestamp */
  firstSeen: Date;
  /** Last seen timestamp */
  lastSeen: Date;
  /** Usage patterns */
  patterns: {
    /** Common sources of usage */
    sources: Set<string>;
    /** Common operations performed */
    operations: Set<string>;
    /** Success rate */
    successRate: number;
    /** Total usage count */
    totalUsage: number;
  };
  /** Usage history */
  history: TokenUsageEvent[];
}

/**
 * Service for fingerprinting and tracking token usage
 */
export class TokenFingerprinter {
  private logger: Logger;
  private fingerprints: Map<string, TokenFingerprint>;
  private readonly maxHistoryLength: number;

  constructor(logger?: Logger, maxHistoryLength: number = 1000) {
    this.logger = logger || new Logger('info');
    this.fingerprints = new Map();
    this.maxHistoryLength = maxHistoryLength;
  }

  /**
   * Generate a fingerprint hash for a token
   * @param token Token to fingerprint
   * @returns Fingerprint hash
   */
  private generateFingerprint(token: string): string {
    return crypto
      .createHash('sha256')
      .update(token)
      .digest('hex')
      .substring(0, 16);
  }

  /**
   * Initialize fingerprint tracking for a token
   * @param token Token to track
   * @param tokenName Name/identifier for the token
   * @returns Fingerprint hash
   */
  public initializeTracking(token: string, tokenName: string): string {
    const hash = this.generateFingerprint(token);
    
    if (!this.fingerprints.has(hash)) {
      this.fingerprints.set(hash, {
        hash,
        tokenName,
        firstSeen: new Date(),
        lastSeen: new Date(),
        patterns: {
          sources: new Set(),
          operations: new Set(),
          successRate: 1.0,
          totalUsage: 0
        },
        history: []
      });

      this.logger.info(`Started tracking token: ${tokenName}`, { fingerprint: hash });
    }

    return hash;
  }

  /**
   * Record a token usage event
   * @param fingerprint Token fingerprint
   * @param event Usage event details
   */
  public recordUsage(fingerprint: string, event: TokenUsageEvent): void {
    const data = this.fingerprints.get(fingerprint);
    if (!data) {
      this.logger.warn(`Attempted to record usage for unknown token: ${fingerprint}`);
      return;
    }

    // Update timestamps
    data.lastSeen = new Date();

    // Update patterns
    data.patterns.sources.add(event.source);
    data.patterns.operations.add(event.operation);
    data.patterns.totalUsage++;

    // Update success rate
    const totalEvents = data.history.length;
    const successfulEvents = data.history.filter(e => e.success).length;
    data.patterns.successRate = (successfulEvents + (event.success ? 1 : 0)) / (totalEvents + 1);

    // Add to history with size limit
    data.history.push(event);
    if (data.history.length > this.maxHistoryLength) {
      data.history.shift();
    }

    // Check for suspicious patterns
    this.detectAnomalies(fingerprint, event);

    this.logger.debug(`Recorded token usage: ${data.tokenName}`, {
      fingerprint,
      operation: event.operation,
      source: event.source,
      success: event.success
    });
  }

  /**
   * Detect anomalous token usage patterns
   * @param fingerprint Token fingerprint
   * @param event Current usage event
   */
  private detectAnomalies(fingerprint: string, event: TokenUsageEvent): void {
    const data = this.fingerprints.get(fingerprint);
    if (!data) { return; }

    // Check for sudden change in success rate
    const recentEvents = data.history.slice(-10);
    if (recentEvents.length >= 10) {
      const recentSuccessRate = recentEvents.filter(e => e.success).length / recentEvents.length;
      const overallSuccessRate = data.patterns.successRate;

      if (recentSuccessRate < overallSuccessRate * 0.5) {
        this.logger.warn(`Unusual failure rate detected for token: ${data.tokenName}`, {
          fingerprint,
          recentSuccessRate,
          overallSuccessRate
        });
      }
    }

    // Check for new source
    if (!data.patterns.sources.has(event.source)) {
      this.logger.warn(`New usage source detected for token: ${data.tokenName}`, {
        fingerprint,
        source: event.source
      });
    }

    // Check for unusual operation
    if (!data.patterns.operations.has(event.operation)) {
      this.logger.warn(`New operation type detected for token: ${data.tokenName}`, {
        fingerprint,
        operation: event.operation
      });
    }

    // Check for unusual timing
    const now = new Date();
    const hour = now.getHours();
    if (hour < 6 || hour > 22) { // Outside normal business hours
      this.logger.warn(`Off-hours token usage detected: ${data.tokenName}`, {
        fingerprint,
        time: now.toISOString()
      });
    }
  }

  /**
   * Get fingerprint data for a token
   * @param fingerprint Token fingerprint
   * @returns Fingerprint data or null if not found
   */
  public getFingerprint(fingerprint: string): TokenFingerprint | null {
    return this.fingerprints.get(fingerprint) || null;
  }

  /**
   * Get usage history for a token
   * @param fingerprint Token fingerprint
   * @param limit Maximum number of events to return
   * @returns Array of usage events
   */
  public getUsageHistory(fingerprint: string, limit?: number): TokenUsageEvent[] {
    const data = this.fingerprints.get(fingerprint);
    if (!data) { return []; }

    const history = [...data.history];
    return limit ? history.slice(-limit) : history;
  }

  /**
   * Get usage patterns for a token
   * @param fingerprint Token fingerprint
   * @returns Usage patterns or null if not found
   */
  public getUsagePatterns(fingerprint: string): TokenFingerprint['patterns'] | null {
    const data = this.fingerprints.get(fingerprint);
    return data ? data.patterns : null;
  }

  /**
   * Remove tracking for a token
   * @param fingerprint Token fingerprint
   */
  public removeTracking(fingerprint: string): void {
    const data = this.fingerprints.get(fingerprint);
    if (data) {
      this.logger.info(`Stopped tracking token: ${data.tokenName}`, { fingerprint });
      this.fingerprints.delete(fingerprint);
    }
  }
} 