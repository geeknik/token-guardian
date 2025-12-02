import { TokenFingerprinter, TokenUsageEvent } from '../src/fingerprinting/TokenFingerprinter';
import { TokenGuardian } from '../src/TokenGuardian';
import { Logger } from '../src/utils/Logger';

describe('TokenFingerprinter', () => {
  let fingerprinter: TokenFingerprinter;
  let logger: Logger;
  let warnSpy: jest.SpyInstance;
  let infoSpy: jest.SpyInstance;
  let mockDate: Date;
  let dateSpy: jest.SpyInstance;
  let tokenGuardian: TokenGuardian | null;

  beforeEach(() => {
    logger = new Logger('info');
    infoSpy = jest.fn();
    warnSpy = jest.fn();
    (logger as unknown as { info: jest.Mock }).info = infoSpy as jest.Mock;
    (logger as unknown as { warn: jest.Mock }).warn = warnSpy as jest.Mock;
    (logger as unknown as { error: jest.Mock }).error = jest.fn();
    (logger as unknown as { debug: jest.Mock }).debug = jest.fn();

    fingerprinter = new TokenFingerprinter(logger, 5);

    // Mock Date.now() to return a fixed timestamp for most tests
    mockDate = new Date('2024-03-30T12:00:00Z');
    dateSpy = jest.spyOn(global as unknown as { Date: unknown }, 'Date').mockImplementation(() => mockDate as unknown as DateConstructor);

    tokenGuardian = new TokenGuardian();
  });

  afterEach(async () => {
    // Clear all mocks and timers
    jest.clearAllMocks();
    jest.clearAllTimers();
    jest.useRealTimers();
    dateSpy?.mockRestore();
    // Clean up any active timers
    tokenGuardian?.stopRotation('API_KEY');
  });

  describe('initializeTracking', () => {
    it('should initialize tracking for a new token', () => {
      const hash = fingerprinter.initializeTracking('test-token', 'Test Token');
      expect(hash).toHaveLength(16);
      expect(infoSpy).toHaveBeenCalledWith(
        'Started tracking token: Test Token',
        expect.objectContaining({ fingerprint: hash })
      );

      const fingerprint = fingerprinter.getFingerprint(hash);
      expect(fingerprint).toBeDefined();
      expect(fingerprint?.tokenName).toBe('Test Token');
      expect(fingerprint?.firstSeen).toEqual(mockDate);
      expect(fingerprint?.lastSeen).toEqual(mockDate);
      expect(fingerprint?.patterns.totalUsage).toBe(0);
      expect(fingerprint?.patterns.successRate).toBe(1.0);
      expect(fingerprint?.history).toHaveLength(0);
    });

    it('should return same hash for same token', () => {
      const hash1 = fingerprinter.initializeTracking('test-token', 'Test Token');
      const hash2 = fingerprinter.initializeTracking('test-token', 'Test Token');
      expect(hash1).toBe(hash2);
    });
  });

  describe('recordUsage', () => {
    let tokenHash: string;
    let testEvent: TokenUsageEvent;

    beforeEach(() => {
      tokenHash = fingerprinter.initializeTracking('test-token', 'Test Token');
      testEvent = {
        timestamp: mockDate,
        operation: 'api_call',
        source: '192.168.1.1',
        success: true,
        context: { endpoint: '/api/test' }
      };
    });

    it('should record usage event', () => {
      fingerprinter.recordUsage(tokenHash, testEvent);
      const fingerprint = fingerprinter.getFingerprint(tokenHash);
      
      expect(fingerprint?.history).toHaveLength(1);
      expect(fingerprint?.patterns.totalUsage).toBe(1);
      expect(fingerprint?.patterns.successRate).toBe(1);
      expect(fingerprint?.patterns.sources.has('192.168.1.1')).toBe(true);
      expect(fingerprint?.patterns.operations.has('api_call')).toBe(true);
    });

    it('should limit history size', () => {
      // Record 6 events (max is 5)
      for (let i = 0; i < 6; i++) {
        fingerprinter.recordUsage(tokenHash, {
          ...testEvent,
          source: `source${i}`
        });
      }

      const history = fingerprinter.getUsageHistory(tokenHash);
      expect(history).toHaveLength(5);
      expect(history[0].source).toBe('source1'); // First event should be removed
    });

    it('should handle unknown fingerprint', () => {
      fingerprinter.recordUsage('unknown-hash', testEvent);
      expect(warnSpy).toHaveBeenCalledWith(
        'Attempted to record usage for unknown token: unknown-hash'
      );
    });

    it('should update success rate correctly', () => {
      // Record 3 events: 2 successful, 1 failed
      fingerprinter.recordUsage(tokenHash, testEvent);
      fingerprinter.recordUsage(tokenHash, { ...testEvent, success: false });
      fingerprinter.recordUsage(tokenHash, testEvent);

      const patterns = fingerprinter.getUsagePatterns(tokenHash);
      expect(patterns?.successRate).toBe(2/3);
    });
  });

  describe('detectAnomalies', () => {
    let tokenHash: string;
    let normalEvent: TokenUsageEvent;

    beforeEach(() => {
      // Use real Date for anomaly tests
      dateSpy.mockRestore();

      // Initialize fingerprinter with normal hours
      const normalHoursDate = new Date('2024-03-30T12:00:00Z');
      tokenHash = fingerprinter.initializeTracking('test-token', 'Test Token');
      normalEvent = {
        timestamp: normalHoursDate,
        operation: 'api_call',
        source: '192.168.1.1',
        success: true
      };

      // Record some initial normal events to establish baseline
      for (let i = 0; i < 10; i++) {
        fingerprinter.recordUsage(tokenHash, {
          ...normalEvent,
          source: '192.168.1.1',
          operation: 'api_call',
          success: true
        });
      }

      // Refresh spies after setup to avoid bleed from baseline events
      warnSpy = jest.fn();
      infoSpy = jest.fn();
      (logger as unknown as { warn: jest.Mock }).warn = warnSpy as jest.Mock;
      (logger as unknown as { info: jest.Mock }).info = infoSpy as jest.Mock;
      (fingerprinter as unknown as { logger: Logger }).logger = logger;
    });

    it('should detect new source', () => {
      fingerprinter.recordUsage(tokenHash, { ...normalEvent, source: 'new-source' });

      expect(warnSpy).toHaveBeenCalledWith(
        'New usage source detected for token: Test Token',
        expect.objectContaining({
          fingerprint: tokenHash,
          source: 'new-source'
        })
      );
    });

    it('should detect new operation', () => {
      fingerprinter.recordUsage(tokenHash, { ...normalEvent, operation: 'new-op' });

      expect(warnSpy).toHaveBeenCalledWith(
        'New operation type detected for token: Test Token',
        expect.objectContaining({
          fingerprint: tokenHash,
          operation: 'new-op'
        })
      );
    });

    it('should detect unusual failure rate', async () => {
      // Setup with proper initialization
      const token = 'test-token';
      const tokenHash = fingerprinter.initializeTracking(token, 'Test Token');

      // Record initial successes
      await Promise.all(Array(10).fill(0).map(() => 
        fingerprinter.recordUsage(tokenHash, { 
          success: true,
          timestamp: new Date(),
          operation: 'test_operation',
          source: 'test_source',
          context: { test: true }
        })
      ));

      // Clear mock calls from initialization
      warnSpy.mockClear();

      // Record failures to trigger warning
      await Promise.all(Array(8).fill(0).map(() => 
        fingerprinter.recordUsage(tokenHash, { 
          success: false,
          timestamp: new Date(),
          operation: 'test_operation',
          source: 'test_source',
          context: { test: false }
        })
      ));

      // Assert
      expect(warnSpy).toHaveBeenCalledWith(
        'Unusual failure rate detected for token: Test Token',
        expect.objectContaining({
          fingerprint: tokenHash,
          recentSuccessRate: expect.any(Number)
        })
      );
    }, 10000);

    it('should detect off-hours usage', () => {
      // Create fixed dates for testing
      const normalHoursDate = new Date('2024-03-30T12:00:00Z');
      const offHoursDate = new Date('2024-03-30T02:00:00Z');

      // Pre-populate patterns to avoid new source/operation warnings
      fingerprinter.recordUsage(tokenHash, { 
        success: true,
        timestamp: normalHoursDate,
        operation: 'after_hours_operation',
        source: 'test_source',
        context: { type: 'setup' }
      });

      // Clear mock calls after setup
      warnSpy.mockClear();

      // Record off-hours usage
      const offHoursEvent: TokenUsageEvent = {
        success: true,
        timestamp: offHoursDate,
        operation: 'after_hours_operation',
        source: 'test_source',
        context: { type: 'after-hours-test' }
      };
      fingerprinter.recordUsage(tokenHash, offHoursEvent);

      // Assert
      expect(warnSpy).toHaveBeenCalledWith(
        'Off-hours token usage detected: Test Token',
        expect.objectContaining({
          fingerprint: tokenHash,
          currentHour: 2
        })
      );
    });
  });

  describe('getFingerprint', () => {
    it('should return null for unknown fingerprint', () => {
      expect(fingerprinter.getFingerprint('unknown')).toBeNull();
    });

    it('should return fingerprint data for known token', () => {
      const hash = fingerprinter.initializeTracking('test-token', 'Test Token');
      const fingerprint = fingerprinter.getFingerprint(hash);
      expect(fingerprint).toBeDefined();
      expect(fingerprint?.hash).toBe(hash);
    });
  });

  describe('getUsageHistory', () => {
    let tokenHash: string;

    beforeEach(() => {
      tokenHash = fingerprinter.initializeTracking('test-token', 'Test Token');
      for (let i = 0; i < 3; i++) {
        fingerprinter.recordUsage(tokenHash, {
          timestamp: new Date(),
          operation: `op${i}`,
          source: `source${i}`,
          success: true
        });
      }
    });

    it('should return full history when no limit specified', () => {
      const history = fingerprinter.getUsageHistory(tokenHash);
      expect(history).toHaveLength(3);
    });

    it('should respect limit parameter', () => {
      const history = fingerprinter.getUsageHistory(tokenHash, 2);
      expect(history).toHaveLength(2);
      expect(history[0].operation).toBe('op1');
      expect(history[1].operation).toBe('op2');
    });

    it('should return empty array for unknown fingerprint', () => {
      expect(fingerprinter.getUsageHistory('unknown')).toEqual([]);
    });
  });

  describe('getUsagePatterns', () => {
    it('should return null for unknown fingerprint', () => {
      expect(fingerprinter.getUsagePatterns('unknown')).toBeNull();
    });

    it('should return patterns for known token', () => {
      const hash = fingerprinter.initializeTracking('test-token', 'Test Token');
      fingerprinter.recordUsage(hash, {
        timestamp: new Date(),
        operation: 'test-op',
        source: 'test-source',
        success: true
      });

      const patterns = fingerprinter.getUsagePatterns(hash);
      expect(patterns).toBeDefined();
      expect(patterns?.totalUsage).toBe(1);
      expect(patterns?.sources.has('test-source')).toBe(true);
      expect(patterns?.operations.has('test-op')).toBe(true);
    });
  });

  describe('removeTracking', () => {
    it('should remove tracking data', () => {
      const hash = fingerprinter.initializeTracking('test-token', 'Test Token');
      fingerprinter.recordUsage(hash, {
        timestamp: new Date(),
        operation: 'test-op',
        source: 'test-source',
        success: true
      });

      fingerprinter.removeTracking(hash);
      expect(fingerprinter.getFingerprint(hash)).toBeNull();
      expect(fingerprinter.getUsageHistory(hash)).toEqual([]);
      expect(fingerprinter.getUsagePatterns(hash)).toBeNull();
    });
  });
}); 
