import { TokenGuardian } from '../src/TokenGuardian';
import { TokenRotator } from '../src/rotation/TokenRotator';
import { CanaryService } from '../src/canary/CanaryService';
import { TokenStore } from '../src/storage/TokenStore';

// Mock dependencies
jest.mock('../src/rotation/TokenRotator');
jest.mock('../src/canary/CanaryService');
jest.mock('../src/storage/TokenStore');

describe('TokenGuardian', () => {
  // Original implementations
  const originalTokenRotator = TokenRotator;
  const originalCanaryService = CanaryService;
  const originalTokenStore = TokenStore;
  
  // Test setup
  let guardian: TokenGuardian;
  let mockTokenRotator: jest.Mocked<TokenRotator>;
  let mockCanaryService: jest.Mocked<CanaryService>;
  let mockTokenStore: jest.Mocked<TokenStore>;
  
  beforeEach(() => {
    // Clear all mocks
    jest.clearAllMocks();
    
    // Setup mock implementations
    (TokenRotator as jest.Mock).mockImplementation(() => ({
      scheduleRotation: jest.fn(),
      cancelRotation: jest.fn(),
      rotateToken: jest.fn().mockResolvedValue({
        success: true,
        message: 'Token rotated successfully',
        newToken: 'new-token-value',
        newExpiry: null
      })
    }));
    
    (CanaryService as jest.Mock).mockImplementation(() => ({
      embedCanary: jest.fn().mockImplementation((token) => `${token}-canary`),
      detectCanary: jest.fn(),
      onCanaryTriggered: jest.fn()
    }));
    
    (TokenStore as jest.Mock).mockImplementation(() => ({
      storeToken: jest.fn().mockReturnValue(true),
      updateToken: jest.fn().mockReturnValue(true),
      getToken: jest.fn().mockImplementation((tokenName) => ({
        value: `${tokenName}-value`,
        config: {
          rotationEnabled: true,
          rotationInterval: '7d',
          canaryEnabled: true,
          serviceType: 'test'
        }
      })),
      getTokenData: jest.fn().mockImplementation((tokenName) => ({
        value: `${tokenName}-value`,
        config: {
          rotationEnabled: true,
          rotationInterval: '7d',
          canaryEnabled: true,
          serviceType: 'test'
        },
        created: new Date(),
        expiry: null,
        lastUsed: null
      })),
      recordTokenUsage: jest.fn(),
      removeToken: jest.fn().mockReturnValue(true),
      listTokens: jest.fn().mockReturnValue(['TOKEN1', 'TOKEN2']),
      getAuditLog: jest.fn().mockReturnValue([
        { tokenName: 'TOKEN1', action: 'store', timestamp: new Date() }
      ])
    }));
    
    // Create instance with mocks
    guardian = new TokenGuardian({
      services: ['test'],
      rotationInterval: '7d',
      canaryEnabled: true,
      encryptionKey: 'test-key',
      logLevel: 'silent'
    });
    
    // Get mock instances
    mockTokenRotator = TokenRotator as unknown as jest.Mocked<TokenRotator>;
    mockCanaryService = CanaryService as unknown as jest.Mocked<CanaryService>;
    mockTokenStore = TokenStore as unknown as jest.Mocked<TokenStore>;
  });
  
  afterAll(() => {
    // Restore original implementations
    (TokenRotator as unknown) = originalTokenRotator;
    (CanaryService as unknown) = originalCanaryService;
    (TokenStore as unknown) = originalTokenStore;
  });
  
  describe('initialization', () => {
    test('should initialize with default values', () => {
      const guardianWithDefaults = new TokenGuardian();
      expect(guardianWithDefaults).toBeInstanceOf(TokenGuardian);
    });
    
    test('should initialize with custom values', () => {
      const customConfig = {
        services: ['github', 'aws'],
        rotationInterval: '30d',
        canaryEnabled: false,
        encryptionKey: 'custom-key',
        logLevel: 'debug'
      };
      
      const guardianWithCustom = new TokenGuardian(customConfig);
      expect(guardianWithCustom).toBeInstanceOf(TokenGuardian);
    });
  });
  
  describe('protect', () => {
    test('should protect a token successfully', () => {
      const result = guardian.protect('TEST_TOKEN', 'token-value', {
        rotationEnabled: true,
        canaryEnabled: true,
        serviceType: 'test'
      });
      
      expect(result).toBe(true);
      expect(mockCanaryService.embedCanary).toHaveBeenCalledWith('token-value', 'TEST_TOKEN');
      expect(mockTokenStore.storeToken).toHaveBeenCalled();
      expect(mockTokenRotator.scheduleRotation).toHaveBeenCalledWith('TEST_TOKEN', 'test', '7d');
    });
    
    test('should protect a token without canary', () => {
      const result = guardian.protect('TEST_TOKEN', 'token-value', {
        rotationEnabled: true,
        canaryEnabled: false,
        serviceType: 'test'
      });
      
      expect(result).toBe(true);
      expect(mockCanaryService.embedCanary).not.toHaveBeenCalled();
      expect(mockTokenStore.storeToken).toHaveBeenCalled();
    });
    
    test('should protect a token without rotation', () => {
      const result = guardian.protect('TEST_TOKEN', 'token-value', {
        rotationEnabled: false,
        canaryEnabled: true,
        serviceType: 'test'
      });
      
      expect(result).toBe(true);
      expect(mockTokenRotator.scheduleRotation).not.toHaveBeenCalled();
    });
    
    test('should handle storage failure', () => {
      (mockTokenStore.storeToken as jest.Mock).mockReturnValueOnce(false);
      
      const result = guardian.protect('TEST_TOKEN', 'token-value');
      
      expect(result).toBe(false);
    });
  });
  
  describe('getToken', () => {
    test('should retrieve a token successfully', () => {
      const token = guardian.getToken('TEST_TOKEN');
      
      expect(token).toBe('TEST_TOKEN-value');
      expect(mockTokenStore.getToken).toHaveBeenCalledWith('TEST_TOKEN');
      expect(mockTokenStore.recordTokenUsage).toHaveBeenCalledWith('TEST_TOKEN');
    });
    
    test('should return null for non-existent token', () => {
      (mockTokenStore.getToken as jest.Mock).mockReturnValueOnce(null);
      
      const token = guardian.getToken('NONEXISTENT_TOKEN');
      
      expect(token).toBeNull();
      expect(mockTokenStore.recordTokenUsage).not.toHaveBeenCalled();
    });
  });
  
  describe('rotateToken', () => {
    test('should rotate a token successfully', async () => {
      const result = await guardian.rotateToken('TEST_TOKEN');
      
      expect(result.success).toBe(true);
      expect(mockTokenRotator.rotateToken).toHaveBeenCalled();
      expect(mockCanaryService.embedCanary).toHaveBeenCalled();
      expect(mockTokenStore.updateToken).toHaveBeenCalled();
    });
    
    test('should handle nonexistent token', async () => {
      (mockTokenStore.getTokenData as jest.Mock).mockReturnValueOnce(null);
      
      const result = await guardian.rotateToken('NONEXISTENT_TOKEN');
      
      expect(result.success).toBe(false);
      expect(mockTokenRotator.rotateToken).not.toHaveBeenCalled();
    });
    
    test('should handle rotation failure', async () => {
      (mockTokenRotator.rotateToken as jest.Mock).mockResolvedValueOnce({
        success: false,
        message: 'Rotation failed',
        newExpiry: null
      });
      
      const result = await guardian.rotateToken('TEST_TOKEN');
      
      expect(result.success).toBe(false);
      expect(mockTokenStore.updateToken).not.toHaveBeenCalled();
    });
    
    test('should handle update failure after successful rotation', async () => {
      (mockTokenStore.updateToken as jest.Mock).mockReturnValueOnce(false);
      
      const result = await guardian.rotateToken('TEST_TOKEN');
      
      expect(result.success).toBe(false);
      expect(result.message).toContain('failed to update');
    });
  });
  
  describe('listTokens', () => {
    test('should list all tokens', () => {
      const tokens = guardian.listTokens();
      
      expect(tokens).toEqual(['TOKEN1', 'TOKEN2']);
      expect(mockTokenStore.listTokens).toHaveBeenCalled();
    });
  });
  
  describe('removeToken', () => {
    test('should remove a token successfully', () => {
      const result = guardian.removeToken('TEST_TOKEN');
      
      expect(result).toBe(true);
      expect(mockTokenRotator.cancelRotation).toHaveBeenCalledWith('TEST_TOKEN');
      expect(mockTokenStore.removeToken).toHaveBeenCalledWith('TEST_TOKEN');
    });
    
    test('should handle removal failure', () => {
      (mockTokenStore.removeToken as jest.Mock).mockReturnValueOnce(false);
      
      const result = guardian.removeToken('TEST_TOKEN');
      
      expect(result).toBe(false);
    });
  });
  
  describe('getAuditLog', () => {
    test('should get the complete audit log', () => {
      const log = guardian.getAuditLog();
      
      expect(log).toHaveLength(1);
      expect(mockTokenStore.getAuditLog).toHaveBeenCalled();
    });
    
    test('should get the audit log for a specific token', () => {
      guardian.getAuditLog('TOKEN1');
      
      expect(mockTokenStore.getAuditLog).toHaveBeenCalledWith('TOKEN1');
    });
  });
  
  describe('scanString', () => {
    test('should scan a string for secrets', () => {
      const scanResult = guardian.scanString('My API key is sk_test_1234567890abcdef');
      
      // This test depends on actual PatternScanner implementation,
      // which isn't mocked, so we'll just check that it returns something
      expect(scanResult).toBeDefined();
      expect(scanResult).toHaveProperty('found');
      expect(scanResult).toHaveProperty('matches');
      expect(scanResult).toHaveProperty('entropy');
    });
  });
});
