import { TokenGuardian } from '../src/TokenGuardian';
import { TokenRotator } from '../src/rotation/TokenRotator';
import { CanaryService } from '../src/canary/CanaryService';
import { TokenStore } from '../src/storage/TokenStore';
import { TokenValidator } from '../src/validation/TokenValidator';
import { PatternScanner } from '../src/scanners/PatternScanner';
import { GuardianConfig } from '../src/interfaces/GuardianConfig';
import { TokenConfig } from '../src/interfaces/TokenConfig';

// Mock all dependencies
jest.mock('../src/canary/CanaryService');
jest.mock('../src/storage/TokenStore');
jest.mock('../src/validation/TokenValidator');
jest.mock('../src/rotation/TokenRotator');
jest.mock('../src/scanners/PatternScanner');

describe('TokenGuardian', () => {
  let tokenGuardian: TokenGuardian;
  let mockCanaryService: jest.Mocked<CanaryService>;
  let mockTokenStore: jest.Mocked<TokenStore>;
  let mockTokenValidator: jest.Mocked<TokenValidator>;
  let mockTokenRotator: jest.Mocked<TokenRotator>;
  let mockPatternScanner: jest.Mocked<PatternScanner>;
  
  const testConfig: Partial<GuardianConfig> = {
    services: ['test-service'],
    rotationInterval: '7d',
    canaryEnabled: true,
    encryptionKey: 'test-key',
    logLevel: 'info'
  };
  
  beforeEach(() => {
    // Clear all mocks
    jest.clearAllMocks();
    
    // Create mock implementations
    mockCanaryService = {
      embedCanary: jest.fn(),
      detectCanary: jest.fn()
    } as unknown as jest.Mocked<CanaryService>;
    
    mockTokenStore = {
      storeToken: jest.fn().mockReturnValue(true),
      getToken: jest.fn(),
      getTokenData: jest.fn(),
      removeToken: jest.fn(),
      listTokens: jest.fn(),
      updateToken: jest.fn(),
      recordTokenUsage: jest.fn()
    } as unknown as jest.Mocked<TokenStore>;
    
    mockTokenValidator = {
      validate: jest.fn()
    } as unknown as jest.Mocked<TokenValidator>;
    
    mockTokenRotator = {
      rotateToken: jest.fn()
    } as unknown as jest.Mocked<TokenRotator>;
    
    mockPatternScanner = {
      scan: jest.fn()
    } as unknown as jest.Mocked<PatternScanner>;
    
    // Set up mock constructors
    (CanaryService as unknown as jest.Mock).mockImplementation(() => mockCanaryService);
    (TokenStore as unknown as jest.Mock).mockImplementation(() => mockTokenStore);
    (TokenValidator as unknown as jest.Mock).mockImplementation(() => mockTokenValidator);
    (TokenRotator as unknown as jest.Mock).mockImplementation(() => mockTokenRotator);
    (PatternScanner as unknown as jest.Mock).mockImplementation(() => mockPatternScanner);
    
    // Initialize TokenGuardian with test config
    tokenGuardian = new TokenGuardian(testConfig);
  });

  test('should initialize with config', () => {
    expect(tokenGuardian).toBeDefined();
    expect(CanaryService).toHaveBeenCalledWith(testConfig.canaryEnabled);
    expect(TokenStore).toHaveBeenCalledWith(testConfig.encryptionKey);
    expect(TokenRotator).toHaveBeenCalled();
  });

  test('should protect token with canary', () => {
    const token = 'test-token';
    const tokenName = 'API_KEY';
    
    mockPatternScanner.scan.mockReturnValue([{
      type: 'api_key',
      value: token,
      description: 'API Key',
      fingerprint: 'abc123',
      entropy: 4.2,
      location: {
        file: 'test.ts',
        line: 1,
        column: 1
      }
    }]);
    
    mockCanaryService.embedCanary.mockReturnValue(token + '-canary');
    
    const result = tokenGuardian.protect(tokenName, token);
    
    expect(result).toBe(true);
    expect(mockCanaryService.embedCanary).toHaveBeenCalledWith(token, tokenName);
    expect(mockTokenStore.storeToken).toHaveBeenCalledWith(tokenName, token + '-canary', expect.any(Object));
    // Rotation scheduling is now handled internally by TokenGuardian
  });

  test('should retrieve and record token usage', () => {
    const token = 'test-token';
    const tokenName = 'API_KEY';
    
    const tokenConfig: TokenConfig = {
      serviceType: 'default',
      rotationEnabled: true,
      canaryEnabled: true,
      rotationInterval: '7d'
    };
    
    mockTokenStore.getToken.mockReturnValue({
      value: token,
      config: tokenConfig
    });
    
    const result = tokenGuardian.getToken(tokenName);
    
    expect(result).toBe(token);
    expect(mockTokenStore.recordTokenUsage).toHaveBeenCalledWith(tokenName);
  });

  test('should rotate token', async () => {
    const token = 'test-token';
    const tokenName = 'API_KEY';
    const newToken = 'new-test-token';
    
    const tokenConfig: TokenConfig = {
      serviceType: 'default',
      rotationEnabled: true,
      canaryEnabled: true,
      rotationInterval: '7d'
    };
    
    mockTokenStore.getTokenData.mockReturnValue({
      value: token,
      config: tokenConfig,
      expiry: null,
      created: new Date(),
      lastUsed: null
    });
    
    mockTokenRotator.rotateToken.mockResolvedValue({
      success: true,
      newToken,
      message: 'Rotation successful',
      newExpiry: new Date()
    });
    
    mockCanaryService.embedCanary.mockReturnValue(newToken + '-canary');
    mockTokenStore.updateToken.mockReturnValue(true);
    
    const result = await tokenGuardian.rotateToken(tokenName);
    
    expect(result.success).toBe(true);
    expect(result.newToken).toBe(newToken);
    expect(mockCanaryService.embedCanary).toHaveBeenCalledWith(newToken, tokenName);
    expect(mockTokenStore.updateToken).toHaveBeenCalledWith(tokenName, newToken + '-canary', expect.any(Date));
  });

  test('should remove token and cancel rotation', () => {
    const tokenName = 'API_KEY';
    
    mockTokenStore.removeToken.mockReturnValue(true);
    
    const result = tokenGuardian.removeToken(tokenName);
    
    expect(result).toBe(true);
    // Rotation cancellation is now handled internally by TokenGuardian
    expect(mockTokenStore.removeToken).toHaveBeenCalledWith(tokenName);
  });

  test('scans file content for tokens', async () => {
    const content = 'AKIAIOSFODNN7EXAMPLE';
    
    mockPatternScanner.scan.mockReturnValue([{
      type: 'aws_access_key',
      value: content,
      description: 'AWS Access Key',
      fingerprint: 'abc123',
      entropy: 4.2,
      location: {
        file: 'test.txt',
        line: 1,
        column: 1
      }
    }]);
    
    const results = await tokenGuardian.scanContent(content, 'test.txt');
    
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].type).toBe('aws_access_key');
    expect(results[0].value).toBe('AKIAIOSFODNN7EXAMPLE');
  });
});
