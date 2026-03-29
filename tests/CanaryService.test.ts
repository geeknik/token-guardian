import axios from 'axios';
import { sign, verify } from 'jsonwebtoken';
import { CanaryService } from '../src/canary/CanaryService';

describe('CanaryService', () => {
  let canaryService: CanaryService;
  
  beforeEach(() => {
    canaryService = new CanaryService(true);
  });

  test('should embed and detect canary in a long hex token', () => {
    const tokenName = 'test_token';
    const originalToken = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
    
    const tokenWithCanary = canaryService.embedCanary(originalToken, tokenName);
    expect(tokenWithCanary).not.toBe(originalToken);
    
    const detectedTokenName = canaryService.detectCanary(tokenWithCanary);
    expect(detectedTokenName).toBe(tokenName);
  });

  test('should not modify JWT tokens because canary embedding would invalidate the signature', () => {
    const secret = 'jwt-secret';
    const originalToken = sign({ sub: 'user-123' }, secret, {
      issuer: 'token-guardian',
      audience: 'default',
      expiresIn: 3600
    });

    const tokenWithCanary = canaryService.embedCanary(originalToken, 'jwt-token');

    expect(tokenWithCanary).toBe(originalToken);
    expect(canaryService.detectCanary(tokenWithCanary)).toBeNull();
    expect(() => verify(tokenWithCanary, secret, {
      issuer: 'token-guardian',
      audience: 'default'
    })).not.toThrow();
  });

  test('should not modify short tokens', () => {
    const shortToken = '123';
    const tokenWithCanary = canaryService.embedCanary(shortToken, 'short-token');
    expect(tokenWithCanary).toBe(shortToken);
  });

  test('should not detect canary in regular token', () => {
    const regularToken = 'REGULAR_TOKEN_123';
    const detectedTokenName = canaryService.detectCanary(regularToken);
    expect(detectedTokenName).toBeNull();
  });

  test('should not detect canaries when disabled', () => {
    const disabledService = new CanaryService(false);
    const originalToken = 'API_KEY_12345';
    const tokenName = 'test-api-key';
    
    const tokenWithCanary = disabledService.embedCanary(originalToken, tokenName);
    expect(tokenWithCanary).toBe(originalToken);
    
    const detectedTokenName = disabledService.detectCanary(tokenWithCanary);
    expect(detectedTokenName).toBeNull();
  });

  test('should reject non-HTTPS webhook destinations', () => {
    expect(() => canaryService.configureWebhook('http://alerts.example.com/hook'))
      .toThrow('HTTPS');
  });

  test('should reject localhost and private-network alert endpoints', () => {
    expect(() => canaryService.addAlertEndpoint('token', 'https://127.0.0.1/hook'))
      .toThrow('private network');
    expect(() => canaryService.addAlertEndpoint('token', 'https://localhost/hook'))
      .toThrow('private network');
  });

  test('should send alerts with bounded outbound request settings', async () => {
    const axiosPostSpy = jest.spyOn(axios, 'post').mockResolvedValue({
      status: 200,
      statusText: 'OK',
      headers: {},
      config: {},
      data: {}
    });

    canaryService.configureWebhook('https://alerts.example.com/hook');

    const internals = canaryService as unknown as {
      sendWebhookAlert: (alertData: {
        tokenName: string;
        timestamp: string;
        detectionMethod: string;
        source: { ipAddress: string; userAgent: string; timestamp: string };
        partialToken: string;
      }) => Promise<void>;
    };

    await internals.sendWebhookAlert({
      tokenName: 'token',
      timestamp: new Date().toISOString(),
      detectionMethod: 'hex',
      source: {
        ipAddress: '203.0.113.10',
        userAgent: 'jest',
        timestamp: new Date().toISOString()
      },
      partialToken: 'abcd****wxyz'
    });

    expect(axiosPostSpy).toHaveBeenCalledWith(
      'https://alerts.example.com/hook',
      expect.any(Object),
      expect.objectContaining({
        timeout: 5000,
        maxRedirects: 0,
        maxContentLength: 16 * 1024,
        maxBodyLength: 16 * 1024,
        validateStatus: expect.any(Function)
      })
    );
  });
});
