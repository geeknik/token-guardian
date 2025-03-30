import { TokenStore } from '../src/storage/TokenStore';
import { TokenConfig } from '../src/interfaces/TokenConfig';

describe('TokenStore', () => {
  let tokenStore: TokenStore;
  const encryptionKey = 'test-encryption-key-32-bytes-long!!';
  const config: TokenConfig = {
    rotationEnabled: true,
    rotationInterval: '7d',
    canaryEnabled: true,
    serviceType: 'test'
  };

  beforeEach(() => {
    tokenStore = new TokenStore(encryptionKey);
  });

  test('should store and retrieve token', () => {
    const tokenName = 'test-token';
    const tokenValue = 'test-value';
    
    const stored = tokenStore.storeToken(tokenName, tokenValue, config);
    expect(stored).toBe(true);
    
    const retrieved = tokenStore.getToken(tokenName);
    expect(retrieved).toBeTruthy();
    expect(retrieved?.value).toBe(tokenValue);
    expect(retrieved?.config).toEqual(config);
  });

  test('should update token value', () => {
    const tokenName = 'test-token';
    const initialValue = 'initial-value';
    const newValue = 'updated-value';
    
    tokenStore.storeToken(tokenName, initialValue, config);
    const updated = tokenStore.updateToken(tokenName, newValue);
    expect(updated).toBe(true);
    
    const retrieved = tokenStore.getToken(tokenName);
    expect(retrieved?.value).toBe(newValue);
  });

  test('should remove token', () => {
    const tokenName = 'test-token';
    const tokenValue = 'test-value';
    
    tokenStore.storeToken(tokenName, tokenValue, config);
    const removed = tokenStore.removeToken(tokenName);
    expect(removed).toBe(true);
    
    const retrieved = tokenStore.getToken(tokenName);
    expect(retrieved).toBeNull();
  });

  test('should maintain audit log', () => {
    const tokenName = 'test-token';
    const tokenValue = 'test-value';
    const newValue = 'updated-value';
    
    tokenStore.storeToken(tokenName, tokenValue, config);
    tokenStore.updateToken(tokenName, newValue);
    tokenStore.recordTokenUsage(tokenName);
    
    const auditLog = tokenStore.getAuditLog(tokenName);
    expect(auditLog.length).toBe(3); // store + update + use
    
    expect(auditLog[0].action).toBe('store');
    expect(auditLog[1].action).toBe('update');
    expect(auditLog[2].action).toBe('use');
  });

  test('should clear audit log on remove', () => {
    const tokenName = 'test-token';
    const tokenValue = 'test-value';
    
    tokenStore.storeToken(tokenName, tokenValue, config);
    tokenStore.updateToken(tokenName, 'value2');
    tokenStore.removeToken(tokenName);
    
    const auditLog = tokenStore.getAuditLog(tokenName);
    expect(auditLog.length).toBe(3); // store + update + remove
    expect(auditLog[2].action).toBe('remove');
  });
});
