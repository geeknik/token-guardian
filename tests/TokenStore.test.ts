import { TokenStore } from '../src/storage/TokenStore';

describe('TokenStore', () => {
  const encryptionKey = 'test-encryption-key-1234567890';
  const tokenName = 'TEST_TOKEN';
  const tokenValue = 'test-token-value-1234567890';
  const tokenConfig = {
    rotationEnabled: true,
    rotationInterval: '7d',
    canaryEnabled: true,
    serviceType: 'test'
  };
  
  let tokenStore: TokenStore;
  
  beforeEach(() => {
    tokenStore = new TokenStore(encryptionKey);
  });
  
  test('should store and retrieve a token', () => {
    // Store token
    const stored = tokenStore.storeToken(tokenName, tokenValue, tokenConfig);
    expect(stored).toBe(true);
    
    // Retrieve token
    const token = tokenStore.getToken(tokenName);
    expect(token).not.toBeNull();
    expect(token?.value).toBe(tokenValue);
    expect(token?.config).toEqual(tokenConfig);
  });
  
  test('should update a token', () => {
    // Store initial token
    tokenStore.storeToken(tokenName, tokenValue, tokenConfig);
    
    // Update token
    const newValue = 'new-token-value-0987654321';
    const updated = tokenStore.updateToken(tokenName, newValue);
    expect(updated).toBe(true);
    
    // Verify update
    const token = tokenStore.getToken(tokenName);
    expect(token?.value).toBe(newValue);
  });
  
  test('should update token expiry', () => {
    // Store initial token
    tokenStore.storeToken(tokenName, tokenValue, tokenConfig);
    
    // Update token with expiry
    const newExpiry = new Date();
    newExpiry.setDate(newExpiry.getDate() + 30); // 30 days in the future
    const updated = tokenStore.updateToken(tokenName, tokenValue, newExpiry);
    expect(updated).toBe(true);
    
    // Verify update
    const tokenData = tokenStore.getTokenData(tokenName);
    expect(tokenData?.expiry).toEqual(newExpiry);
  });
  
  test('should record token usage', () => {
    // Store token
    tokenStore.storeToken(tokenName, tokenValue, tokenConfig);
    
    // Record usage
    tokenStore.recordTokenUsage(tokenName);
    
    // Verify usage recorded
    const tokenData = tokenStore.getTokenData(tokenName);
    expect(tokenData?.lastUsed).not.toBeNull();
  });
  
  test('should remove a token', () => {
    // Store token
    tokenStore.storeToken(tokenName, tokenValue, tokenConfig);
    
    // Remove token
    const removed = tokenStore.removeToken(tokenName);
    expect(removed).toBe(true);
    
    // Verify token is gone
    const token = tokenStore.getToken(tokenName);
    expect(token).toBeNull();
  });
  
  test('should list all tokens', () => {
    // Store multiple tokens
    tokenStore.storeToken('TOKEN1', 'value1', tokenConfig);
    tokenStore.storeToken('TOKEN2', 'value2', tokenConfig);
    tokenStore.storeToken('TOKEN3', 'value3', tokenConfig);
    
    // List tokens
    const tokens = tokenStore.listTokens();
    expect(tokens.length).toBe(3);
    expect(tokens).toContain('TOKEN1');
    expect(tokens).toContain('TOKEN2');
    expect(tokens).toContain('TOKEN3');
  });
  
  test('should maintain an audit log', () => {
    // Perform various operations
    tokenStore.storeToken(tokenName, tokenValue, tokenConfig);
    tokenStore.getToken(tokenName); // This should record usage
    tokenStore.updateToken(tokenName, 'updated-value');
    tokenStore.removeToken(tokenName);
    
    // Get audit log
    const auditLog = tokenStore.getAuditLog();
    expect(auditLog.length).toBe(4); // store, use, update, remove
    
    // Check specific operations
    const actions = auditLog.map(entry => entry.action);
    expect(actions).toContain('store');
    expect(actions).toContain('use');
    expect(actions).toContain('update');
    expect(actions).toContain('remove');
  });
  
  test('should filter audit log by token name', () => {
    // Store and manipulate multiple tokens
    tokenStore.storeToken('TOKEN1', 'value1', tokenConfig);
    tokenStore.storeToken('TOKEN2', 'value2', tokenConfig);
    tokenStore.getToken('TOKEN1');
    tokenStore.updateToken('TOKEN2', 'new-value');
    
    // Get filtered audit log
    const token1Log = tokenStore.getAuditLog('TOKEN1');
    expect(token1Log.length).toBe(2); // store, use
    expect(token1Log.every(entry => entry.tokenName === 'TOKEN1')).toBe(true);
    
    const token2Log = tokenStore.getAuditLog('TOKEN2');
    expect(token2Log.length).toBe(2); // store, update
    expect(token2Log.every(entry => entry.tokenName === 'TOKEN2')).toBe(true);
  });
});
