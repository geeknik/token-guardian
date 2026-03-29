import { GitHubRotator } from '../src/rotation/services/GitHubRotator';

describe('GitHubRotator', () => {
  test('fails closed for PAT rotation attempts', async () => {
    const rotator = new GitHubRotator();

    const result = await rotator.rotateToken('GITHUB_TOKEN', 'ghp_exampletoken');

    expect(result.success).toBe(false);
    expect(result.newExpiry).toBeNull();
    expect(result.message).toContain('unsupported');
    expect(result.warnings?.[0]).toContain('OAuth refresh token handling');
  });

  test('rejects PAT creation helper usage', async () => {
    const rotator = new GitHubRotator();

    await expect(
      rotator.createPersonalAccessToken('ghp_exampletoken', 'note', ['repo'])
    ).rejects.toThrow('unsupported');
  });
});
