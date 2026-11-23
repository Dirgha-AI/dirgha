import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { runCluster } from '../cluster.js';
import { existsSync, unlinkSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

const CLUSTER_CONFIG_PATH = join(homedir(), '.dirgha', 'cluster-state.json');

describe('dirgha cluster CLI subcommand', () => {
  beforeEach(() => {
    if (existsSync(CLUSTER_CONFIG_PATH)) {
      try {
        unlinkSync(CLUSTER_CONFIG_PATH);
      } catch {}
    }
  });

  afterEach(() => {
    if (existsSync(CLUSTER_CONFIG_PATH)) {
      try {
        unlinkSync(CLUSTER_CONFIG_PATH);
      } catch {}
    }
  });

  it('runs cluster init and persists cluster state', async () => {
    const code = await runCluster(['init', '--name=test-cluster', '--json'], { cwd: process.cwd() });
    expect(code).toBe(0);
    expect(existsSync(CLUSTER_CONFIG_PATH)).toBe(true);
  });

  it('runs cluster status when active', async () => {
    await runCluster(['init', '--name=test-cluster'], { cwd: process.cwd() });
    const code = await runCluster(['status', '--json'], { cwd: process.cwd() });
    expect(code).toBe(0);
  });

  it('runs cluster partition calculation for 80 layers', async () => {
    await runCluster(['init', '--name=test-cluster'], { cwd: process.cwd() });
    const code = await runCluster(['partition', '80', '42', '--json'], { cwd: process.cwd() });
    expect(code).toBe(0);
  });

  it('runs cluster leave and cleans up session', async () => {
    await runCluster(['init', '--name=test-cluster'], { cwd: process.cwd() });
    const code = await runCluster(['leave'], { cwd: process.cwd() });
    expect(code).toBe(0);
  });
});
