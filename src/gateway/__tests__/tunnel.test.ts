import { describe, it, expect } from 'vitest';
import { DirghaTunnelClient } from '../tunnel.js';

describe('Dirgha Tunnel: DirghaTunnelClient Protocol', () => {
  it('instantiates with custom options and default ports', () => {
    const client = new DirghaTunnelClient({
      relayUrl: 'wss://custom.relay.example/v1',
      clientId: 'worker-node-1',
      localPort: 4040,
    });

    const status = client.getStatus();
    expect(status.connected).toBe(false);
    expect(status.relayUrl).toBe('wss://custom.relay.example/v1');
    expect(status.bytesReceived).toBe(0);
    expect(status.bytesSent).toBe(0);
  });

  it('safely handles send when not connected', () => {
    const client = new DirghaTunnelClient();
    const sent = client.send({ test: 'payload' });
    expect(sent).toBe(false);
  });

  it('disconnects and resets socket references cleanly', () => {
    const client = new DirghaTunnelClient();
    client.disconnect();
    const status = client.getStatus();
    expect(status.connected).toBe(false);
  });
});
