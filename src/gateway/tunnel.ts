/**
 * Outbound WebSocket Tunnel Protocol for Dirgha Agent Gateway.
 * Enables secure remote monitoring and fleet control from mobile or web cockpit
 * without inbound port-forwarding, router holes, or public IP exposure.
 */

import * as crypto from 'node:crypto';
import { EventEmitter } from 'node:events';

export interface TunnelOptions {
  /**
   * Relay server WebSocket URL (e.g. wss://tunnel.dirgha.ai/v1/relay)
   */
  relayUrl?: string;

  /**
   * Pairing key or authentication bearer token
   */
  token?: string;

  /**
   * Local port of the running dirgha cockpit daemon (default: 4040)
   */
  localPort?: number;

  /**
   * Workstation/machine identifier
   */
  clientId?: string;

  /**
   * Auto-reconnect on network drop (default: true)
   */
  reconnect?: boolean;
}

export interface TunnelStatus {
  connected: boolean;
  sessionId?: string;
  relayUrl: string;
  bytesReceived: number;
  bytesSent: number;
  lastPing?: string;
  error?: string;
}

export class DirghaTunnelClient extends EventEmitter {
  private relayUrl: string;
  private token?: string;
  private localPort: number;
  private clientId: string;
  private reconnect: boolean;
  private ws: any = null;
  private isTerminated = false;
  private sessionId?: string;
  private bytesReceived = 0;
  private bytesSent = 0;
  private lastPing?: string;

  constructor(options: TunnelOptions = {}) {
    super();
    this.relayUrl = options.relayUrl || 'wss://tunnel.dirgha.ai/v1/relay';
    this.token = options.token || process.env.DIRGHA_COCKPIT_TOKEN;
    this.localPort = options.localPort || 4040;
    this.clientId = options.clientId || `node_${crypto.randomBytes(4).toString('hex')}`;
    this.reconnect = options.reconnect !== false;
  }

  /**
   * Connects outbound to the relay server
   */
  public async connect(): Promise<TunnelStatus> {
    this.isTerminated = false;
    this.sessionId = `ses_${crypto.randomBytes(8).toString('hex')}`;

    // Verify WebSocket support
    const WS = (globalThis as any).WebSocket;
    if (!WS) {
      const err = 'WebSocket is not natively available in this runtime';
      this.emit('error', new Error(err));
      return this.getStatus(err);
    }

    try {
      const url = new URL(this.relayUrl);
      url.searchParams.set('client_id', this.clientId);
      url.searchParams.set('session_id', this.sessionId);
      if (this.token) {
        url.searchParams.set('token', this.token);
      }

      this.ws = new WS(url.toString());

      this.ws.onopen = () => {
        this.emit('connected', this.getStatus());
      };

      this.ws.onmessage = async (event: { data: string }) => {
        const payload = String(event.data);
        this.bytesReceived += payload.length;
        await this.handleRelayMessage(payload);
      };

      this.ws.onerror = (event: any) => {
        const errorMsg = event.message || 'Tunnel connection error';
        this.emit('error', new Error(errorMsg));
      };

      this.ws.onclose = () => {
        this.emit('disconnected');
        if (this.reconnect && !this.isTerminated) {
          setTimeout(() => this.connect(), 3000);
        }
      };

      return this.getStatus();
    } catch (err: any) {
      return this.getStatus(err.message);
    }
  }

  /**
   * Pipes an incoming message from the relay to the local loopback cockpit daemon
   */
  private async handleRelayMessage(raw: string) {
    try {
      const parsed = JSON.parse(raw);

      // Handle heartbeat ping
      if (parsed.type === 'ping') {
        this.lastPing = new Date().toISOString();
        this.send({ type: 'pong', timestamp: this.lastPing });
        return;
      }

      // Forward JSON-RPC requests to local cockpit daemon
      if (parsed.jsonrpc === '2.0' && parsed.method) {
        const res = await fetch(`http://127.0.0.1:${this.localPort}/api/rpc`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            ...(this.token ? { 'Authorization': `Bearer ${this.token}` } : {}),
          },
          body: JSON.stringify(parsed),
        });

        const rpcResponse = await res.json();
        this.send({
          type: 'rpc_response',
          requestId: parsed.id,
          payload: rpcResponse,
        });
      }
    } catch (err: any) {
      this.send({
        type: 'error',
        error: err.message,
      });
    }
  }

  /**
   * Sends an encrypted or JSON payload to the relay
   */
  public send(data: unknown): boolean {
    if (!this.ws || this.ws.readyState !== 1) {
      return false;
    }
    const message = JSON.stringify(data);
    this.bytesSent += message.length;
    this.ws.send(message);
    return true;
  }

  /**
   * Disconnects the tunnel
   */
  public disconnect() {
    this.isTerminated = true;
    if (this.ws) {
      try {
        this.ws.close();
      } catch {
        // ignore
      }
      this.ws = null;
    }
    this.emit('disconnected');
  }

  /**
   * Returns live telemetry status of the tunnel
   */
  public getStatus(error?: string): TunnelStatus {
    return {
      connected: this.ws !== null && this.ws.readyState === 1,
      sessionId: this.sessionId,
      relayUrl: this.relayUrl,
      bytesReceived: this.bytesReceived,
      bytesSent: this.bytesSent,
      lastPing: this.lastPing,
      error,
    };
  }
}
