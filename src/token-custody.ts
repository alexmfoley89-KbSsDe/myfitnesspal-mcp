/**
 * Per-user Durable Object owning the MyFitnessPal token chain — the single
 * writer that ends refresh-rotation races between MCP sessions (each Claude
 * surface/conversation is its own McpAgent DO, but they all funnel token work
 * here). Addressed by idFromName(userHash); the logic lives in TokenVault
 * (token-vault.ts), which is unit-tested without Workers runtime.
 *
 * Security: the chain is AES-GCM sealed with SESSION_ENCRYPTION_KEY before it
 * touches DO storage, and an alarm self-purges everything after 30 days
 * without use — a disconnected connector never leaves a live credential
 * behind indefinitely (mirrors the old sealed-KV TTL).
 */
import { DurableObject } from "cloudflare:workers";
import type { Env } from "./types";
import { TokenVault, type VaultRequest, type VaultTokenResult } from "./token-vault";

const INACTIVITY_PURGE_MS = 30 * 24 * 60 * 60 * 1000;
const LAST_USED_KEY = "lastUsed";

export class MfpTokenCustody extends DurableObject<Env> {
  private vaultInstance?: TokenVault;

  private vault(): TokenVault {
    if (!this.vaultInstance) {
      this.vaultInstance = new TokenVault({
        storage: this.ctx.storage,
        creds: { clientId: this.env.MFP_CLIENT_ID, clientSecret: this.env.MFP_CLIENT_SECRET },
        sealSecret: this.env.SESSION_ENCRYPTION_KEY,
      });
    }
    return this.vaultInstance;
  }

  async getToken(req: VaultRequest): Promise<VaultTokenResult> {
    const result = await this.vault().getToken(req);
    await this.touch();
    return result;
  }

  async peek(): Promise<{ expiresAt?: number }> {
    return this.vault().peek();
  }

  /** Full wipe (delete_my_data). The next getToken reseeds from the grant. */
  async purge(): Promise<void> {
    await this.vault().purge();
    await this.ctx.storage.deleteAll();
    await this.ctx.storage.deleteAlarm();
  }

  /** Every use pushes the self-destruct out another 30 days. */
  private async touch(): Promise<void> {
    const now = Date.now();
    await this.ctx.storage.put(LAST_USED_KEY, now);
    await this.ctx.storage.setAlarm(now + INACTIVITY_PURGE_MS);
  }

  async alarm(): Promise<void> {
    const lastUsed = (await this.ctx.storage.get<number>(LAST_USED_KEY)) ?? 0;
    const dueAt = lastUsed + INACTIVITY_PURGE_MS;
    if (Date.now() >= dueAt - 1000) {
      await this.ctx.storage.deleteAll();
    } else {
      // touch() normally rescheduled us already; belt and braces.
      await this.ctx.storage.setAlarm(dueAt);
    }
  }
}
