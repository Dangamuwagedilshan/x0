export interface X0Config {
  apiKey: string;
  baseUrl?: string;
  timeout?: number;
}

export interface SessionConfig {
  agentId: string;
  agentName?: string;
  userWallet: string;
  maxPerTransaction?: number;
  maxPerDay?: number;
  maxPerWeek?: number;
  maxPerMonth?: number;
  requireApprovalAbove?: number;
  expiresIn?: number;
  metadata?: Record<string, unknown>;
}

export interface Session {
  id: string;
  sessionToken: string;
  agentId: string;
  agentName?: string;
  userWallet: string;
  maxPerTransaction?: number;
  maxPerDay?: number;
  maxPerWeek?: number;
  maxPerMonth?: number;
  requireApprovalAbove?: number;
  spentToday: number;
  spentThisWeek: number;
  spentThisMonth: number;
  isActive: boolean;
  createdAt: string;
  expiresAt: string;
}

export interface SessionKeyConfig {
  limitUsdc: number;
  expiresIn?: number;
  dailyLimitUsdc?: number;
  weeklyLimitUsdc?: number;
  monthlyLimitUsdc?: number;
  deviceFingerprint?: string;
}

export interface SessionKey {
  id: string;
  publicKey: string;
  limitUsdc: number;
  usedAmountUsdc: number;
  dailyLimitUsdc?: number;
  weeklyLimitUsdc?: number;
  monthlyLimitUsdc?: number;
  isActive: boolean;
  expiresAt: string;
  createdAt: string;
}

export interface PaymentConfig {
  sessionToken: string;
  amount: number;
  recipient: string;
  currency?: 'USDC' | 'USDT';
  memo?: string;
  idempotencyKey?: string;
  metadata?: Record<string, unknown>;
}

export interface Payment {
  id: string;
  status: 'pending' | 'confirmed' | 'failed' | 'expired';
  amount: number;
  currency: string;
  transactionSignature?: string;
  fromWallet: string;
  toWallet: string;
  createdAt: string;
}

export interface SpendingCheck {
  allowed: boolean;
  reason?: string;
  limit?: number;
  spent?: number;
  remaining?: number;
  requiresApproval?: boolean;
}

export interface PricingSuggestion {
  suggestedPrice: number;
  pppFactor: number;
  country: string;
  currency: string;
  reasoning: string;
}

export class X0Error extends Error {
  constructor(
    message: string,
    public code: string,
    public statusCode?: number,
    public details?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'X0Error';
  }
}

export class X0Client {
  private readonly config: Required<X0Config>;

  constructor(config: X0Config) {
    this.config = {
      apiKey: config.apiKey,
      baseUrl: config.baseUrl ?? 'https://api.x0.dev',
      timeout: config.timeout ?? 30000,
    };
  }

  private async request<T>(
    method: string,
    path: string,
    body?: unknown
  ): Promise<T> {
    const url = `${this.config.baseUrl}${path}`;
    const controller = new (globalThis as any).AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.config.timeout);

    try {
      const response = await fetch(url, {
        method,
        headers: {
          'Authorization': `Bearer ${this.config.apiKey}`,
          'Content-Type': 'application/json',
        },
        body: body ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });

      const data = await response.json() as { error?: { message?: string; code?: string; details?: Record<string, unknown> } };

      if (!response.ok) {
        throw new X0Error(
          data.error?.message ?? 'Request failed',
          data.error?.code ?? 'UNKNOWN_ERROR',
          response.status,
          data.error?.details
        );
      }

      return data as T;
    } finally {
      clearTimeout(timeoutId);
    }
  }

  async createSession(config: SessionConfig): Promise<Session> {
    return this.request<Session>('POST', '/api/v1/sessions', {
      agent_id: config.agentId,
      agent_name: config.agentName,
      user_wallet: config.userWallet,
      max_per_transaction: config.maxPerTransaction,
      max_per_day: config.maxPerDay,
      max_per_week: config.maxPerWeek,
      max_per_month: config.maxPerMonth,
      require_approval_above: config.requireApprovalAbove,
      expires_in: config.expiresIn,
      metadata: config.metadata,
    });
  }

  async getSession(sessionId: string): Promise<Session> {
    return this.request<Session>('GET', `/api/v1/sessions/${sessionId}`);
  }

  async listSessions(): Promise<Session[]> {
    const response = await this.request<{ sessions: Session[] }>('GET', '/api/v1/sessions');
    return response.sessions;
  }

  async revokeSession(sessionId: string): Promise<void> {
    await this.request<void>('POST', `/api/v1/sessions/${sessionId}/revoke`);
  }

  async createSessionKey(config: SessionKeyConfig): Promise<SessionKey> {
    return this.request<SessionKey>('POST', '/api/v1/session-keys/create', {
      limit_usdc: config.limitUsdc,
      expires_in: config.expiresIn,
      daily_limit_usdc: config.dailyLimitUsdc,
      weekly_limit_usdc: config.weeklyLimitUsdc,
      monthly_limit_usdc: config.monthlyLimitUsdc,
      device_fingerprint: config.deviceFingerprint,
    });
  }

  async getSessionKeyStatus(sessionKeyId: string): Promise<SessionKey> {
    return this.request<SessionKey>('POST', '/api/v1/session-keys/status', {
      session_key_id: sessionKeyId,
    });
  }

  async revokeSessionKey(sessionKeyId: string): Promise<void> {
    await this.request<void>('POST', '/api/v1/session-keys/revoke', {
      session_key_id: sessionKeyId,
    });
  }

  async listSessionKeys(): Promise<SessionKey[]> {
    const response = await this.request<{ session_keys: SessionKey[] }>('GET', '/api/v1/session-keys/list');
    return response.session_keys;
  }

  async makePayment(config: PaymentConfig): Promise<Payment> {
    return this.request<Payment>('POST', '/api/v1/payments', {
      session_token: config.sessionToken,
      amount: config.amount,
      recipient: config.recipient,
      currency: config.currency ?? 'USDC',
      memo: config.memo,
      idempotency_key: config.idempotencyKey,
      metadata: config.metadata,
    });
  }

  async checkSpendingLimit(
    sessionToken: string,
    amount: number
  ): Promise<SpendingCheck> {
    return this.request<SpendingCheck>('POST', '/api/v1/spending/check', {
      session_token: sessionToken,
      amount,
    });
  }

  async getPricingSuggestion(
    basePrice: number,
    targetCountry: string
  ): Promise<PricingSuggestion> {
    return this.request<PricingSuggestion>('POST', '/api/v1/pricing/suggest', {
      base_price: basePrice,
      target_country: targetCountry,
    });
  }

  async getPppFactor(country: string): Promise<{ factor: number; country: string }> {
    return this.request<{ factor: number; country: string }>('POST', '/api/v1/pricing/ppp-factor', {
      country,
    });
  }
}

export function createClient(config: X0Config): X0Client {
  return new X0Client(config);
}

export default X0Client;

