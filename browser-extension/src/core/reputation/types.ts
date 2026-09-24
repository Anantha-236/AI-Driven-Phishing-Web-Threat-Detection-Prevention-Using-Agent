export type ReputationMatchStatus = 'KNOWN_MALICIOUS' | 'NO_MATCH' | 'UNAVAILABLE';

export interface ReputationResult {
  providerId: string;
  source: string;
  status: ReputationMatchStatus;
  checkedAt: number;
  matchedUrl: string | null;
}

export interface ReputationSnapshot {
  providerId: string;
  source: string;
  updatedAt: number | null;
  checkedAt: number;
  indicatorCount: number;
  excludedCount: number;
  state: 'ACTIVE' | 'UNAVAILABLE' | 'EXPIRED';
}

export interface ReputationProvider {
  readonly id: string;
  readonly source: string;
  status(): Promise<ReputationSnapshot>;
  refresh(force?: boolean): Promise<ReputationSnapshot>;
  lookup(url: string): Promise<ReputationResult>;
}
