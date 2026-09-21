export interface Quote {
    id: string; // UUID
    text: string;
    author: string;
    context?: string | null;
    quote_date?: string | null; // YYYY-MM-DD
    created_at: string; // ISO string
    user_id: string;
    vault_generation: string;
    sync_status?: 'synced' | 'pending' | 'rejected'; // Local only flag
}

export interface SyncQueueItem {
    id: string; // operation_id; never reuse a quote ID as a queue key
    operation_id: string;
    action: 'INSERT' | 'DELETE';
    quote_id: string;
    actor_id?: string;
    vault_generation?: string;
    payload?: Quote; // INSERT only; DELETE must never retain quote contents
    created_at: string;
    status?: 'pending' | 'rejected' | 'blocked';
    error?: string;
}

export interface SyncMetadata {
    id: string;
    value: string | number;
}
