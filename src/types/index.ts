export interface Quote {
    id: string; // UUID
    text: string;
    author: string;
    context?: string;
    quote_date?: string; // YYYY-MM-DD
    created_at: string; // ISO string
    user_id: string;
    sync_status?: 'synced' | 'pending'; // Local only flag
}

export interface SyncQueueItem {
    id: string; // UUID matched to the quote
    action: 'INSERT' | 'UPDATE' | 'DELETE';
    payload: Quote;
    created_at: string;
}
