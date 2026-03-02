import Dexie, { type Table } from 'dexie';
import type { Quote, SyncQueueItem } from '../types';

export class QuoteVaultDB extends Dexie {
    quotes!: Table<Quote, string>;
    syncQueue!: Table<SyncQueueItem, string>;

    constructor() {
        super('QuoteVaultDB');
        this.version(1).stores({
            quotes: 'id, created_at, user_id, author', // Primary key and indexed props
            syncQueue: 'id, created_at, action'
        });
    }
}

export const db = new QuoteVaultDB();
