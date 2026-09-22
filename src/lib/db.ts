import Dexie, { type Table } from 'dexie';
import type { DeviceLocalState, Quote, SyncMetadata, SyncQueueItem } from '../types';

export class QuoteVaultDB extends Dexie {
    quotes!: Table<Quote, string>;
    syncQueue!: Table<SyncQueueItem, string>;
    metadata!: Table<SyncMetadata, string>;
    deviceState!: Table<DeviceLocalState, string>;

    constructor() {
        super('QuoteVaultDB');
        this.version(1).stores({
            quotes: 'id, created_at, user_id, author', // Primary key and indexed props
            syncQueue: 'id, created_at, action'
        });
        this.version(2).stores({
            quotes: 'id, created_at, user_id, author, vault_generation',
            syncQueue: 'id, operation_id, quote_id, created_at, action, actor_id, vault_generation, status',
            metadata: 'id'
        }).upgrade(async tx => {
            await tx.table('syncQueue').toCollection().modify((item: SyncQueueItem) => {
                const legacy = item as SyncQueueItem & { payload?: Quote };
                legacy.operation_id ??= legacy.id;
                legacy.id = legacy.operation_id;
                legacy.quote_id ??= legacy.payload?.id ?? legacy.id;
                legacy.status ??= 'pending';
                if (legacy.action === 'DELETE') {
                    // Legacy deletes may contain decrypted UI values. Never retain or infer their actor.
                    delete legacy.payload;
                    delete legacy.actor_id;
                    legacy.status = 'blocked';
                    legacy.error = 'Deletion created before secure sync must be repeated.';
                } else if (legacy.action === 'INSERT') {
                    // Old inserts recorded the authenticated creator as user_id.
                    legacy.actor_id ??= legacy.payload?.user_id;
                } else if (legacy.action !== 'INSERT') {
                    legacy.status = 'blocked';
                    legacy.error = 'Unsupported legacy sync operation.';
                }
            });
        });
        this.version(3).stores({
            quotes: 'id, created_at, user_id, author, vault_generation',
            syncQueue: 'id, operation_id, quote_id, created_at, action, actor_id, vault_generation, status',
            metadata: 'id',
            deviceState: 'accountId'
        });
    }
}

export const db = new QuoteVaultDB();
