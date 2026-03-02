import { db } from './db';
import { supabase } from './supabase';
import type { Quote } from '../types';

export async function addToSyncQueue(action: 'INSERT' | 'UPDATE' | 'DELETE', payload: Quote) {
    await db.syncQueue.put({
        id: payload.id, // Using the same ID to prevent duplication of identical actions
        action,
        payload,
        created_at: new Date().toISOString()
    });
}

export async function processSyncQueue() {
    if (!navigator.onLine) return; // Only process when online

    const queue = await db.syncQueue.orderBy('created_at').toArray();

    if (queue.length === 0) return;

    for (const item of queue) {
        try {
            if (item.action === 'INSERT') {
                const { error } = await supabase
                    .from('quotes')
                    .insert([{
                        id: item.payload.id,
                        text: item.payload.text,
                        author: item.payload.author,
                        context: item.payload.context,
                        quote_date: item.payload.quote_date,
                        created_at: item.payload.created_at,
                        user_id: item.payload.user_id
                    }]);

                if (error) throw error;
            }
            // Add UPDATE/DELETE logic here if needed later

            // On success, update the local DB to mark as synced and remove from queue
            await db.quotes.update(item.payload.id, { sync_status: 'synced' });
            await db.syncQueue.delete(item.id);

        } catch (err) {
            console.error('Sync failed for item', item, err);
            // We will break and retry later to maintain order
            break;
        }
    }
}

// Set up a listener for when the browser comes online
window.addEventListener('online', () => {
    processSyncQueue();
});

// Also try to sync when the browser regains focus/visibility
// Mobile browsers often pause JS and miss the 'online' event when backgrounded
document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') {
        processSyncQueue();
    }
});
