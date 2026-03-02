import { useEffect } from 'react';
import { useLiveQuery } from 'dexie-react-hooks';
import { db } from '../lib/db';
import { supabase } from '../lib/supabase';
import { addToSyncQueue, processSyncQueue } from '../lib/sync';
import type { Quote } from '../types';

export const useQuotes = () => {
    const quotes = useLiveQuery(() => db.quotes.orderBy('created_at').reverse().toArray());

    // Function to pull remote changes and update local DB
    const fetchRemoteQuotes = async () => {
        if (!navigator.onLine) return;

        try {
            const { data, error } = await supabase
                .from('quotes')
                .select('*')
                .order('created_at', { ascending: false });

            if (error) throw error;
            if (data) {
                // Bulk put will overwrite existing records with same IDs, adding new ones
                await db.quotes.bulkPut(
                    data.map(q => ({ ...q, sync_status: 'synced' as const }))
                );
            }
        } catch (err) {
            console.error('Error fetching remote quotes', err);
        }
    };

    useEffect(() => {
        // Initial fetch
        fetchRemoteQuotes();

        // Setup real-time subscription for when app is online
        const subscription = supabase
            .channel('quotes_changes')
            .on('postgres_changes', { event: '*', schema: 'public', table: 'quotes' }, (payload) => {
                if (payload.eventType === 'INSERT' || payload.eventType === 'UPDATE') {
                    db.quotes.put({ ...payload.new as Quote, sync_status: 'synced' });
                } else if (payload.eventType === 'DELETE') {
                    db.quotes.delete(payload.old.id);
                }
            })
            .subscribe();

        // Also attempt to process sync queue whenever we use quotes
        processSyncQueue();

        return () => {
            subscription.unsubscribe();
        };
    }, []);

    const addQuote = async (text: string, author: string, context?: string, quoteDate?: string, userId?: string) => {
        const newQuote: Quote = {
            id: crypto.randomUUID(),
            text,
            author,
            context,
            quote_date: quoteDate,
            created_at: new Date().toISOString(),
            user_id: userId || 'anonymous',
            sync_status: navigator.onLine ? 'synced' : 'pending' // Optimistic assumption
        };

        // 1. Optimistic UI: save to local IndexedDB immediately
        await db.quotes.put(newQuote);

        // 2. Add to Sync Queue
        await addToSyncQueue('INSERT', newQuote);

        // 3. Attempt to Sync
        processSyncQueue();
    };

    const deleteQuote = async (quote: Quote) => {
        // 1. Optimistic UI: delete from local IndexedDB immediately
        await db.quotes.delete(quote.id);

        // 2. Add to Sync Queue
        await addToSyncQueue('DELETE', quote);

        // 3. Attempt to Sync
        processSyncQueue();
    };

    return {
        quotes,
        addQuote,
        deleteQuote,
        refresh: fetchRemoteQuotes
    };
};
