import { useEffect, useRef, type RefObject } from 'react';
import { decryptQuoteRecord } from '../lib/quote-crypto';
import type { Quote } from '../types';

export function localDateInputValue(date = new Date()): string {
    const pad = (value: number) => String(value).padStart(2, '0');
    return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
}

export function getErrorMessage(error: unknown, fallback: string): string {
    return error instanceof Error ? error.message :
        typeof error === 'object' && error !== null && 'message' in error && typeof error.message === 'string'
            ? error.message
            : fallback;
}

export const MAX_CIPHERTEXT_DATA_LENGTH = 262_144;

export function isCiphertextWithinLimit(payload: unknown): payload is { data: string } {
    return typeof payload === 'object' && payload !== null && 'data' in payload
        && typeof payload.data === 'string' && payload.data.length <= MAX_CIPHERTEXT_DATA_LENGTH;
}

export function isDecryptedPayload(value: unknown): value is { text: string; author: string; context?: string; source_sender?: string } {
    if (typeof value !== 'object' || value === null) return false;
    const payload = value as Record<string, unknown>;
    return typeof payload.text === 'string' &&
        typeof payload.author === 'string' &&
        (payload.context === undefined || typeof payload.context === 'string') &&
        (payload.source_sender === undefined || typeof payload.source_sender === 'string');
}

export async function decryptQuoteForDisplay(quote: Quote, encryptionKey: CryptoKey | null): Promise<Quote> {
    const safeQuote = { ...quote };
    delete safeQuote.source_sender;
    if (!quote.text.startsWith('$$E2E$$')) return safeQuote;
    try {
        if (!encryptionKey) throw new Error('No key');
        const payload: unknown = await decryptQuoteRecord(quote, encryptionKey);
        if (!isDecryptedPayload(payload)) throw new Error('Invalid encrypted quote payload');
        return {
            ...safeQuote,
            text: payload.text,
            author: payload.author,
            ...(payload.context === undefined ? {} : { context: payload.context }),
            ...(payload.source_sender === undefined ? {} : { source_sender: payload.source_sender }),
        };
    } catch {
        return { ...safeQuote, text: '🔒 Encrypted Payload (Decryption Failed)', author: 'Unknown' };
    }
}

export function useModalDialog(
    dialogRef: RefObject<HTMLDialogElement | null>,
    isOpen: boolean,
    onClose: () => void,
    initialFocusRef: RefObject<HTMLElement | null>
) {
    const onCloseRef = useRef(onClose);
    useEffect(() => {
        onCloseRef.current = onClose;
    }, [onClose]);

    useEffect(() => {
        const dialog = dialogRef.current;
        if (!dialog) return;

        const opener = document.activeElement instanceof HTMLElement ? document.activeElement : null;
        const handleCancel = (event: Event) => {
            event.preventDefault();
            onCloseRef.current();
        };
        let focusFrame: number | undefined;

        if (isOpen) {
            if (!dialog.open) dialog.showModal();
            dialog.addEventListener('cancel', handleCancel);
            focusFrame = requestAnimationFrame(() => initialFocusRef.current?.focus());
        } else if (dialog.open) {
            dialog.close();
        }

        return () => {
            dialog.removeEventListener('cancel', handleCancel);
            if (focusFrame !== undefined) cancelAnimationFrame(focusFrame);
            if (dialog.open) dialog.close();
            if (isOpen) opener?.focus();
        };
    }, [dialogRef, initialFocusRef, isOpen]);
}
