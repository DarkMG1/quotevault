import { useEffect, useEffectEvent, useRef, useState, type PointerEvent } from 'react';
import { CloudOff, Cloud, Trash2, Pencil } from 'lucide-react';
import type { Quote } from '../types';
import { dayFormat } from './ui';

const SWIPE_TO_DELETE = -100;
const DRAG_THRESHOLD = 3;

interface QuoteCardProps {
    quote: Quote;
    canEdit: boolean;
    canDelete: boolean;
    /** Removed from the feed: fade out, then call onLeft. */
    leaving: boolean;
    onLeft: () => void;
    onEdit: () => void;
    onDelete: () => void;
}

export const QuoteCard = ({ quote, canEdit, canDelete, leaving, onLeft, onEdit, onDelete }: QuoteCardProps) => {
    // Visual drag offset while swiping; null when idle.
    const [offset, setOffset] = useState<number | null>(null);
    const drag = useRef<AbortController | null>(null);
    const card = useRef<HTMLDivElement>(null);
    const left = useEffectEvent(onLeft);
    useEffect(() => () => drag.current?.abort(), []);
    useEffect(() => {
        if (!leaving || !card.current) return;
        const fade = card.current.animate([{ opacity: 1 }, { opacity: 0 }], { duration: 150, easing: 'ease-out', fill: 'forwards' });
        fade.onfinish = () => left();
        return () => fade.cancel();
    }, [leaving]);
    const unsynced = quote.sync_status === 'pending' || quote.sync_status === 'rejected';
    const syncLabel = quote.sync_status === 'rejected' ? 'Sync rejected' : 'Pending Sync';

    // Swipe left past 100px to ask for deletion. The card follows at half speed and never moves right.
    const startSwipe = (down: PointerEvent) => {
        if (!down.isPrimary || down.button > 0) return;
        drag.current?.abort();
        const controller = new AbortController();
        drag.current = controller;
        let dx = 0;
        let dragging = false;
        const move = (event: globalThis.PointerEvent) => {
            if (event.pointerId !== down.pointerId) return;
            dx = event.clientX - down.clientX;
            dragging ||= Math.hypot(dx, event.clientY - down.clientY) >= DRAG_THRESHOLD;
            if (dragging) setOffset(Math.min(dx, 0) / 2);
        };
        const end = (event: globalThis.PointerEvent) => {
            if (event.pointerId !== down.pointerId) return;
            controller.abort();
            setOffset(null);
            if (dragging && dx < SWIPE_TO_DELETE) onDelete();
        };
        const options = { signal: controller.signal };
        window.addEventListener('pointermove', move, options);
        window.addEventListener('pointerup', end, options);
        window.addEventListener('pointercancel', end, options);
    };

    return (
        <div ref={card} className="relative rounded-2xl">
            {/* Only while swiping: an always-present red panel shows through cards that paint late during fast scrolls. */}
            {canDelete && !!offset && (
                <div className="absolute inset-0 bg-red-500/80 rounded-2xl flex items-center justify-end px-8 z-0">
                    <Trash2 aria-hidden="true" className="w-6 h-6 text-white" />
                </div>
            )}
            <div
                onPointerDown={canDelete ? startSwipe : undefined}
                draggable={canDelete ? false : undefined}
                style={offset === null ? undefined : { transform: `translateX(${offset}px)` }}
                className={`bg-slate-800/40 backdrop-blur-sm border border-slate-700/50 p-5 rounded-2xl relative z-10 group bg-surface touch-pan-y ${
                    canDelete ? 'select-none [-webkit-touch-callout:none]' : ''} ${offset === null ? 'transition-transform duration-300 ease-out' : ''}`}
            >
                <div className="absolute top-4 right-4 text-xs">
                    {unsynced ? (
                        <span role="img" aria-label={syncLabel} title={syncLabel}>
                            <CloudOff aria-hidden="true" className={`w-4 h-4 ${quote.sync_status === 'rejected' ? 'text-red-400' : 'text-orange-400'}`} />
                        </span>
                    ) : (
                        <span title="Synced">
                            <Cloud aria-hidden="true" className="w-4 h-4 text-emerald-400/50 opacity-0 group-hover:opacity-100 transition-opacity" />
                        </span>
                    )}
                </div>
                <blockquote className="text-lg md:text-xl font-medium text-slate-200 mb-4 leading-relaxed pr-8 select-text whitespace-pre-wrap">
                    "{quote.text}"
                </blockquote>
                <div className="flex items-center justify-between text-sm">
                    <div className="font-semibold text-primary-400">— {quote.author}</div>
                    <div className="text-slate-500 select-none">
                        {new Date(quote.quote_date || quote.created_at).toLocaleDateString(undefined, dayFormat)}
                    </div>
                </div>
                {quote.context && (
                    <div className="mt-3 pt-3 border-t border-slate-700/30 text-sm text-slate-400 italic select-text">Context: {quote.context}</div>
                )}
                {quote.source_sender && (
                    <div className="mt-3 text-sm text-slate-400 select-text">Originally shared by {quote.source_sender}</div>
                )}
                {canEdit && (
                    <button
                        type="button"
                        disabled={unsynced}
                        onClick={onEdit}
                        aria-label={`Edit quote by ${quote.author}`}
                        className="mt-4 mr-3 inline-flex items-center gap-2 rounded-lg border border-slate-600 px-3 py-2 text-sm font-medium text-slate-300 hover:bg-slate-700/50 disabled:opacity-50"
                    >
                        <Pencil aria-hidden="true" className="h-4 w-4" /> Edit
                    </button>
                )}
                {canDelete && (
                    <button
                        type="button"
                        onClick={onDelete}
                        aria-label={`Delete quote by ${quote.author}`}
                        className="mt-4 inline-flex items-center gap-2 rounded-lg border border-red-500/20 px-3 py-2 text-sm font-medium text-red-400 hover:bg-red-500/10"
                    >
                        <Trash2 aria-hidden="true" className="h-4 w-4" /> Delete
                    </button>
                )}
            </div>
        </div>
    );
};
