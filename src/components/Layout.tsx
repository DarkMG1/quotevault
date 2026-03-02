import React, { useState } from 'react';
import { LogOut, PlusCircle, Quote } from 'lucide-react';
import { supabase } from '../lib/supabase';
import { AddQuote } from './AddQuote';

export const Layout = ({ children }: { children: React.ReactNode }) => {
    const [isAddOpen, setIsAddOpen] = useState(false);

    const handleSignOut = async () => {
        await supabase.auth.signOut();
    };

    return (
        <div className="min-h-screen pb-20">
            {/* Header */}
            <header className="sticky top-0 z-40 bg-surface/80 backdrop-blur-md border-b border-slate-800 p-4 flex justify-between items-center shadow-lg">
                <div className="flex items-center space-x-2">
                    <Quote className="w-6 h-6 text-primary-500" />
                    <h1 className="text-xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-primary-400 to-purple-400">
                        QuoteVault
                    </h1>
                </div>
                <button
                    onClick={handleSignOut}
                    className="p-2 text-slate-400 hover:text-red-400 transition-colors rounded-full hover:bg-slate-800"
                >
                    <LogOut className="w-5 h-5" />
                </button>
            </header>

            {/* Main Content */}
            <main className="max-w-2xl mx-auto w-full">
                {children}
            </main>

            {/* Floating Action Button (for mobile primarily) */}
            <button
                className="fixed bottom-6 right-6 p-4 bg-primary-600 text-white rounded-full shadow-[0_0_20px_rgba(124,58,237,0.4)] hover:scale-105 active:scale-95 transition-all hover:bg-primary-500 z-30"
                onClick={() => setIsAddOpen(true)}
            >
                <PlusCircle className="w-6 h-6" />
            </button>

            <AddQuote isOpen={isAddOpen} onClose={() => setIsAddOpen(false)} />
        </div>
    );
};
