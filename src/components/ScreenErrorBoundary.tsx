import { Component, type ReactNode } from 'react';

// React logs the caught error; this keeps a failed chunk from blanking the whole app.
export class ScreenErrorBoundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  state = { failed: false };
  static getDerivedStateFromError() { return { failed: true }; }
  render() {
    if (!this.state.failed) return this.props.children;
    return <div role="alert" className="p-4">
      <p>This screen could not load. Check your connection and reload.</p>
      <button type="button" onClick={() => window.location.reload()} className="mt-3 rounded-lg bg-slate-800 px-3 py-2 text-sm">Reload</button>
    </div>;
  }
}
