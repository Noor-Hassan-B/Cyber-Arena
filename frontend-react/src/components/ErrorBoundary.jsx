import React from 'react';
import { AlertOctagon, RefreshCw, RotateCcw, ShieldAlert } from 'lucide-react';

export default class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null, errorInfo: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error('Unhandled SOC UI Exception caught by ErrorBoundary:', error, errorInfo);
    this.setState({ errorInfo });
  }

  handleResetState = () => {
    try {
      localStorage.removeItem('aegis_theme');
      localStorage.removeItem('aegis_scenario');
    } catch (e) {
      // ignore
    }
    this.setState({ hasError: false, error: null, errorInfo: null });
    window.location.reload();
  };

  handleReload = () => {
    this.setState({ hasError: false, error: null, errorInfo: null });
    window.location.reload();
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-[#070A12] text-slate-100 flex items-center justify-center p-4">
          <div className="max-w-xl w-full bg-[#0B0F19] border border-red-500/30 rounded-2xl p-6 shadow-2xl space-y-4">
            <div className="flex items-start gap-3">
              <div className="p-2.5 rounded-xl bg-red-950/60 border border-red-500/40 text-red-400 shrink-0">
                <ShieldAlert className="w-6 h-6" />
              </div>
              <div className="flex-1">
                <h1 className="text-base font-bold text-white flex items-center gap-2">
                  <span>SOC Platform Handled Exception</span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-red-950 border border-red-800 text-red-300">
                    ISOLATED
                  </span>
                </h1>
                <p className="text-xs text-slate-400 mt-1">
                  An unhandled UI state exception was safely intercepted by the Error Boundary. No telemetry data or active forensic sessions were lost.
                </p>
              </div>
            </div>

            {this.state.error && (
              <div className="bg-[#070A12] border border-slate-800 rounded-xl p-3 font-mono text-[11px] text-red-300 break-all select-all">
                {String(this.state.error.message || this.state.error)}
              </div>
            )}

            <div className="flex flex-wrap items-center justify-end gap-2 pt-2 border-t border-slate-800">
              <button
                onClick={this.handleResetState}
                className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200 transition"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                <span>Reset Local State</span>
              </button>
              <button
                onClick={this.handleReload}
                className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-xs font-semibold text-white transition shadow"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                <span>Reload Platform</span>
              </button>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
