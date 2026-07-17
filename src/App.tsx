import { useEffect, useState, useCallback } from "react";
import TokenGate from "./components/TokenGate";
import PulseStrip from "./components/PulseStrip";
import AlertsFeed from "./components/AlertsFeed";
import { fetchAlerts, getStoredToken, clearToken } from "./lib/api";
import type { Alert } from "./lib/types";

export default function App() {
  const [connected, setConnected] = useState<boolean>(!!getStoredToken());
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [status, setStatus] = useState<"idle" | "loading" | "error">("idle");
  const [onlyUnack, setOnlyUnack] = useState(false);

  const load = useCallback(async () => {
    setStatus("loading");
    try {
      const res = await fetchAlerts(onlyUnack);
      setAlerts(res.alerts);
      setStatus("idle");
    } catch (e) {
      if ((e as Error).message === "unauthorized") {
        setConnected(false);
      }
      setStatus("error");
    }
  }, [onlyUnack]);

  useEffect(() => {
    if (!connected) return;
    load();
    const interval = setInterval(load, 15000);
    return () => clearInterval(interval);
  }, [connected, load]);

  if (!connected) {
    return <TokenGate onReady={() => setConnected(true)} />;
  }

  const criticalCount = alerts.filter((a) => a.severity === "critical").length;
  const isCompliant = criticalCount === 0;

  return (
    <div className="min-h-screen bg-base">
      <header className="border-b border-line px-6 py-4 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span
            className={`w-2 h-2 rounded-full ${isCompliant ? "bg-safe" : "bg-critical"}`}
          />
          <h1 className="font-display text-base font-semibold tracking-tight">
            IronShield FIM
          </h1>
          <span className="text-muted text-xs font-mono ml-1">
            {isCompliant ? "conforme" : `${criticalCount} alerte(s) critique(s)`}
          </span>
        </div>
        <button
          onClick={() => {
            clearToken();
            setConnected(false);
          }}
          className="text-xs text-muted hover:text-text transition-colors"
        >
          Déconnecter
        </button>
      </header>

      <main className="max-w-3xl mx-auto px-6 py-8 space-y-8">
        <section>
          <div className="flex items-baseline justify-between mb-2">
            <h2 className="font-display text-sm font-semibold text-muted uppercase tracking-wide">
              Pouls d'intégrité — 48 derniers événements
            </h2>
          </div>
          <div className="border border-line rounded-lg bg-surface p-4">
            <PulseStrip alerts={alerts} />
          </div>
        </section>

        <section>
          <div className="flex items-center justify-between mb-3">
            <h2 className="font-display text-sm font-semibold text-muted uppercase tracking-wide">
              Alertes
            </h2>
            <label className="flex items-center gap-2 text-xs text-muted cursor-pointer">
              <input
                type="checkbox"
                checked={onlyUnack}
                onChange={(e) => setOnlyUnack(e.target.checked)}
                className="accent-safe"
              />
              Non acquittées seulement
            </label>
          </div>
          {status === "error" && (
            <p className="text-critical text-xs mb-3">
              Impossible de contacter le serveur. Nouvelle tentative dans 15s.
            </p>
          )}
          <AlertsFeed alerts={alerts} />
        </section>
      </main>
    </div>
  );
}
