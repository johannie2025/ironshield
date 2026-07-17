import type { Alert } from "../lib/types";

const severityStyles: Record<string, string> = {
  info: "text-muted border-line",
  warning: "text-signal border-signal/40",
  critical: "text-critical border-critical/40",
};

const severityLabel: Record<string, string> = {
  info: "Info",
  warning: "Attention",
  critical: "Critique",
};

export default function AlertsFeed({ alerts }: { alerts: Alert[] }) {
  if (alerts.length === 0) {
    return (
      <div className="border border-line rounded-lg p-8 text-center bg-surface">
        <p className="text-muted text-sm">
          Aucune alerte. Le parc surveillé est conforme.
        </p>
      </div>
    );
  }

  return (
    <div className="border border-line rounded-lg bg-surface divide-y divide-line overflow-hidden">
      {alerts.map((a) => (
        <div key={a.id} className="flex items-start gap-3 px-4 py-3">
          <span
            className={`shrink-0 mt-0.5 text-[10px] font-mono uppercase tracking-wide border rounded px-1.5 py-0.5 ${severityStyles[a.severity]}`}
          >
            {severityLabel[a.severity]}
          </span>
          <div className="min-w-0 flex-1">
            <p className="text-sm text-text truncate">{a.title}</p>
            <p className="text-xs text-muted font-mono truncate">{a.description}</p>
          </div>
          <time className="shrink-0 text-xs text-muted font-mono">
            {new Date(a.created_at).toLocaleTimeString("fr-FR", {
              hour: "2-digit",
              minute: "2-digit",
            })}
          </time>
        </div>
      ))}
    </div>
  );
}
