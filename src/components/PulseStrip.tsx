import type { Alert } from "../lib/types";

const severityColor: Record<string, string> = {
  info: "bg-line",
  warning: "bg-signal",
  critical: "bg-critical",
};

/**
 * Représente les 40 derniers événements comme un tracé de sismographe :
 * chaque tick est un événement, sa hauteur/couleur encode la sévérité.
 * Fait écho au rôle du produit : un pouls continu de l'intégrité du parc.
 */
export default function PulseStrip({ alerts }: { alerts: Alert[] }) {
  const ticks = [...alerts].reverse().slice(-48);
  const filled = [...Array(48 - ticks.length).fill(null), ...ticks];

  return (
    <div className="flex items-end gap-[3px] h-16 px-1">
      {filled.map((a, i) =>
        a ? (
          <div
            key={a.id}
            title={`${a.title} — ${a.severity}`}
            className={`w-1.5 rounded-sm ${severityColor[a.severity]} ${
              a.severity === "critical" ? "h-full" : a.severity === "warning" ? "h-2/3" : "h-1/3"
            }`}
          />
        ) : (
          <div key={`empty-${i}`} className="w-1.5 h-[3px] rounded-sm bg-line/40 self-center" />
        )
      )}
    </div>
  );
}
