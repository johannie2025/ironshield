import { useState } from "react";
import { storeToken } from "../lib/api";

export default function TokenGate({ onReady }: { onReady: () => void }) {
  const [value, setValue] = useState("");
  const [error, setError] = useState<string | null>(null);

  function submit(e: React.FormEvent) {
    e.preventDefault();
    const trimmed = value.trim();
    if (!/^[a-f0-9]{64}$/i.test(trimmed)) {
      setError("Le jeton doit être une chaîne hexadécimale de 64 caractères.");
      return;
    }
    storeToken(trimmed);
    onReady();
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-base px-6">
      <form
        onSubmit={submit}
        className="w-full max-w-md bg-surface border border-line rounded-lg p-8"
      >
        <div className="flex items-center gap-2 mb-1">
          <span className="w-2 h-2 rounded-full bg-safe" />
          <h1 className="font-display text-lg font-semibold tracking-tight">
            IronShield FIM
          </h1>
        </div>
        <p className="text-muted text-sm mb-6">
          Connectez ce poste au serveur de collecte avec le jeton d'activation
          de la machine.
        </p>

        <label className="block text-xs uppercase tracking-wide text-muted mb-2">
          Jeton d'activation
        </label>
        <input
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder="a1b2c3d4..."
          className="w-full bg-surface2 border border-line rounded px-3 py-2 font-mono text-sm text-text placeholder:text-muted/50 focus:border-safe transition-colors"
          autoFocus
        />
        {error && <p className="text-critical text-xs mt-2">{error}</p>}

        <button
          type="submit"
          className="mt-6 w-full bg-safe text-base font-semibold text-sm rounded py-2.5 hover:brightness-110 transition-all"
        >
          Connecter
        </button>
      </form>
    </div>
  );
}
