"use client";

import type { SessionInfo } from "@/hooks/use-sessions";

interface SessionPickerProps {
  sessions: SessionInfo[];
  activePort: number;
  onSelect: (port: number) => void;
}

export function SessionPicker({
  sessions,
  activePort,
  onSelect,
}: SessionPickerProps) {
  if (sessions.length <= 1) return null;

  return (
    <div className="flex items-center gap-1">
      <span className="text-[var(--text-muted)] mr-1">Sessions:</span>
      {sessions.map((s) => (
        <button
          key={s.port}
          onClick={() => onSelect(s.port)}
          className={`px-2 py-0.5 rounded text-xs font-mono transition-colors ${
            s.port === activePort
              ? "bg-[var(--accent)] text-white"
              : "bg-[var(--bg-tertiary)] text-[var(--text-muted)] hover:text-[var(--text)]"
          }`}
        >
          {s.session}
        </button>
      ))}
    </div>
  );
}
