"use client";

import { useCallback, useEffect, useRef, useState } from "react";

export interface ExtensionInfo {
  name: string;
  version: string;
  description?: string;
  path: string;
}

export interface SessionInfo {
  session: string;
  port: number;
  engine?: string;
  extensions?: ExtensionInfo[];
  pending?: boolean;
  closing?: boolean;
}

const DASHBOARD_PORT = 4848;

function getSessionsUrl(): string {
  if (typeof window !== "undefined") {
    const origin = window.location.origin;
    // When served by the Rust server, same-origin works
    if (origin.includes(`:${DASHBOARD_PORT}`)) {
      return "/api/sessions";
    }
  }
  // Otherwise hit the dashboard server directly
  return `http://localhost:${DASHBOARD_PORT}/api/sessions`;
}

export function useSessions(pollInterval = 5000): SessionInfo[] {
  const [sessions, setSessions] = useState<SessionInfo[]>([]);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const failCountRef = useRef(0);

  const fetchSessions = useCallback(async () => {
    try {
      const resp = await fetch(getSessionsUrl());
      if (resp.ok) {
        failCountRef.current = 0;
        const data: SessionInfo[] = await resp.json();
        data.sort((a, b) => a.session.localeCompare(b.session));
        setSessions(data);
        return;
      }
    } catch {
      // Server unreachable
    }
    failCountRef.current++;
    if (failCountRef.current >= 2) setSessions([]);
  }, []);

  useEffect(() => {
    fetchSessions();
    timerRef.current = setInterval(fetchSessions, pollInterval);
    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [fetchSessions, pollInterval]);

  return sessions;
}
