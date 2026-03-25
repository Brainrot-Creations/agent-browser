"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useStreamConnection } from "@/hooks/use-stream-connection";
import type { ActivityEvent, TabInfo } from "@/hooks/use-stream-connection";
import { useSessions } from "@/hooks/use-sessions";
import { useMediaQuery } from "@/hooks/use-media-query";
import { execCommand, killSession, sessionArgs } from "@/lib/exec";
import { Viewport } from "@/components/viewport";
import { ActivityFeed } from "@/components/activity-feed";
import { ConsolePanel } from "@/components/console-panel";
import { StoragePanel } from "@/components/storage-panel";
import { ExtensionsPanel } from "@/components/extensions-panel";
import { NetworkPanel } from "@/components/network-panel";
import { SessionTree } from "@/components/session-tree";
import {
  ResizablePanelGroup,
  ResizablePanel,
  ResizableHandle,
} from "@/components/ui/resizable";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";

const PERSIST_KEY = "ab-persist-activity";
const MAX_PERSISTED = 500;

function activityStorageKey(session: string) {
  return `ab-activity-${session}`;
}

function loadPersistedEvents(session: string): ActivityEvent[] {
  try {
    const raw = localStorage.getItem(activityStorageKey(session));
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function savePersistedEvents(session: string, events: ActivityEvent[]) {
  try {
    const capped = events.slice(-MAX_PERSISTED);
    localStorage.setItem(activityStorageKey(session), JSON.stringify(capped));
  } catch {
    // Storage full or unavailable
  }
}

function clearPersistedEvents(session: string) {
  try {
    localStorage.removeItem(activityStorageKey(session));
  } catch {
    // Ignore
  }
}

function getPort(): number {
  if (typeof window === "undefined") return 9223;
  const params = new URLSearchParams(window.location.search);
  const p = params.get("port");
  return p ? parseInt(p, 10) || 9223 : 9223;
}

export default function DashboardPage() {
  const [activePort, setActivePort] = useState(getPort);
  const stream = useStreamConnection(activePort);
  const polledSessions = useSessions();
  const isDesktop = useMediaQuery("(min-width: 768px)");
  const [pendingSessions, setPendingSessions] = useState<
    { session: string; engine: string }[]
  >([]);
  const [closingSessions, setClosingSessions] = useState<Set<string>>(
    new Set(),
  );

  const [tabCache, setTabCache] = useState<Record<number, TabInfo[]>>({});
  const [engineCache, setEngineCache] = useState<Record<number, string>>({});

  // Remove pending sessions once they appear in the polled list,
  // and remove closing sessions once they disappear
  useEffect(() => {
    const polledNames = new Set(polledSessions.map((s) => s.session));
    if (pendingSessions.length > 0) {
      setPendingSessions((prev) => prev.filter((p) => !polledNames.has(p.session)));
    }
    if (closingSessions.size > 0) {
      setClosingSessions((prev) => {
        const next = new Set(prev);
        for (const name of prev) {
          if (!polledNames.has(name)) next.delete(name);
        }
        return next.size === prev.size ? prev : next;
      });
    }
  }, [polledSessions, pendingSessions.length, closingSessions.size]);

  const sessions = useMemo(() => {
    const polledNames = new Set(polledSessions.map((s) => s.session));
    const pending = pendingSessions
      .filter((p) => !polledNames.has(p.session))
      .map((p) => ({
        session: p.session,
        port: 0,
        engine: p.engine,
        pending: true as const,
      }));
    const merged = polledSessions.map((s) =>
      closingSessions.has(s.session) ? { ...s, closing: true as const } : s,
    );
    return [...merged, ...pending];
  }, [polledSessions, pendingSessions, closingSessions]);

  const [persistActivity, setPersistActivity] = useState(() => {
    if (typeof window === "undefined") return false;
    return localStorage.getItem(PERSIST_KEY) === "true";
  });

  const activeSessionInfo = sessions.find((s) => s.port === activePort);
  const activeSession = activeSessionInfo?.session ?? "";
  const activeExtensions = (activeSessionInfo && "extensions" in activeSessionInfo ? activeSessionInfo.extensions : undefined) ?? [];

  const [restoredEvents, setRestoredEvents] = useState<ActivityEvent[]>([]);
  const prevSessionRef = useRef(activeSession);

  // Load persisted events when session changes (or on mount)
  useEffect(() => {
    if (prevSessionRef.current !== activeSession) {
      prevSessionRef.current = activeSession;
    }
    if (persistActivity && activeSession) {
      setRestoredEvents(loadPersistedEvents(activeSession));
    } else {
      setRestoredEvents([]);
    }
  }, [persistActivity, activeSession]);

  const combinedEvents = useMemo(
    () =>
      persistActivity && restoredEvents.length > 0
        ? [...restoredEvents, ...stream.events].slice(-MAX_PERSISTED)
        : stream.events,
    [persistActivity, restoredEvents, stream.events],
  );

  // Save combined events to localStorage when persist is on
  useEffect(() => {
    if (persistActivity && activeSession && combinedEvents.length > 0) {
      savePersistedEvents(activeSession, combinedEvents);
    }
  }, [persistActivity, activeSession, combinedEvents]);

  const handleTogglePersist = useCallback(() => {
    setPersistActivity((prev) => {
      const next = !prev;
      localStorage.setItem(PERSIST_KEY, String(next));
      if (!next && activeSession) {
        clearPersistedEvents(activeSession);
        setRestoredEvents([]);
      }
      return next;
    });
  }, [activeSession]);

  const handleClearActivity = useCallback(() => {
    stream.clearEvents();
    setRestoredEvents([]);
    if (activeSession) clearPersistedEvents(activeSession);
  }, [stream.clearEvents, activeSession]);

  // Auto-select the first available session when no matching session is active
  useEffect(() => {
    if (sessions.length > 0 && !sessions.some((s) => s.port === activePort)) {
      setActivePort(sessions[0].port);
    }
  }, [sessions, activePort]);

  // Seed engine cache from session list (engine is returned by /api/sessions)
  useEffect(() => {
    setEngineCache((prev) => {
      const next = { ...prev };
      for (const s of sessions) {
        if (s.engine && !next[s.port]) {
          next[s.port] = s.engine;
        }
      }
      return next;
    });
  }, [sessions]);

  useEffect(() => {
    if (stream.tabs.length > 0) {
      setTabCache((prev) => ({ ...prev, [activePort]: stream.tabs }));
    }
  }, [activePort, stream.tabs]);

  useEffect(() => {
    if (stream.engine) {
      setEngineCache((prev) => ({ ...prev, [activePort]: stream.engine }));
    }
  }, [activePort, stream.engine]);

  useEffect(() => {
    if (sessions.length === 0) return;

    const fetchSessionData = async () => {
      for (const s of sessions) {
        try {
          const tabsResp = await fetch(
            `http://localhost:${s.port}/api/tabs`,
          ).catch(() => null);
          if (tabsResp?.ok) {
            const tabs: TabInfo[] = await tabsResp.json();
            if (tabs.length > 0) {
              setTabCache((prev) => ({ ...prev, [s.port]: tabs }));
            }
          }
        } catch {
          // Session unreachable
        }
      }
    };

    fetchSessionData();
    const interval = setInterval(fetchSessionData, 10000);
    return () => clearInterval(interval);
  }, [sessions]);

  const getTabsForSession = useCallback(
    (port: number): TabInfo[] => {
      if (port === activePort && stream.tabs.length > 0) return stream.tabs;
      return tabCache[port] ?? [];
    },
    [activePort, stream.tabs, tabCache],
  );

  const getEngineForSession = useCallback(
    (port: number): string => {
      if (engineCache[port]) return engineCache[port];
      if (port === activePort && stream.engine) return stream.engine;
      return "";
    },
    [activePort, stream.engine, engineCache],
  );

  const sessionForPort = useCallback(
    (port: number): string =>
      sessions.find((s) => s.port === port)?.session ?? "",
    [sessions],
  );

  const handleCloseTab = useCallback(
    (port: number, tabIndex: number) => {
      const s = sessionForPort(port);
      if (s) execCommand(sessionArgs(s, "tab", "close", String(tabIndex)));
    },
    [sessionForPort],
  );

  const handleAddTab = useCallback(
    (port: number) => {
      const s = sessionForPort(port);
      if (s) execCommand(sessionArgs(s, "tab", "new"));
    },
    [sessionForPort],
  );

  const handleSwitchTab = useCallback(
    (port: number, tabIndex: number) => {
      const s = sessionForPort(port);
      if (s) execCommand(sessionArgs(s, "tab", String(tabIndex)));
    },
    [sessionForPort],
  );

  const markClosing = useCallback((name: string) => {
    setClosingSessions((prev) => new Set(prev).add(name));
  }, []);

  const handleCloseSession = useCallback(
    (port: number) => {
      const s = sessionForPort(port);
      if (s) {
        markClosing(s);
        execCommand(sessionArgs(s, "close"));
      }
    },
    [sessionForPort, markClosing],
  );

  const handleKillSession = useCallback(
    (port: number) => {
      const s = sessionForPort(port);
      if (s) {
        markClosing(s);
        killSession(s);
      }
    },
    [sessionForPort, markClosing],
  );

  const handleCloseAllSessions = useCallback(() => {
    for (const s of sessions) {
      if (!s.pending && !s.closing) {
        markClosing(s.session);
        execCommand(sessionArgs(s.session, "close"));
      }
    }
  }, [sessions, markClosing]);

  const handleCreateSession = useCallback((name: string, engine: string) => {
    setPendingSessions((prev) => [...prev, { session: name, engine }]);
    execCommand(["--session", name, "--engine", engine, "open", "about:blank"]);
  }, []);

  const activeUrl = stream.tabs.find((t) => t.active)?.url ?? "";

  const sessionTreeEl = (
    <SessionTree
      sessions={sessions}
      activePort={activePort}
      getTabsForSession={getTabsForSession}
      getEngineForSession={getEngineForSession}
      onSelectSession={setActivePort}
      onCloseTab={handleCloseTab}
      onAddTab={handleAddTab}
      onSwitchTab={handleSwitchTab}
      onCreateSession={handleCreateSession}
      onCloseSession={handleCloseSession}
      onKillSession={handleKillSession}
      onCloseAllSessions={handleCloseAllSessions}
    />
  );

  const viewportEl = (
    <Viewport
      frame={stream.currentFrame}
      viewportWidth={stream.viewportWidth}
      viewportHeight={stream.viewportHeight}
      browserConnected={stream.browserConnected}
      screencasting={stream.screencasting}
      recording={stream.recording}
      engine={stream.engine}
      url={activeUrl}
      sessionName={activeSession}
      streamPort={activePort}
      sendInput={stream.sendInput}
    />
  );

  const sidePanel = (
    <Tabs defaultValue="activity" className="flex h-full flex-col">
      <div className="shrink-0 px-2 pt-1">
        <TabsList variant="line" className="h-7 w-full">
          <TabsTrigger value="activity" className="text-[11px]">Activity</TabsTrigger>
          <TabsTrigger value="console" className="text-[11px]">
            Console
            {stream.consoleLogs.filter((e) => e.type === "page_error" || (e.type === "console" && e.level === "error")).length > 0 && (
              <span className="ml-1 inline-flex size-1.5 rounded-full bg-destructive" />
            )}
          </TabsTrigger>
          <TabsTrigger value="network" className="text-[11px]">Network</TabsTrigger>
          <TabsTrigger value="storage" className="text-[11px]">Storage</TabsTrigger>
          <TabsTrigger value="extensions" className="text-[11px]">
            Extensions
            {activeExtensions.length > 0 && (
              <span className="ml-1 text-[9px] tabular-nums text-muted-foreground">{activeExtensions.length}</span>
            )}
          </TabsTrigger>
        </TabsList>
      </div>
      <TabsContent value="activity" className="min-h-0 flex-1 overflow-hidden">
        <ActivityFeed
          events={combinedEvents}
          persist={persistActivity}
          onTogglePersist={handleTogglePersist}
          onClear={handleClearActivity}
        />
      </TabsContent>
      <TabsContent value="console" className="min-h-0 flex-1 overflow-hidden">
        <ConsolePanel
          entries={stream.consoleLogs}
          onClear={stream.clearConsoleLogs}
          sessionName={activeSession}
        />
      </TabsContent>
      <TabsContent value="network" className="min-h-0 flex-1 overflow-hidden">
        <NetworkPanel sessionName={activeSession} />
      </TabsContent>
      <TabsContent value="storage" className="min-h-0 flex-1 overflow-hidden">
        <StoragePanel sessionName={activeSession} />
      </TabsContent>
      <TabsContent value="extensions" className="min-h-0 flex-1 overflow-hidden">
        <ExtensionsPanel extensions={activeExtensions} sessionName={activeSession} />
      </TabsContent>
    </Tabs>
  );

  if (isDesktop) {
    return (
      <div className="flex h-screen flex-col bg-background">
        <ResizablePanelGroup
          orientation="horizontal"
          className="min-h-0 flex-1"
        >
          <ResizablePanel id="sessions" defaultSize="15%" minSize="10%" maxSize="30%">
            {sessionTreeEl}
          </ResizablePanel>
          <ResizableHandle />
          <ResizablePanel id="viewport" defaultSize="55%" minSize="30%">
            {viewportEl}
          </ResizablePanel>
          <ResizableHandle />
          <ResizablePanel id="activity" defaultSize="30%" minSize="15%" maxSize="50%">
            {sidePanel}
          </ResizablePanel>
        </ResizablePanelGroup>
      </div>
    );
  }

  return (
    <div className="flex h-screen flex-col bg-background">
      <Tabs defaultValue="viewport" className="min-h-0 flex-1">
        <div className="shrink-0 px-2 pt-2">
          <TabsList className="w-full">
            <TabsTrigger value="sessions">Sessions</TabsTrigger>
            <TabsTrigger value="viewport">Viewport</TabsTrigger>
            <TabsTrigger value="activity">Activity</TabsTrigger>
          </TabsList>
        </div>
        <TabsContent value="sessions" className="min-h-0 overflow-hidden">
          {sessionTreeEl}
        </TabsContent>
        <TabsContent value="viewport" className="min-h-0 overflow-hidden">
          {viewportEl}
        </TabsContent>
        <TabsContent value="activity" className="min-h-0 overflow-hidden">
          {sidePanel}
        </TabsContent>
      </Tabs>
    </div>
  );
}
