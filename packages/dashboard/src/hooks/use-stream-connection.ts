"use client";

import { useCallback, useEffect, useRef, useState } from "react";

export interface FrameMessage {
  type: "frame";
  data: string;
  metadata: {
    offsetTop: number;
    pageScaleFactor: number;
    deviceWidth: number;
    deviceHeight: number;
    scrollOffsetX: number;
    scrollOffsetY: number;
    timestamp: number;
  };
}

export interface StatusMessage {
  type: "status";
  connected: boolean;
  screencasting: boolean;
  viewportWidth: number;
  viewportHeight: number;
  engine?: string;
  recording?: boolean;
}

export interface CommandMessage {
  type: "command";
  action: string;
  id: string;
  params: Record<string, unknown>;
  timestamp: number;
}

export interface ResultMessage {
  type: "result";
  id: string;
  action: string;
  success: boolean;
  data: unknown;
  duration_ms: number;
  timestamp: number;
}

export interface ConsoleMessage {
  type: "console";
  level: string;
  text: string;
  timestamp: number;
}

export interface UrlMessage {
  type: "url";
  url: string;
  timestamp: number;
}

export interface PageErrorMessage {
  type: "page_error";
  text: string;
  line: number | null;
  column: number | null;
  timestamp: number;
}

export interface ErrorMessage {
  type: "error";
  message: string;
}

export interface TabInfo {
  index: number;
  title: string;
  url: string;
  type: string;
  active: boolean;
}

export interface TabsMessage {
  type: "tabs";
  tabs: TabInfo[];
  timestamp: number;
}

export type StreamMessage =
  | FrameMessage
  | StatusMessage
  | CommandMessage
  | ResultMessage
  | ConsoleMessage
  | PageErrorMessage
  | ErrorMessage
  | UrlMessage
  | TabsMessage;

export type ActivityEvent = CommandMessage | ResultMessage | ConsoleMessage;
export type ConsoleEntry = ConsoleMessage | PageErrorMessage;

export interface StreamState {
  connected: boolean;
  browserConnected: boolean;
  screencasting: boolean;
  recording: boolean;
  viewportWidth: number;
  viewportHeight: number;
  currentFrame: string | null;
  events: ActivityEvent[];
  consoleLogs: ConsoleEntry[];
  tabs: TabInfo[];
  engine: string;
}

const MAX_EVENTS = 500;

export function useStreamConnection(port: number = 9223) {
  const [state, setState] = useState<StreamState>({
    connected: false,
    browserConnected: false,
    screencasting: false,
    recording: false,
    viewportWidth: 1280,
    viewportHeight: 720,
    currentFrame: null,
    events: [],
    consoleLogs: [],
    tabs: [],
    engine: "",
  });

  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const eventsRef = useRef<ActivityEvent[]>([]);
  const consoleRef = useRef<ConsoleEntry[]>([]);

  const portRef = useRef(port);

  useEffect(() => {
    if (portRef.current !== port) {
      portRef.current = port;
      eventsRef.current = [];
      consoleRef.current = [];
      setState({
        connected: false,
        browserConnected: false,
        screencasting: false,
        recording: false,
        viewportWidth: 1280,
        viewportHeight: 720,
        currentFrame: null,
        events: [],
        consoleLogs: [],
        tabs: [],
        engine: "",
      });
    }
  }, [port]);

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;

    const ws = new WebSocket(`ws://localhost:${port}`);
    wsRef.current = ws;

    ws.onopen = () => {
      setState((prev) => ({ ...prev, connected: true }));
    };

    ws.onclose = () => {
      setState((prev) => ({ ...prev, connected: false }));
      reconnectTimerRef.current = setTimeout(connect, 2000);
    };

    ws.onerror = () => {
      ws.close();
    };

    ws.onmessage = (event) => {
      let msg: StreamMessage;
      try {
        msg = JSON.parse(event.data);
      } catch {
        return;
      }

      switch (msg.type) {
        case "frame":
          setState((prev) => ({
            ...prev,
            currentFrame: msg.data,
          }));
          break;

        case "status":
          setState((prev) => ({
            ...prev,
            browserConnected: msg.connected,
            screencasting: msg.screencasting,
            recording: msg.recording ?? prev.recording,
            viewportWidth: msg.viewportWidth,
            viewportHeight: msg.viewportHeight,
            engine: msg.engine ?? prev.engine,
          }));
          break;

        case "command": {
          const updated = [...eventsRef.current, msg].slice(-MAX_EVENTS);
          eventsRef.current = updated;
          setState((prev) => ({ ...prev, events: updated }));
          break;
        }

        case "console": {
          const conUpdated = [...consoleRef.current, msg].slice(-MAX_EVENTS);
          consoleRef.current = conUpdated;
          setState((prev) => ({ ...prev, consoleLogs: conUpdated }));
          break;
        }

        case "page_error": {
          const conUpdated = [...consoleRef.current, msg].slice(-MAX_EVENTS);
          consoleRef.current = conUpdated;
          setState((prev) => ({ ...prev, consoleLogs: conUpdated }));
          break;
        }

        case "result": {
          const cmdIdx = eventsRef.current.findIndex(
            (e) => e.type === "command" && e.id === msg.id,
          );
          const base =
            cmdIdx >= 0
              ? [
                  ...eventsRef.current.slice(0, cmdIdx),
                  ...eventsRef.current.slice(cmdIdx + 1),
                ]
              : eventsRef.current;
          const updated = [...base, msg].slice(-MAX_EVENTS);
          eventsRef.current = updated;
          setState((prev) => ({ ...prev, events: updated }));
          break;
        }

        case "tabs":
          setState((prev) => ({
            ...prev,
            tabs: msg.tabs,
          }));
          break;

        case "url":
          setState((prev) => ({
            ...prev,
            tabs: prev.tabs.map((t) =>
              t.active ? { ...t, url: msg.url } : t,
            ),
          }));
          break;

        case "error":
          break;
      }
    };
  }, [port]);

  useEffect(() => {
    connect();
    return () => {
      if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
      wsRef.current?.close();
    };
  }, [connect]);

  const clearEvents = useCallback(() => {
    eventsRef.current = [];
    setState((prev) => ({ ...prev, events: [] }));
  }, []);

  const clearConsoleLogs = useCallback(() => {
    consoleRef.current = [];
    setState((prev) => ({ ...prev, consoleLogs: [] }));
  }, []);

  const sendInput = useCallback((msg: Record<string, unknown>) => {
    const ws = wsRef.current;
    if (ws?.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify(msg));
    }
  }, []);

  return { ...state, clearEvents, clearConsoleLogs, sendInput };
}
