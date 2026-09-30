/** WO-U4 tests: the query layer — polling, shared cache, invalidation. */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useSystemHealth } from "./system";
import { caseKey, invalidateKeys, systemKey } from "./keys";

const fetchMock = vi.fn<(input: string) => Promise<Response>>();

beforeEach(() => {
  fetchMock.mockClear();
  vi.stubGlobal("fetch", fetchMock as unknown as typeof fetch);
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

function makeClient() {
  return new QueryClient({
    defaultOptions: { queries: { retry: false, refetchOnWindowFocus: false } },
  });
}

function payload(backend: string, esReachable: boolean): Response {
  return {
    ok: true,
    json: async () =>
      ({
        backend,
        es: { configured: true, reachable: esReachable },
        sift: { selected: false, reachable: true },
      }) as unknown as Response,
  } as Response;
}

function HealthReader({ intervalMs = 30_000 }: { intervalMs?: number }) {
  const { data } = useSystemHealth(intervalMs);
  return (
    <div>
      <span data-testid="backend">{data?.backend ?? "?"}</span>
      <span data-testid="es">{String(data?.es.reachable)}</span>
    </div>
  );
}

describe("useSystemHealth", () => {
  it("reports backend and ES as separate signals", async () => {
    fetchMock.mockResolvedValue(payload("ok", false));
    render(
      <QueryClientProvider client={makeClient()}>
        <HealthReader />
      </QueryClientProvider>,
    );
    await waitFor(() => expect(screen.getByTestId("backend").textContent).toBe("ok"));
    expect(screen.getByTestId("es").textContent).toBe("false");
  });

  it("a later poll flips the badge — the service came up after mount", async () => {
    // short interval + real timers: the second poll answers "ok"
    fetchMock.mockResolvedValueOnce(payload("down", false));
    render(
      <QueryClientProvider client={makeClient()}>
        <HealthReader intervalMs={20} />
      </QueryClientProvider>,
    );
    await waitFor(() => expect(screen.getByTestId("backend").textContent).toBe("down"));

    fetchMock.mockResolvedValue(payload("ok", true));
    await waitFor(
      () => expect(screen.getByTestId("backend").textContent).toBe("ok"),
      { timeout: 3_000, interval: 20 },
    );
    await waitFor(() => expect(screen.getByTestId("es").textContent).toBe("true"));
  });

  it("the cache is shared — two readers under one client fetch once", async () => {
    fetchMock.mockResolvedValue(payload("ok", true));
    render(
      <QueryClientProvider client={makeClient()}>
        <HealthReader />
        <HealthReader />
      </QueryClientProvider>,
    );
    await waitFor(() => {
      const backends = screen.getAllByTestId("backend");
      expect(backends.length).toBe(2);
      expect(backends[0].textContent).toBe("ok");
    });
    const calls = fetchMock.mock.calls.filter((c) => String(c[0]).includes("/system/health"));
    expect(calls.length).toBe(1);
  });
});

describe("query keys", () => {
  it("are case-scoped by construction", () => {
    expect(caseKey("CASE-A", "findings")).toEqual(["case", "CASE-A", "findings"]);
    expect(caseKey("CASE-A", "findings")).not.toEqual(caseKey("CASE-B", "findings"));
  });

  it("invalidateKeys.case invalidates only that case+domain", async () => {
    const client = makeClient();
    const seen: string[] = [];
    const spy = vi
      .spyOn(client, "invalidateQueries")
      .mockImplementation(((opts: { queryKey: readonly unknown[] }) => {
        seen.push(opts.queryKey.join("|"));
        return Promise.resolve({ scopes: [] });
      }) as never);
    await invalidateKeys.case(client, "CASE-A", "findings");
    expect(seen).toEqual(["case|CASE-A|findings"]);
    spy.mockRestore();
  });

  it("system keys never collide with case keys", () => {
    expect(systemKey("health")).toEqual(["system", "health"]);
  });
});
