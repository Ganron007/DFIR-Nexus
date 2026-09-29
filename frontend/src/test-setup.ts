// jsdom polyfills for component tests

class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}
if (typeof globalThis.ResizeObserver === "undefined") {
  (globalThis as { ResizeObserver?: unknown }).ResizeObserver = ResizeObserverStub;
}

// jsdom has no EventSource, and both Agent Run views open one as soon as a run
// id is known. Stub it rather than mocking it per test file: a missing global
// browser API is an environment gap, and stubbing it centrally means every
// component that tails an SSE stream is testable without each test repeating it.
if (typeof globalThis.EventSource === "undefined") {
  class EventSourceStub {
    url: string;
    onerror: ((e: unknown) => void) | null = null;
    onmessage: ((e: unknown) => void) | null = null;
    onopen: ((e: unknown) => void) | null = null;
    readyState = 0;
    constructor(url: string) {
      this.url = url;
    }
    addEventListener(): void {}
    removeEventListener(): void {}
    close(): void {
      this.readyState = 2;
    }
    dispatchEvent(): boolean {
      return false;
    }
  }
  (globalThis as { EventSource?: unknown }).EventSource = EventSourceStub;
}
