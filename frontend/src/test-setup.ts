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

// jsdom exposes scroll offsets but not Element.scrollTo. Model its coordinate
// effect and scroll event: a no-op would hide broken chat autoscrolling. There
// is no layout/animation clock here; the component test checks the final offset.
if (typeof Element.prototype.scrollTo !== "function") {
  Element.prototype.scrollTo = function (options?: ScrollToOptions | number, y?: number): void {
    const previousTop = this.scrollTop;
    const previousLeft = this.scrollLeft;
    if (typeof options === "number") {
      this.scrollLeft = options;
      if (y !== undefined) this.scrollTop = y;
    } else if (options) {
      if (options.left !== undefined) this.scrollLeft = options.left;
      if (options.top !== undefined) this.scrollTop = options.top;
    }
    if (this.scrollTop !== previousTop || this.scrollLeft !== previousLeft) {
      this.dispatchEvent(new Event("scroll"));
    }
  };
}
