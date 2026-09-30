import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import App from "./App";
import "./styles/global.css";

// WO-U4 defaults (UI-FOUNDATION-DESIGN §6): no refetch-on-focus (the examiner
// shares the screen, not the tab), short stale times, one retry.
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
      staleTime: 10_000,
    },
  },
});

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter basename="/portal/app">
        <App />
      </BrowserRouter>
    </QueryClientProvider>
  </React.StrictMode>
);
