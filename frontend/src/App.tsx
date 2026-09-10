import { Routes, Route, Navigate } from "react-router-dom";
import { CaseProvider } from "./context/CaseContext";
import Layout from "./components/Layout";
import RequireCase from "./components/RequireCase";
import Overview from "./pages/Overview";
import Explore from "./pages/Explore";
import Timeline from "./pages/Timeline";
import SteerChat from "./pages/SteerChat";
import Workbench from "./pages/Workbench";
import Findings from "./pages/Findings";
import Approve from "./pages/Approve";
import Report from "./pages/Report";
import Evidence from "./pages/Evidence";
import Entities from "./pages/Entities";
import Transparency from "./pages/Transparency";
import CaseSetup from "./pages/CaseSetup";
import Iocs from "./pages/Iocs";
import Todos from "./pages/Todos";

export default function App() {
  return (
    <CaseProvider>
      <Layout>
        <Routes>
          {/* Dashboard — case management, no active case required */}
          <Route path="/" element={<Overview />} />
          <Route path="/case-setup" element={<CaseSetup />} />

          {/* Cockpit — requires a server-confirmed active case */}
          <Route path="/explore" element={<RequireCase><Explore /></RequireCase>} />
          <Route path="/timeline" element={<RequireCase><Timeline /></RequireCase>} />
          <Route path="/steer" element={<RequireCase><SteerChat /></RequireCase>} />
          <Route path="/workbench" element={<RequireCase><Workbench /></RequireCase>} />
          <Route path="/findings" element={<RequireCase><Findings /></RequireCase>} />
          <Route path="/approve" element={<RequireCase><Approve /></RequireCase>} />
          <Route path="/report" element={<RequireCase><Report /></RequireCase>} />
          <Route path="/evidence" element={<RequireCase><Evidence /></RequireCase>} />
          <Route path="/entities" element={<RequireCase><Entities /></RequireCase>} />
          <Route path="/transparency" element={<RequireCase><Transparency /></RequireCase>} />
          <Route path="/iocs" element={<RequireCase><Iocs /></RequireCase>} />
          <Route path="/todos" element={<RequireCase><Todos /></RequireCase>} />

          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Layout>
    </CaseProvider>
  );
}
