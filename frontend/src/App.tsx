import { Routes, Route, Navigate } from "react-router-dom";
import { CaseProvider } from "./context/CaseContext";
import Layout from "./components/Layout";
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
          <Route path="/" element={<Overview />} />
          <Route path="/explore" element={<Explore />} />
          <Route path="/timeline" element={<Timeline />} />
          <Route path="/steer" element={<SteerChat />} />
          <Route path="/workbench" element={<Workbench />} />
          <Route path="/findings" element={<Findings />} />
          <Route path="/approve" element={<Approve />} />
          <Route path="/report" element={<Report />} />
          <Route path="/evidence" element={<Evidence />} />
          <Route path="/entities" element={<Entities />} />
          <Route path="/transparency" element={<Transparency />} />
          <Route path="/case-setup" element={<CaseSetup />} />
          <Route path="/iocs" element={<Iocs />} />
          <Route path="/todos" element={<Todos />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Layout>
    </CaseProvider>
  );
}
