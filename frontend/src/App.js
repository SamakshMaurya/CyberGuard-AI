import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Layout from './components/Layout/Layout';
import Dashboard from './components/Dashboard/Dashboard';
import ChatContainer from './components/Chat/ChatContainer';
import ReportView from './components/Reports/ReportView';

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index element={<Dashboard />} />
          <Route path="assessment/:id" element={<ChatContainer />} />
          <Route path="assessment/:id/report" element={<ReportView />} />
        </Route>
      </Routes>
    </Router>
  );
}

export default App;
