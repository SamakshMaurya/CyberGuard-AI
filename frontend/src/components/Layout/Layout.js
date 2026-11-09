import React, { useState } from 'react';
import { Outlet } from 'react-router-dom';
import Navbar from './Navbar';
import Sidebar from './Sidebar';

function Layout() {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [isConnected, setIsConnected] = useState(false);

  const handleToggleSidebar = () => {
    setSidebarOpen((prev) => !prev);
  };

  const handleCloseSidebar = () => {
    setSidebarOpen(false);
  };

  return (
    <div className="app-container">
      <Navbar isConnected={isConnected} onToggleSidebar={handleToggleSidebar} />
      <div className="app-body">
        <Sidebar isOpen={sidebarOpen} onClose={handleCloseSidebar} />
        <main className="main-content">
          <Outlet context={{ setIsConnected }} />
        </main>
      </div>
      {sidebarOpen && (
        <div
          onClick={handleCloseSidebar}
          style={{
            position: 'fixed',
            inset: 0,
            zIndex: 1015,
            background: 'rgba(0,0,0,0.5)',
            display: 'none',
          }}
          className="sidebar-overlay"
        />
      )}
    </div>
  );
}

export default Layout;
