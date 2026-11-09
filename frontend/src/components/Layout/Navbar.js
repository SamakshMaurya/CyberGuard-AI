import React from 'react';
import { useNavigate } from 'react-router-dom';
import { FiShield, FiWifi, FiWifiOff } from 'react-icons/fi';

function Navbar({ isConnected, onToggleSidebar }) {
  const navigate = useNavigate();

  return (
    <nav className="navbar-cyber">
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
        <button className="sidebar-toggle" onClick={onToggleSidebar}>
          ☰
        </button>
        <div
          className="navbar-brand-cyber"
          onClick={() => navigate('/')}
          role="button"
          tabIndex={0}
          onKeyDown={(e) => e.key === 'Enter' && navigate('/')}
        >
          <span className="brand-icon">
            <FiShield />
          </span>
          <div>
            <div>CyberGuard AI</div>
            <div className="brand-subtitle">VAPT Assessment Platform</div>
          </div>
        </div>
      </div>
      <div className="navbar-right">
        <div className="connection-status">
          <span className={`connection-dot ${isConnected ? 'connected' : ''}`}></span>
          <span>
            {isConnected ? (
              <>
                <FiWifi style={{ marginRight: 4, fontSize: '0.85rem' }} /> Connected
              </>
            ) : (
              <>
                <FiWifiOff style={{ marginRight: 4, fontSize: '0.85rem' }} /> Disconnected
              </>
            )}
          </span>
        </div>
      </div>
    </nav>
  );
}

export default Navbar;
