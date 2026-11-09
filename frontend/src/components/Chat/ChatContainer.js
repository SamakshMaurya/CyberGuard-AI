import React, { useState, useEffect, useRef, useCallback } from 'react';
import { useParams, useOutletContext } from 'react-router-dom';
import { FiSend, FiShield, FiZap, FiFileText, FiSearch } from 'react-icons/fi';
import {
  getAssessment,
  getChatHistory,
  createChatWebSocket,
  getFindings,
  getScans,
} from '../../services/api';
import ChatMessage from './ChatMessage';
import ToolCallCard from './ToolCallCard';
import ApprovalCard from './ApprovalCard';
import QuickInfoPanel from './QuickInfoPanel';
import FindingsPanel from '../ScanResults/FindingsPanel';

function ChatContainer() {
  const { id } = useParams();
  const { setIsConnected } = useOutletContext();

  const [assessment, setAssessment] = useState(null);
  const [messages, setMessages] = useState([]);
  const [inputValue, setInputValue] = useState('');
  const [isWaiting, setIsWaiting] = useState(false);
  const [wsConnected, setWsConnected] = useState(false);
  const [findings, setFindings] = useState([]);
  const [scans, setScans] = useState([]);
  const [currentStreamMessage, setCurrentStreamMessage] = useState('');
  const [activeTab, setActiveTab] = useState('chat');

  const wsRef = useRef(null);
  const messagesEndRef = useRef(null);
  const textareaRef = useRef(null);
  const reconnectTimerRef = useRef(null);

  const scrollToBottom = useCallback(() => {
    requestAnimationFrame(() => {
      messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    });
  }, []);

  // Fetch assessment details
  const fetchAssessment = useCallback(async () => {
    try {
      const data = await getAssessment(id);
      setAssessment(data);
    } catch (err) {
      console.error('Failed to fetch assessment:', err);
    }
  }, [id]);

  // Fetch chat history
  const fetchChatHistory = useCallback(async () => {
    try {
      const data = await getChatHistory(id);
      const history = Array.isArray(data) ? data : data.messages || [];
      setMessages(history);
    } catch (err) {
      console.error('Failed to fetch chat history:', err);
    }
  }, [id]);

  // Fetch findings and scans for sidebar
  const fetchSidebarData = useCallback(async () => {
    try {
      const [findingsData, scansData] = await Promise.allSettled([
        getFindings(id),
        getScans(id),
      ]);
      if (findingsData.status === 'fulfilled') {
        const f = Array.isArray(findingsData.value)
          ? findingsData.value
          : findingsData.value.findings || [];
        setFindings(f);
      }
      if (scansData.status === 'fulfilled') {
        const s = Array.isArray(scansData.value)
          ? scansData.value
          : scansData.value.scans || [];
        setScans(s);
      }
    } catch (err) {
      console.error('Failed to fetch sidebar data:', err);
    }
  }, [id]);

  // WebSocket connection
  const connectWebSocket = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;

    const ws = createChatWebSocket(id);

    ws.onopen = () => {
      setWsConnected(true);
      setIsConnected(true);
      console.log('WebSocket connected');
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        handleWsMessage(data);
      } catch (err) {
        console.error('Failed to parse WS message:', err);
      }
    };

    ws.onerror = (err) => {
      console.error('WebSocket error:', err);
    };

    ws.onclose = () => {
      setWsConnected(false);
      setIsConnected(false);
      console.log('WebSocket disconnected');
      // Attempt reconnect after 3 seconds
      reconnectTimerRef.current = setTimeout(() => {
        connectWebSocket();
      }, 3000);
    };

    wsRef.current = ws;
  }, [id, setIsConnected]);

  const handleWsMessage = (data) => {
    switch (data.type) {
      case 'text':
        setCurrentStreamMessage('');
        setMessages((prev) => [
          ...prev,
          {
            id: Date.now().toString(),
            role: 'assistant',
            type: 'text',
            content: data.content,
            timestamp: new Date().toISOString(),
          },
        ]);
        setIsWaiting(false);
        break;

      case 'text_delta':
        setCurrentStreamMessage((prev) => prev + (data.content || ''));
        break;

      case 'tool_call':
        setMessages((prev) => [
          ...prev,
          {
            id: `tool-${Date.now()}`,
            role: 'system',
            type: 'tool_call',
            content: data.content,
            status: 'running',
            timestamp: new Date().toISOString(),
          },
        ]);
        break;

      case 'tool_result':
        setMessages((prev) => {
          const updated = [...prev];
          const toolIdx = updated.findLastIndex((m) => m.type === 'tool_call' && m.status === 'running');
          if (toolIdx !== -1) {
            updated[toolIdx] = {
              ...updated[toolIdx],
              status: 'completed',
              result: data.content?.result || data.content,
            };
          }
          return updated;
        });
        fetchSidebarData();
        break;

      case 'reasoning':
        setMessages((prev) => [
          ...prev,
          {
            id: `reasoning-${Date.now()}`,
            role: 'system',
            type: 'reasoning',
            content: data.content,
            timestamp: new Date().toISOString(),
          },
        ]);
        break;

      case 'approval_request':
        setMessages((prev) => [
          ...prev,
          {
            id: `approval-${Date.now()}`,
            role: 'system',
            type: 'approval_request',
            content: data.content,
            timestamp: new Date().toISOString(),
          },
        ]);
        setIsWaiting(false);
        break;

      case 'error':
        setMessages((prev) => [
          ...prev,
          {
            id: `error-${Date.now()}`,
            role: 'system',
            type: 'error',
            content: data.content,
            timestamp: new Date().toISOString(),
          },
        ]);
        setIsWaiting(false);
        break;

      case 'complete':
        if (currentStreamMessage) {
          setMessages((prev) => [
            ...prev,
            {
              id: Date.now().toString(),
              role: 'assistant',
              type: 'text',
              content: currentStreamMessage,
              timestamp: new Date().toISOString(),
            },
          ]);
          setCurrentStreamMessage('');
        }
        setIsWaiting(false);
        fetchSidebarData();
        break;

      default:
        console.log('Unknown WS message type:', data.type);
    }
  };

  // Initialize
  useEffect(() => {
    fetchAssessment();
    fetchChatHistory();
    fetchSidebarData();
    connectWebSocket();

    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
      if (reconnectTimerRef.current) {
        clearTimeout(reconnectTimerRef.current);
      }
      setIsConnected(false);
    };
  }, [id, fetchAssessment, fetchChatHistory, fetchSidebarData, connectWebSocket, setIsConnected]);

  // Auto scroll on new messages
  useEffect(() => {
    scrollToBottom();
  }, [messages, currentStreamMessage, isWaiting, scrollToBottom]);

  // Send message
  const handleSend = () => {
    const trimmed = inputValue.trim();
    if (!trimmed || isWaiting) return;

    const userMsg = {
      id: `user-${Date.now()}`,
      role: 'user',
      type: 'text',
      content: trimmed,
      timestamp: new Date().toISOString(),
    };

    setMessages((prev) => [...prev, userMsg]);
    setInputValue('');
    setIsWaiting(true);
    setCurrentStreamMessage('');

    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ type: 'message', content: trimmed }));
    }

    // Reset textarea height
    if (textareaRef.current) {
      textareaRef.current.style.height = '42px';
    }
  };

  const handleApproval = (actionId, approved) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(
        JSON.stringify({ type: 'approval', action_id: actionId, approved })
      );
      setIsWaiting(true);
    }

    // Update the approval message status
    setMessages((prev) =>
      prev.map((m) =>
        m.type === 'approval_request' && m.content?.action_id === actionId
          ? { ...m, responded: true, approvedValue: approved }
          : m
      )
    );
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  const handleInputChange = (e) => {
    setInputValue(e.target.value);
    // Auto-resize textarea
    const textarea = e.target;
    textarea.style.height = '42px';
    textarea.style.height = Math.min(textarea.scrollHeight, 160) + 'px';
  };

  const handleQuickAction = (action) => {
    setInputValue(action);
    textareaRef.current?.focus();
  };

  const quickActions = [
    { label: '🔍 Start Reconnaissance', action: 'Start a reconnaissance scan on the target to identify open ports and services.' },
    { label: '🌐 Run Web Scan', action: 'Run a comprehensive web vulnerability scan on the target application.' },
    { label: '📊 Generate Report', action: 'Generate a detailed VAPT report with all findings and recommendations.' },
    { label: '📋 Show Findings', action: 'Show me a summary of all findings discovered so far.' },
  ];

  // Render individual messages
  const renderMessage = (msg) => {
    switch (msg.type) {
      case 'tool_call':
        return <ToolCallCard key={msg.id} data={msg} />;
      case 'approval_request':
        return (
          <ApprovalCard
            key={msg.id}
            data={msg.content}
            responded={msg.responded}
            approvedValue={msg.approvedValue}
            onApprove={(actionId) => handleApproval(actionId, true)}
            onDeny={(actionId) => handleApproval(actionId, false)}
          />
        );
      case 'reasoning':
        return <ReasoningBlock key={msg.id} content={msg.content} />;
      case 'error':
        return (
          <div key={msg.id} className="chat-message system" style={{ animationDelay: '0s' }}>
            <div className="message-bubble" style={{ borderColor: 'rgba(239, 68, 68, 0.3)', color: '#ef4444' }}>
              ⚠️ {msg.content}
            </div>
          </div>
        );
      default:
        return <ChatMessage key={msg.id} message={msg} />;
    }
  };

  return (
    <div className="chat-container">
      <div className="chat-main">
        {/* Top View Selector Tabs */}
        <div className="d-flex align-items-center gap-2 px-3 py-2 border-bottom border-secondary bg-black bg-opacity-40">
          <button
            className={`btn btn-sm ${activeTab === 'chat' ? 'btn-info text-dark fw-bold' : 'btn-outline-secondary text-light'}`}
            onClick={() => setActiveTab('chat')}
          >
            💬 Conversational Guidance
          </button>
          <button
            className={`btn btn-sm ${activeTab === 'findings' ? 'btn-info text-dark fw-bold' : 'btn-outline-secondary text-light'}`}
            onClick={() => setActiveTab('findings')}
          >
            🛡️ Findings Dossier ({findings.length})
          </button>
        </div>

        {activeTab === 'findings' ? (
          <div className="p-3 overflow-auto flex-grow-1" style={{ height: 'calc(100vh - 120px)' }}>
            <FindingsPanel findings={findings} onFindingUpdated={fetchSidebarData} />
          </div>
        ) : (
          <>
            {/* Messages Area */}
            <div className="chat-messages">
              {messages.length === 0 && !isWaiting && (
                <div className="chat-welcome">
                  <div className="welcome-icon">
                    <FiShield />
                  </div>
                  <h3>Welcome to CyberGuard AI</h3>
                  <p>
                    {assessment
                      ? `Assessment: ${assessment.name} — Target: ${assessment.target}. Describe your goals or use the quick actions below to begin.`
                      : 'Start by describing your assessment goals or use the quick actions below.'}
                  </p>
                </div>
              )}

              {messages.map(renderMessage)}

              {/* Streaming message */}
              {currentStreamMessage && (
                <ChatMessage
                  message={{
                    id: 'streaming',
                    role: 'assistant',
                    type: 'text',
                    content: currentStreamMessage,
                  }}
                />
              )}

              {/* Typing indicator */}
              {isWaiting && !currentStreamMessage && (
                <div className="typing-indicator">
                  <div className="dots">
                    <span className="dot"></span>
                    <span className="dot"></span>
                    <span className="dot"></span>
                  </div>
                  <span className="typing-text">CyberGuard AI is analyzing...</span>
                </div>
              )}

              <div ref={messagesEndRef} />
            </div>

            {/* Input Area */}
            <div className="chat-input-area">
              <div className="quick-actions">
                {quickActions.map((qa, idx) => (
                  <button
                    key={idx}
                    className="quick-action-btn"
                    onClick={() => handleQuickAction(qa.action)}
                  >
                    {qa.label}
                  </button>
                ))}
              </div>
              <div className="chat-input-wrapper">
                <textarea
                  ref={textareaRef}
                  value={inputValue}
                  onChange={handleInputChange}
                  onKeyDown={handleKeyDown}
                  placeholder="Describe your assessment goals or ask about findings..."
                  rows={1}
                  disabled={!wsConnected}
                />
                <button
                  className="chat-send-btn"
                  onClick={handleSend}
                  disabled={!inputValue.trim() || isWaiting || !wsConnected}
                  title="Send message"
                >
                  <FiSend />
                </button>
              </div>
            </div>
          </>
        )}
      </div>

      {/* Right sidebar */}
      <QuickInfoPanel
        assessment={assessment}
        findings={findings}
        scans={scans}
        onRefresh={fetchSidebarData}
      />
    </div>
  );
}

/* Reasoning Block (inline component) */
function ReasoningBlock({ content }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="reasoning-block">
      <button className="reasoning-toggle" onClick={() => setExpanded(!expanded)}>
        💡 Agent Reasoning
        <span style={{ marginLeft: 'auto', fontSize: '0.75rem' }}>
          {expanded ? '▲' : '▼'}
        </span>
      </button>
      {expanded && <div className="reasoning-content">{content}</div>}
    </div>
  );
}

export default ChatContainer;
