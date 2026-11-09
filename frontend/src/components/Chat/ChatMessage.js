import React, { useState, useCallback } from 'react';
import ReactMarkdown from 'react-markdown';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { oneDark } from 'react-syntax-highlighter/dist/esm/styles/prism';
import { FiCopy, FiCheck, FiChevronDown, FiChevronUp } from 'react-icons/fi';
import { format } from 'date-fns';

const MAX_COLLAPSED_LENGTH = 1200;

function ChatMessage({ message }) {
  const { role, content, timestamp } = message;
  const [copied, setCopied] = useState(false);
  const [expanded, setExpanded] = useState(false);

  const isLong = content && content.length > MAX_COLLAPSED_LENGTH;
  const displayContent = isLong && !expanded ? content.slice(0, MAX_COLLAPSED_LENGTH) + '...' : content;

  const handleCopy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(content);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error('Copy failed:', err);
    }
  }, [content]);

  const formatTimestamp = (ts) => {
    if (!ts) return '';
    try {
      return format(new Date(ts), 'HH:mm');
    } catch {
      return '';
    }
  };

  const roleClass = role === 'user' ? 'user' : role === 'assistant' ? 'assistant' : 'system';

  return (
    <div className={`chat-message ${roleClass}`}>
      <div className="message-bubble">
        {role === 'assistant' ? (
          <ReactMarkdown
            components={{
              code({ node, inline, className, children, ...props }) {
                const match = /language-(\w+)/.exec(className || '');
                const codeString = String(children).replace(/\n$/, '');

                if (!inline && match) {
                  return (
                    <div style={{ position: 'relative' }}>
                      <div
                        style={{
                          position: 'absolute',
                          top: 4,
                          right: 4,
                          display: 'flex',
                          gap: 4,
                          alignItems: 'center',
                        }}
                      >
                        <span
                          style={{
                            fontSize: '0.65rem',
                            color: '#6b7280',
                            textTransform: 'uppercase',
                          }}
                        >
                          {match[1]}
                        </span>
                      </div>
                      <SyntaxHighlighter
                        style={oneDark}
                        language={match[1]}
                        PreTag="div"
                        customStyle={{
                          margin: '8px 0',
                          borderRadius: '8px',
                          fontSize: '0.82rem',
                          background: 'rgba(0,0,0,0.5)',
                        }}
                        {...props}
                      >
                        {codeString}
                      </SyntaxHighlighter>
                    </div>
                  );
                }

                if (!inline) {
                  return (
                    <SyntaxHighlighter
                      style={oneDark}
                      language="text"
                      PreTag="div"
                      customStyle={{
                        margin: '8px 0',
                        borderRadius: '8px',
                        fontSize: '0.82rem',
                        background: 'rgba(0,0,0,0.5)',
                      }}
                      {...props}
                    >
                      {codeString}
                    </SyntaxHighlighter>
                  );
                }

                return (
                  <code className={className} {...props}>
                    {children}
                  </code>
                );
              },
              a({ href, children }) {
                return (
                  <a href={href} target="_blank" rel="noopener noreferrer">
                    {children}
                  </a>
                );
              },
            }}
          >
            {displayContent}
          </ReactMarkdown>
        ) : (
          <span style={{ whiteSpace: 'pre-wrap' }}>{displayContent}</span>
        )}

        {isLong && (
          <button
            onClick={() => setExpanded(!expanded)}
            style={{
              background: 'none',
              border: 'none',
              color: '#00d4ff',
              fontSize: '0.78rem',
              cursor: 'pointer',
              padding: '4px 0',
              display: 'flex',
              alignItems: 'center',
              gap: 4,
              marginTop: 4,
            }}
          >
            {expanded ? <FiChevronUp /> : <FiChevronDown />}
            {expanded ? 'Show less' : 'Show more'}
          </button>
        )}

        <div className="message-meta">
          <span>{formatTimestamp(timestamp)}</span>
          {role !== 'system' && (
            <button className="message-copy-btn" onClick={handleCopy} title="Copy message">
              {copied ? <FiCheck style={{ color: '#10b981' }} /> : <FiCopy />}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

export default React.memo(ChatMessage);
