import React from 'react';
import { Doughnut } from 'react-chartjs-2';
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from 'chart.js';

ChartJS.register(ArcElement, Tooltip, Legend);

function StatsChart({ findings, total }) {
  const data = {
    labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
    datasets: [
      {
        data: [
          findings.critical || 0,
          findings.high || 0,
          findings.medium || 0,
          findings.low || 0,
          findings.info || 0,
        ],
        backgroundColor: [
          'rgba(239, 68, 68, 0.8)',
          'rgba(249, 115, 22, 0.8)',
          'rgba(245, 158, 11, 0.8)',
          'rgba(59, 130, 246, 0.8)',
          'rgba(107, 114, 128, 0.8)',
        ],
        borderColor: [
          'rgba(239, 68, 68, 1)',
          'rgba(249, 115, 22, 1)',
          'rgba(245, 158, 11, 1)',
          'rgba(59, 130, 246, 1)',
          'rgba(107, 114, 128, 1)',
        ],
        borderWidth: 1,
        hoverBorderWidth: 2,
        hoverOffset: 6,
      },
    ],
  };

  const options = {
    responsive: true,
    maintainAspectRatio: true,
    cutout: '65%',
    plugins: {
      legend: {
        position: 'bottom',
        labels: {
          color: '#9ca3af',
          padding: 12,
          font: { size: 11 },
          usePointStyle: true,
          pointStyleWidth: 8,
        },
      },
      tooltip: {
        backgroundColor: '#1a2236',
        titleColor: '#e5e7eb',
        bodyColor: '#e5e7eb',
        borderColor: '#1f2937',
        borderWidth: 1,
        padding: 10,
        displayColors: true,
        callbacks: {
          label: function (context) {
            const value = context.parsed;
            const percentage = total > 0 ? ((value / total) * 100).toFixed(1) : 0;
            return ` ${context.label}: ${value} (${percentage}%)`;
          },
        },
      },
    },
  };

  return (
    <div className="chart-container">
      <Doughnut data={data} options={options} />
      <div className="chart-center-text">
        <span className="chart-total">{total}</span>
        <span className="chart-label">Findings</span>
      </div>
    </div>
  );
}

export default StatsChart;
