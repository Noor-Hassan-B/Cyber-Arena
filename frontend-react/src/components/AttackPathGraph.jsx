import React, { useState, useEffect } from 'react';
import { 
  Play, 
  Pause, 
  RotateCcw, 
  ShieldAlert, 
  Server, 
  Laptop, 
  Cloud, 
  Radio, 
  ExternalLink,
  ChevronRight,
  Info,
  Zap,
  Crosshair
} from 'lucide-react';

export default function AttackPathGraph({ graphData, onSelectEvent, selectedEventUuid }) {
  const [activeStep, setActiveStep] = useState(null);
  const [isPlaying, setIsPlaying] = useState(false);
  const [hoveredNode, setHoveredNode] = useState(null);

  if (!graphData || !graphData.nodes || graphData.nodes.length === 0) {
    return (
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-8 text-center text-slate-400">
        No graph topology data available for this scenario.
      </div>
    );
  }

  const { nodes, edges, critical_path, blast_radius } = graphData;

  // Auto playback of attack path sequence
  useEffect(() => {
    let interval = null;
    if (isPlaying) {
      interval = setInterval(() => {
        setActiveStep((prev) => {
          if (prev === null || prev >= edges.length - 1) {
            return 0;
          }
          return prev + 1;
        });
      }, 2000);
    }
    return () => clearInterval(interval);
  }, [isPlaying, edges.length]);

  // Position calculation for dynamic responsive layout
  // Arranges nodes logically from left (Initial Access / Attacker) to right (Target / Cloud Exfil)
  const nodePositions = calculateNodeLayout(nodes);

  const getNodeIcon = (type) => {
    switch (type) {
      case 'c2_server':
        return <Radio className="w-5 h-5 text-red-400 animate-pulse" />;
      case 'cloud_resource':
        return <Cloud className="w-5 h-5 text-cyan-400" />;
      case 'server':
        return <Server className="w-5 h-5 text-purple-400" />;
      case 'endpoint':
      default:
        return <Laptop className="w-5 h-5 text-blue-400" />;
    }
  };

  const getNodeBadgeClass = (type) => {
    switch (type) {
      case 'c2_server':
        return 'border-red-500/50 bg-red-950/40 text-red-300';
      case 'cloud_resource':
        return 'border-cyan-500/50 bg-cyan-950/40 text-cyan-300';
      case 'server':
        return 'border-purple-500/50 bg-purple-950/40 text-purple-300';
      default:
        return 'border-blue-500/50 bg-blue-950/40 text-blue-300';
    }
  };

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 sm:p-5 shadow-xl space-y-4">
      {/* Top Graph Controls Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-3">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-sm font-bold text-slate-100 flex items-center gap-1.5">
              <Crosshair className="w-4 h-4 text-blue-400" />
              Interactive Attack Path & Lateral Movement Topology
            </h2>
            <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-blue-950/80 border border-blue-500/30 text-blue-300">
              {nodes.length} Nodes &bull; {edges.length} Traversals
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Click any edge or node to inspect evidence, or run animated attack reconstruction.
          </p>
        </div>

        {/* Playback Controls */}
        <div className="flex items-center gap-2 self-start sm:self-auto">
          <button
            onClick={() => setIsPlaying(!isPlaying)}
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg transition-all ${
              isPlaying
                ? 'bg-amber-600 hover:bg-amber-500 text-white'
                : 'bg-blue-600 hover:bg-blue-500 text-white shadow-md shadow-blue-600/30'
            }`}
          >
            {isPlaying ? (
              <>
                <Pause className="w-3.5 h-3.5" /> Pause Sequence
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 fill-current" /> Play Attack Sequence
              </>
            )}
          </button>

          <button
            onClick={() => {
              setIsPlaying(false);
              setActiveStep(null);
            }}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition"
            title="Reset Sequence"
          >
            <RotateCcw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* SVG Canvas Graph Visualization */}
      <div className="relative w-full h-[380px] bg-[#080D1A] border border-slate-800/80 rounded-xl overflow-hidden select-none">
        
        {/* Background Grid Pattern */}
        <svg className="absolute inset-0 w-full h-full opacity-20 pointer-events-none">
          <defs>
            <pattern id="grid" width="30" height="30" patternUnits="userSpaceOnUse">
              <path d="M 30 0 L 0 0 0 30" fill="none" stroke="#3B82F6" strokeWidth="0.5" />
            </pattern>
          </defs>
          <rect width="100%" height="100%" fill="url(#grid)" />
        </svg>

        {/* Directed SVG Edges */}
        <svg className="absolute inset-0 w-full h-full pointer-events-none">
          <defs>
            <marker
              id="arrowhead-default"
              markerWidth="8"
              markerHeight="8"
              refX="18"
              refY="4"
              orient="auto"
            >
              <polygon points="0 0, 8 4, 0 8" fill="#475569" />
            </marker>
            <marker
              id="arrowhead-active"
              markerWidth="10"
              markerHeight="10"
              refX="18"
              refY="5"
              orient="auto"
            >
              <polygon points="0 0, 10 5, 0 10" fill="#EF4444" />
            </marker>
            <marker
              id="arrowhead-selected"
              markerWidth="10"
              markerHeight="10"
              refX="18"
              refY="5"
              orient="auto"
            >
              <polygon points="0 0, 10 5, 0 10" fill="#3B82F6" />
            </marker>
          </defs>

          {edges.map((edge, idx) => {
            const p1 = nodePositions[edge.source];
            const p2 = nodePositions[edge.target];
            if (!p1 || !p2) return null;

            const isStepActive = activeStep === idx;
            const isSelected = selectedEventUuid === edge.event_uuid;

            // Curved bezier path
            const dx = p2.x - p1.x;
            const dy = p2.y - p1.y;
            const cx1 = p1.x + dx * 0.5;
            const cy1 = p1.y - 20;

            let strokeColor = '#334155';
            let strokeWidth = 2;
            let marker = 'url(#arrowhead-default)';

            if (isSelected) {
              strokeColor = '#3B82F6';
              strokeWidth = 3.5;
              marker = 'url(#arrowhead-selected)';
            } else if (isStepActive) {
              strokeColor = '#EF4444';
              strokeWidth = 4;
              marker = 'url(#arrowhead-active)';
            }

            return (
              <g key={edge.id}>
                <path
                  d={`M ${p1.x} ${p1.y} Q ${cx1} ${cy1} ${p2.x} ${p2.y}`}
                  fill="none"
                  stroke={strokeColor}
                  strokeWidth={strokeWidth}
                  strokeDasharray={isStepActive ? '6,4' : 'none'}
                  markerEnd={marker}
                  className="transition-all duration-300"
                />
              </g>
            );
          })}
        </svg>

        {/* Interactive Clickable Nodes */}
        {nodes.map((node) => {
          const pos = nodePositions[node.id];
          if (!pos) return null;

          const isHovered = hoveredNode === node.id;
          const isNodeInActiveStep = activeStep !== null && (
            edges[activeStep]?.source === node.id || edges[activeStep]?.target === node.id
          );

          return (
            <div
              key={node.id}
              style={{
                left: `${pos.x}px`,
                top: `${pos.y}px`,
                transform: 'translate(-50%, -50%)'
              }}
              onMouseEnter={() => setHoveredNode(node.id)}
              onMouseLeave={() => setHoveredNode(null)}
              className={`absolute cursor-pointer transition-all duration-300 z-10 ${
                isNodeInActiveStep ? 'scale-110' : ''
              }`}
            >
              <div
                className={`flex flex-col items-center p-2.5 rounded-xl border backdrop-blur-md shadow-lg ${
                  getNodeBadgeClass(node.type)
                } ${
                  isNodeInActiveStep ? 'ring-2 ring-red-400 glow-red' : ''
                } ${
                  isHovered ? 'scale-105 border-slate-400 shadow-blue-500/20' : ''
                }`}
              >
                <div className="p-2 rounded-lg bg-slate-900/80 mb-1">
                  {getNodeIcon(node.type)}
                </div>
                <span className="text-[11px] font-bold text-slate-200 tracking-tight text-center max-w-[130px] truncate">
                  {node.label}
                </span>
                <span className="text-[9px] font-mono text-slate-400 uppercase mt-0.5">
                  {node.type.replace('_', ' ')}
                </span>
                {node.users && node.users.length > 0 && (
                  <span className="text-[9px] font-mono text-amber-300/90 truncate max-w-[120px]">
                    User: {node.users[0]}
                  </span>
                )}
              </div>
            </div>
          );
        })}

        {/* Edge Action Badges (Clickable to trigger evidence) */}
        {edges.map((edge, idx) => {
          const p1 = nodePositions[edge.source];
          const p2 = nodePositions[edge.target];
          if (!p1 || !p2) return null;

          const midX = (p1.x + p2.x) / 2;
          const midY = (p1.y + p2.y) / 2 - 14;
          const isSelected = selectedEventUuid === edge.event_uuid;
          const isStepActive = activeStep === idx;

          return (
            <div
              key={`badge-${edge.id}`}
              style={{
                left: `${midX}px`,
                top: `${midY}px`,
                transform: 'translate(-50%, -50%)'
              }}
              onClick={() => onSelectEvent(edge.event_uuid)}
              className={`absolute z-20 cursor-pointer px-2 py-1 rounded text-[10px] font-mono border shadow-md transition-all ${
                isSelected
                  ? 'bg-blue-600 text-white border-blue-400 font-bold glow-blue scale-105'
                  : isStepActive
                  ? 'bg-red-600 text-white border-red-400 font-bold glow-red scale-110'
                  : 'bg-slate-950/90 text-slate-300 border-slate-700/80 hover:border-slate-500 hover:text-white'
              }`}
            >
              <div className="flex items-center gap-1">
                <span>{edge.technique_id}</span>
                <span className="hidden sm:inline font-sans text-[9px] text-slate-400">
                  {edge.label}
                </span>
              </div>
            </div>
          );
        })}

      </div>

      {/* Attack Sequence Step Breadcrumbs */}
      <div className="space-y-1.5">
        <div className="flex items-center justify-between text-xs text-slate-400">
          <span className="font-semibold text-slate-300">Attack Path Execution Sequence</span>
          <span className="font-mono text-[11px]">
            {activeStep !== null ? `Stage ${activeStep + 1} of ${edges.length}` : 'All steps shown'}
          </span>
        </div>

        <div className="flex items-center gap-1.5 overflow-x-auto pb-1 scrollbar-thin">
          {edges.map((edge, idx) => {
            const isStepActive = activeStep === idx;
            const isSelected = selectedEventUuid === edge.event_uuid;

            return (
              <button
                key={`btn-${edge.id}`}
                onClick={() => {
                  setActiveStep(idx);
                  onSelectEvent(edge.event_uuid);
                }}
                className={`flex-shrink-0 flex items-center gap-1 px-2 py-1 rounded text-xs font-mono border transition-all ${
                  isStepActive || isSelected
                    ? 'bg-blue-600 text-white border-blue-400 font-bold'
                    : 'bg-slate-900 text-slate-300 border-slate-800 hover:bg-slate-800'
                }`}
              >
                <span className="w-4 h-4 rounded-full bg-slate-950/60 text-[10px] flex items-center justify-center font-bold">
                  {idx + 1}
                </span>
                <span className="truncate max-w-[100px]">{edge.technique_id}</span>
              </button>
            );
          })}
        </div>
      </div>

    </div>
  );
}

// Layout coordinate generator for node positions
function calculateNodeLayout(nodes) {
  const positions = {};
  const total = nodes.length;
  const width = 860;
  const height = 360;

  // Categorize
  const c2Nodes = nodes.filter(n => n.type === 'c2_server');
  const endpointNodes = nodes.filter(n => n.type === 'endpoint');
  const serverNodes = nodes.filter(n => n.type === 'server');
  const cloudNodes = nodes.filter(n => n.type === 'cloud_resource');

  // Multi-tier column distribution
  // Column 1: Attacker / C2 (X: 120)
  // Column 2: Initial Endpoint (X: 320)
  // Column 3: Servers / Pivot (X: 540)
  // Column 4: Cloud / Exfil Targets (X: 740)

  c2Nodes.forEach((n, idx) => {
    positions[n.id] = {
      x: 120,
      y: 110 + idx * 140
    };
  });

  endpointNodes.forEach((n, idx) => {
    positions[n.id] = {
      x: 320,
      y: 100 + idx * 130
    };
  });

  serverNodes.forEach((n, idx) => {
    positions[n.id] = {
      x: 530,
      y: 110 + idx * 140
    };
  });

  cloudNodes.forEach((n, idx) => {
    positions[n.id] = {
      x: 740,
      y: 110 + idx * 130
    };
  });

  // Fallback for any unmapped
  nodes.forEach((n, idx) => {
    if (!positions[n.id]) {
      positions[n.id] = {
        x: 150 + (idx * 160) % 700,
        y: 80 + (idx * 70) % 250
      };
    }
  });

  return positions;
}
