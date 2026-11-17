import React, { useState, useEffect, useMemo, useRef } from 'react';
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
  Crosshair,
  ArrowRight,
  SlidersHorizontal,
  Layers,
  Activity,
  CheckCircle2
} from 'lucide-react';

export default function AttackPathGraph({ graphData, onSelectEvent, selectedEventUuid }) {
  const [activeStep, setActiveStep] = useState(null);
  const [isPlaying, setIsPlaying] = useState(false);
  const [hoveredNode, setHoveredNode] = useState(null);
  const [viewMode, setViewMode] = useState('linear'); // 'linear' (straight line) | 'topology'

  if (!graphData || !graphData.nodes || graphData.nodes.length === 0) {
    return (
      <div className="bg-[#111827] border border-[#1f293d] rounded-xl p-8 text-center text-gray-400">
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
      }, 2200);
    }
    return () => clearInterval(interval);
  }, [isPlaying, edges.length]);

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
        return 'border-red-500/40 bg-red-950/30 text-red-300';
      case 'cloud_resource':
        return 'border-cyan-500/40 bg-cyan-950/30 text-cyan-300';
      case 'server':
        return 'border-purple-500/40 bg-purple-950/30 text-purple-300';
      default:
        return 'border-blue-500/40 bg-blue-950/30 text-blue-300';
    }
  };

  // ── Calculated Clean Linear & Distributed Coordinates ───────────────────────
  const nodePositions = useMemo(() => {
    const pos = {};
    const c2Nodes = nodes.filter(n => n.type === 'c2_server');
    const endpointNodes = nodes.filter(n => n.type === 'endpoint');
    const serverNodes = nodes.filter(n => n.type === 'server');
    const cloudNodes = nodes.filter(n => n.type === 'cloud_resource');

    // 4 Distinct Horizontal Stages with wide separation so cards & labels never overlap
    // Stage 1 (Attacker / C2): X: 110
    // Stage 2 (Patient-Zero Endpoint): X: 370
    // Stage 3 (Lateral Pivot / Server): X: 650
    // Stage 4 (Exfiltration Target / Cloud): X: 930
    c2Nodes.forEach((n, idx) => {
      pos[n.id] = { x: 120, y: 150 + idx * 160 };
    });

    endpointNodes.forEach((n, idx) => {
      pos[n.id] = { x: 380, y: 140 + idx * 150 };
    });

    serverNodes.forEach((n, idx) => {
      pos[n.id] = { x: 660, y: 150 + idx * 160 };
    });

    cloudNodes.forEach((n, idx) => {
      pos[n.id] = { x: 940, y: 140 + idx * 150 };
    });

    nodes.forEach((n, idx) => {
      if (!pos[n.id]) {
        pos[n.id] = {
          x: 200 + (idx * 220) % 800,
          y: 100 + (idx * 120) % 320
        };
      }
    });

    return pos;
  }, [nodes]);

  // Group edges by connection pair to apply smart vertical staggering to badges
  const edgePairCount = useMemo(() => {
    const pairMap = {};
    edges.forEach((edge) => {
      const pairKey = [edge.source, edge.target].sort().join(':::');
      pairMap[pairKey] = (pairMap[pairKey] || 0) + 1;
    });
    return pairMap;
  }, [edges]);

  // Track index within pair for vertical staggering
  const edgePairIndexMap = useMemo(() => {
    const counts = {};
    const indexMap = {};
    edges.forEach((edge) => {
      const pairKey = [edge.source, edge.target].sort().join(':::');
      indexMap[edge.id] = counts[pairKey] || 0;
      counts[pairKey] = (counts[pairKey] || 0) + 1;
    });
    return indexMap;
  }, [edges]);

  return (
    <div className="space-y-4">
      {/* ── Top Controls & Stats Bar ────────────────────────────────────────── */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-[#1f293d]">
        <div>
          <div className="flex items-center gap-2 flex-wrap">
            <h2 className="text-sm font-bold text-gray-200 flex items-center gap-1.5 font-mono">
              <Crosshair className="w-4 h-4 text-blue-400" />
              Attack Path Topology & Lateral Movement Sequence
            </h2>
            <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-blue-950/60 border border-blue-500/30 text-blue-300">
              {nodes.length} Stage Nodes &bull; {edges.length} Traversals
            </span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
              Full-Width Linear Flow
            </span>
          </div>
          <p className="text-xs text-gray-400 mt-0.5">
            Stages arranged in a straight progression: <strong className="text-red-400">Initial Access</strong> &rarr; <strong className="text-blue-400">Endpoint Weaponization</strong> &rarr; <strong className="text-purple-400">Internal Pivot</strong> &rarr; <strong className="text-cyan-400">Cloud Exfiltration</strong>
          </p>
        </div>

        {/* View Toggle & Playback Controls */}
        <div className="flex items-center gap-2 self-start sm:self-auto flex-wrap">
          <div className="flex items-center bg-[#0b0f17] border border-[#1f293d] rounded-lg p-0.5 text-xs font-mono">
            <button
              onClick={() => setViewMode('linear')}
              className={`px-2.5 py-1 rounded-md transition ${
                viewMode === 'linear'
                  ? 'bg-blue-600 text-white font-bold shadow'
                  : 'text-gray-400 hover:text-gray-200'
              }`}
            >
              Straight Line
            </button>
            <button
              onClick={() => setViewMode('topology')}
              className={`px-2.5 py-1 rounded-md transition ${
                viewMode === 'topology'
                  ? 'bg-blue-600 text-white font-bold shadow'
                  : 'text-gray-400 hover:text-gray-200'
              }`}
            >
              Topology Mesh
            </button>
          </div>

          <button
            onClick={() => setIsPlaying(!isPlaying)}
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-bold font-mono rounded-lg transition-all ${
              isPlaying
                ? 'bg-amber-600 hover:bg-amber-500 text-white shadow-md shadow-amber-600/30'
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
            className="p-1.5 rounded-lg bg-[#0b0f17] hover:bg-gray-800 border border-[#1f293d] text-gray-300 transition"
            title="Reset Sequence"
          >
            <RotateCcw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* ── Mode 1: Clean Straight Line Stepper View (Straight Progression) ─── */}
      {viewMode === 'linear' && (
        <div className="bg-[#0b0f17] border border-[#1f293d] rounded-xl p-5 space-y-5">
          <div className="flex items-center justify-between text-xs font-mono text-gray-400 border-b border-[#1f293d] pb-2">
            <span className="font-bold text-gray-300 flex items-center gap-1.5">
              <Activity className="w-3.5 h-3.5 text-blue-400" />
              Kill Chain Stage Progression (Straight Line)
            </span>
            <span className="text-[11px] text-gray-500">
              {activeStep !== null ? `Active Step ${activeStep + 1} of ${edges.length}` : 'Click any stage to inspect evidence'}
            </span>
          </div>

          {/* Row 1: Primary Stages in a Straight Line */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 relative">
            {[
              {
                stage: 'Stage 1',
                title: 'External C2 Server',
                sub: 'Initial Access & Staging',
                type: 'c2_server',
                nodes: nodes.filter(n => n.type === 'c2_server'),
                badge: 'border-red-500/40 bg-red-950/20 text-red-300',
                edgeLabel: 'T1071.001 Web Protocol'
              },
              {
                stage: 'Stage 2',
                title: 'Compromised Endpoint',
                sub: 'Weaponization & Defense Evasion',
                type: 'endpoint',
                nodes: nodes.filter(n => n.type === 'endpoint'),
                badge: 'border-blue-500/40 bg-blue-950/20 text-blue-300',
                edgeLabel: 'T1059.001 PowerShell'
              },
              {
                stage: 'Stage 3',
                title: 'Domain Infrastructure',
                sub: 'Lateral Movement & Pivot',
                type: 'server',
                nodes: nodes.filter(n => n.type === 'server'),
                badge: 'border-purple-500/40 bg-purple-950/20 text-purple-300',
                edgeLabel: 'T1021.002 SMB Exec'
              },
              {
                stage: 'Stage 4',
                title: 'Cloud Target Enclave',
                sub: 'S3 Data Exfiltration',
                type: 'cloud_resource',
                nodes: nodes.filter(n => n.type === 'cloud_resource'),
                badge: 'border-cyan-500/40 bg-cyan-950/20 text-cyan-300',
                edgeLabel: 'T1530 S3 Exfil'
              }
            ].map((col, cIdx) => (
              <div key={col.stage} className="space-y-3 relative">
                {/* Connecting Arrow between columns (straight line flow) */}
                {cIdx < 3 && (
                  <div className="hidden md:flex absolute -right-3 top-14 z-20 items-center justify-center w-6 h-6 rounded-full bg-[#111827] border border-blue-500/40 text-blue-400">
                    <ArrowRight className="w-3.5 h-3.5" />
                  </div>
                )}

                {/* Stage Header Pill */}
                <div className="flex items-center justify-between px-2">
                  <span className="text-[10px] font-mono font-bold text-gray-500 uppercase tracking-widest">
                    {col.stage}
                  </span>
                  <span className="text-[10px] font-mono text-gray-400">
                    {col.sub}
                  </span>
                </div>

                {/* Node Cards in this stage */}
                <div className="space-y-2">
                  {col.nodes.map(node => {
                    const isHovered = hoveredNode === node.id;
                    const isNodeActive = activeStep !== null && (
                      edges[activeStep]?.source === node.id || edges[activeStep]?.target === node.id
                    );

                    return (
                      <div
                        key={node.id}
                        onMouseEnter={() => setHoveredNode(node.id)}
                        onMouseLeave={() => setHoveredNode(null)}
                        className={`p-3.5 rounded-xl border transition-all cursor-pointer ${
                          getNodeBadgeClass(node.type)
                        } ${
                          isNodeActive ? 'ring-2 ring-red-400 shadow-lg shadow-red-500/20' : ''
                        } ${
                          isHovered ? 'scale-[1.02] border-blue-400 shadow-md' : ''
                        }`}
                      >
                        <div className="flex items-center gap-2.5 mb-2">
                          <div className="p-2 rounded-lg bg-[#0b0f17] border border-[#1f293d] shrink-0">
                            {getNodeIcon(node.type)}
                          </div>
                          <div className="min-w-0">
                            <span className="text-xs font-bold text-white block truncate">
                              {node.label}
                            </span>
                            <span className="text-[9px] font-mono uppercase text-gray-400">
                              {node.type.replace('_', ' ')}
                            </span>
                          </div>
                        </div>

                        {node.users && node.users.length > 0 && (
                          <div className="text-[10px] font-mono text-amber-300 bg-[#0b0f17]/70 px-2 py-1 rounded border border-[#1f293d] truncate">
                            Account: {node.users[0]}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>

          {/* Row 2: Sequential Attack Traversals (Clean Horizontal Bridge) */}
          <div className="pt-4 border-t border-[#1f293d]">
            <div className="flex items-center justify-between text-xs font-mono text-gray-400 mb-2">
              <span className="font-bold text-gray-300">Observed Lateral Traversals in Chronological Order</span>
              <span className="text-[10px] text-gray-500">Click any step to inspect correlated forensic evidence</span>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-2">
              {edges.map((edge, idx) => {
                const isStepActive = activeStep === idx;
                const isSelected = selectedEventUuid === edge.event_uuid;

                return (
                  <button
                    key={edge.id}
                    onClick={() => {
                      setActiveStep(idx);
                      onSelectEvent(edge.event_uuid);
                    }}
                    className={`p-2.5 rounded-lg border text-left transition font-mono ${
                      isStepActive || isSelected
                        ? 'bg-blue-600 text-white border-blue-400 shadow-md font-bold'
                        : 'bg-[#111827] border-[#1f293d] text-gray-300 hover:border-gray-600 hover:bg-[#151e30]'
                    }`}
                  >
                    <div className="flex items-center justify-between text-[10px] text-gray-400 mb-1">
                      <span className="text-gray-300">Step {idx + 1}</span>
                      <span className={`px-1 py-0.2 rounded text-[9px] ${
                        isStepActive ? 'bg-red-500 text-white' : 'bg-gray-800 text-gray-400'
                      }`}>
                        {edge.technique_id}
                      </span>
                    </div>
                    <div className="text-xs truncate font-bold text-white">
                      {edge.label}
                    </div>
                  </button>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* ── Mode 2: Full-Width Dynamic SVG Canvas (Cleanly Spaced) ─────────── */}
      {viewMode === 'topology' && (
        <div className="relative w-full h-[460px] bg-[#080D1A] border border-[#1f293d] rounded-xl overflow-hidden select-none shadow-inner">
          
          {/* Subtle Grid Pattern */}
          <svg className="absolute inset-0 w-full h-full opacity-15 pointer-events-none">
            <defs>
              <pattern id="clean-grid" width="40" height="40" patternUnits="userSpaceOnUse">
                <path d="M 40 0 L 0 0 0 40" fill="none" stroke="#3B82F6" strokeWidth="0.5" />
              </pattern>
            </defs>
            <rect width="100%" height="100%" fill="url(#clean-grid)" />
          </svg>

          {/* Directed SVG Edges with Smooth Bézier Curves */}
          <svg className="absolute inset-0 w-full h-full pointer-events-none">
            <defs>
              <marker id="arr-default" markerWidth="8" markerHeight="8" refX="16" refY="4" orient="auto">
                <polygon points="0 0, 8 4, 0 8" fill="#475569" />
              </marker>
              <marker id="arr-active" markerWidth="10" markerHeight="10" refX="16" refY="5" orient="auto">
                <polygon points="0 0, 10 5, 0 10" fill="#EF4444" />
              </marker>
              <marker id="arr-selected" markerWidth="10" markerHeight="10" refX="16" refY="5" orient="auto">
                <polygon points="0 0, 10 5, 0 10" fill="#3B82F6" />
              </marker>
            </defs>

            {edges.map((edge, idx) => {
              const p1 = nodePositions[edge.source];
              const p2 = nodePositions[edge.target];
              if (!p1 || !p2) return null;

              const isSelected = selectedEventUuid === edge.event_uuid;
              const isStepActive = activeStep === idx;

              // Curve offsets to ensure parallel edges do not overlap
              const pairIdx = edgePairIndexMap[edge.id] || 0;
              const curveOffset = pairIdx === 0 ? 0 : pairIdx % 2 === 1 ? pairIdx * 25 : -pairIdx * 25;
              const midX = (p1.x + p2.x) / 2;
              const midY = (p1.y + p2.y) / 2 + curveOffset;

              let strokeColor = '#334155';
              let strokeWidth = 2;
              let marker = 'url(#arr-default)';

              if (isSelected) {
                strokeColor = '#3B82F6';
                strokeWidth = 3.5;
                marker = 'url(#arr-selected)';
              } else if (isStepActive) {
                strokeColor = '#EF4444';
                strokeWidth = 4;
                marker = 'url(#arr-active)';
              }

              return (
                <path
                  key={edge.id}
                  d={`M ${p1.x} ${p1.y} Q ${midX} ${midY} ${p2.x} ${p2.y}`}
                  fill="none"
                  stroke={strokeColor}
                  strokeWidth={strokeWidth}
                  strokeDasharray={isStepActive ? '6,4' : 'none'}
                  markerEnd={marker}
                  className="transition-all duration-300"
                />
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
                  className={`flex flex-col items-center p-3 rounded-xl border backdrop-blur-md shadow-xl ${
                    getNodeBadgeClass(node.type)
                  } ${
                    isNodeInActiveStep ? 'ring-2 ring-red-400 shadow-red-500/30' : ''
                  } ${
                    isHovered ? 'scale-105 border-blue-400 shadow-blue-500/20' : ''
                  }`}
                >
                  <div className="p-2 rounded-lg bg-[#0b0f17] mb-1">
                    {getNodeIcon(node.type)}
                  </div>
                  <span className="text-[11px] font-bold text-gray-100 tracking-tight text-center max-w-[130px] truncate">
                    {node.label}
                  </span>
                  <span className="text-[9px] font-mono text-gray-400 uppercase mt-0.5">
                    {node.type.replace('_', ' ')}
                  </span>
                  {node.users && node.users.length > 0 && (
                    <span className="text-[9px] font-mono text-amber-300 truncate max-w-[120px] mt-0.5">
                      {node.users[0]}
                    </span>
                  )}
                </div>
              </div>
            );
          })}

          {/* Non-Overlapping Staggered Traversal Badges */}
          {edges.map((edge, idx) => {
            const p1 = nodePositions[edge.source];
            const p2 = nodePositions[edge.target];
            if (!p1 || !p2) return null;

            const pairIdx = edgePairIndexMap[edge.id] || 0;
            const verticalStagger = pairIdx === 0 ? -18 : pairIdx % 2 === 1 ? -18 - (pairIdx * 20) : -18 + (pairIdx * 20);
            const midX = (p1.x + p2.x) / 2;
            const midY = (p1.y + p2.y) / 2 + verticalStagger;

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
                className={`absolute z-20 cursor-pointer px-2 py-0.5 rounded text-[10px] font-mono border shadow-md transition-all ${
                  isSelected
                    ? 'bg-blue-600 text-white border-blue-400 font-bold scale-105 shadow-blue-500/40'
                    : isStepActive
                    ? 'bg-red-600 text-white border-red-400 font-bold scale-110 shadow-red-500/40'
                    : 'bg-[#0b0f17]/95 text-gray-300 border-[#1f293d] hover:border-blue-400 hover:text-white'
                }`}
              >
                <div className="flex items-center gap-1">
                  <span className="font-bold">{edge.technique_id}</span>
                  <span className="hidden sm:inline text-[9px] text-gray-400 truncate max-w-[100px]">
                    {edge.label}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* ── Sequence Step Pills ────────────────────────────────────────────── */}
      <div className="space-y-1.5 pt-2">
        <div className="flex items-center justify-between text-xs text-gray-400 font-mono">
          <span className="font-semibold text-gray-300">Fast Stepper (Step-by-Step Traversal)</span>
          <span className="text-[11px] text-gray-500">
            {activeStep !== null ? `Traversal ${activeStep + 1} of ${edges.length}` : 'All traversals armed'}
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
                className={`flex-shrink-0 flex items-center gap-1 px-2.5 py-1 rounded text-xs font-mono border transition-all ${
                  isStepActive || isSelected
                    ? 'bg-blue-600 text-white border-blue-400 font-bold shadow'
                    : 'bg-[#111827] text-gray-300 border-[#1f293d] hover:bg-gray-800'
                }`}
              >
                <span className="w-4 h-4 rounded-full bg-[#0b0f17] text-[10px] flex items-center justify-center font-bold">
                  {idx + 1}
                </span>
                <span className="truncate max-w-[120px]">{edge.technique_id}</span>
              </button>
            );
          })}
        </div>
      </div>
    </div>
  );
}
