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
  CheckCircle2,
  Network
} from 'lucide-react';
import PacketTracerSimulator from './PacketTracerSimulator';

export default function AttackPathGraph({ graphData, onSelectEvent, selectedEventUuid, activeSimulation, theme = 'dark' }) {
  const [activeStep, setActiveStep] = useState(null);
  const [isPlaying, setIsPlaying] = useState(false);
  const [hoveredNode, setHoveredNode] = useState(null);
  const [viewMode, setViewMode] = useState('packet-tracer'); // 'packet-tracer' (Cisco PT) | 'linear' | 'topology'

  if (!graphData || !graphData.nodes || graphData.nodes.length === 0) {
    return (
      <div className="bg-[#111827] border border-[#1f293d] rounded-xl p-8 text-center text-gray-400">
        No graph topology data available for this scenario.
      </div>
    );
  }

  const { nodes, edges, critical_path, blast_radius } = graphData;
  const isDark = theme === 'dark';

  // Auto playback of attack path sequence for classical modes
  useEffect(() => {
    let interval = null;
    if (isPlaying && viewMode !== 'packet-tracer') {
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
  }, [isPlaying, edges.length, viewMode]);

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

  const nodePositions = useMemo(() => {
    const pos = {};
    const c2Nodes = nodes.filter(n => n.type === 'c2_server');
    const endpointNodes = nodes.filter(n => n.type === 'endpoint');
    const serverNodes = nodes.filter(n => n.type === 'server');
    const cloudNodes = nodes.filter(n => n.type === 'cloud_resource');

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
      {/* ── View Mode Switcher Header ───────────────────────────────────────── */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2 border-b border-inherit">
        <div className="flex items-center gap-2 flex-wrap">
          <Network className="w-4 h-4 text-blue-500" />
          <span className="text-xs font-mono font-bold uppercase tracking-wider">
            Network Topology & Attack Simulation Engine:
          </span>
          <div className="flex items-center gap-1 bg-inherit border border-inherit rounded-lg p-0.5 text-xs font-mono">
            <button
              onClick={() => setViewMode('packet-tracer')}
              className={`px-3 py-1 rounded-md transition flex items-center gap-1.5 font-bold ${
                viewMode === 'packet-tracer'
                  ? 'bg-blue-600 text-white shadow-md'
                  : 'opacity-70 hover:opacity-100'
              }`}
            >
              <span>Cisco Packet Tracer (Recommended)</span>
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
            </button>
            <button
              onClick={() => setViewMode('linear')}
              className={`px-2.5 py-1 rounded-md transition ${
                viewMode === 'linear'
                  ? 'bg-blue-600 text-white font-bold shadow'
                  : 'opacity-70 hover:opacity-100'
              }`}
            >
              Kill Chain Stages
            </button>
            <button
              onClick={() => setViewMode('topology')}
              className={`px-2.5 py-1 rounded-md transition ${
                viewMode === 'topology'
                  ? 'bg-blue-600 text-white font-bold shadow'
                  : 'opacity-70 hover:opacity-100'
              }`}
            >
              Mesh Topology
            </button>
          </div>
        </div>

        <div className="text-[11px] font-mono opacity-60">
          {viewMode === 'packet-tracer'
            ? 'Interactive PDU Simulation & OSI Inspector'
            : `${nodes.length} Nodes &bull; ${edges.length} Traversals`}
        </div>
      </div>

      {/* ── 1. Cisco Packet Tracer Mode (Primary / Default) ─────────────────── */}
      {viewMode === 'packet-tracer' && (
        <PacketTracerSimulator onSelectEvent={onSelectEvent} activeSimulation={activeSimulation} theme={theme} />
      )}

      {/* ── 2. Linear Kill Chain Stages View ─────────────────────────────────── */}
      {viewMode === 'linear' && (
        <div className={`border rounded-xl p-5 space-y-5 ${
          isDark ? 'bg-[#0B0F17] border-[#1F293D]' : 'bg-slate-50 border-slate-200'
        }`}>
          <div className="flex items-center justify-between text-xs font-mono opacity-70 border-b border-inherit pb-2">
            <span className="font-bold flex items-center gap-1.5">
              <Activity className="w-3.5 h-3.5 text-blue-500" />
              Kill Chain Stage Progression (Straight Line)
            </span>
            <span className="text-[11px]">
              {activeStep !== null ? `Active Step ${activeStep + 1} of ${edges.length}` : 'All steps visible'}
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 relative">
            {[
              {
                stage: 'Stage 1',
                title: 'External C2 Server',
                sub: 'Initial Access & Staging',
                type: 'c2_server',
                nodes: nodes.filter(n => n.type === 'c2_server'),
              },
              {
                stage: 'Stage 2',
                title: 'Compromised Endpoint',
                sub: 'Weaponization & Defense Evasion',
                type: 'endpoint',
                nodes: nodes.filter(n => n.type === 'endpoint'),
              },
              {
                stage: 'Stage 3',
                title: 'Domain Infrastructure',
                sub: 'Lateral Movement & Pivot',
                type: 'server',
                nodes: nodes.filter(n => n.type === 'server'),
              },
              {
                stage: 'Stage 4',
                title: 'Cloud Target Enclave',
                sub: 'S3 Data Exfiltration',
                type: 'cloud_resource',
                nodes: nodes.filter(n => n.type === 'cloud_resource'),
              }
            ].map((col, cIdx) => (
              <div key={col.stage} className="space-y-3 relative">
                {cIdx < 3 && (
                  <div className="hidden md:flex absolute -right-3 top-14 z-20 items-center justify-center w-6 h-6 rounded-full bg-inherit border border-blue-500/40 text-blue-500">
                    <ArrowRight className="w-3.5 h-3.5" />
                  </div>
                )}

                <div className="flex items-center justify-between px-2">
                  <span className="text-[10px] font-mono font-bold opacity-60 uppercase tracking-widest">
                    {col.stage}
                  </span>
                  <span className="text-[10px] font-mono opacity-70">
                    {col.sub}
                  </span>
                </div>

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
                          <div className="p-2 rounded-lg bg-black/40 border border-inherit shrink-0">
                            {getNodeIcon(node.type)}
                          </div>
                          <div className="min-w-0">
                            <span className="text-xs font-bold block truncate">
                              {node.label}
                            </span>
                            <span className="text-[9px] font-mono uppercase opacity-70">
                              {node.type.replace('_', ' ')}
                            </span>
                          </div>
                        </div>

                        {node.users && node.users.length > 0 && (
                          <div className="text-[10px] font-mono text-amber-500 bg-black/30 px-2 py-1 rounded border border-inherit truncate">
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
        </div>
      )}

      {/* ── 3. Topology Mesh Canvas View ────────────────────────────────────── */}
      {viewMode === 'topology' && (
        <div className={`relative w-full h-[460px] rounded-xl border overflow-hidden select-none shadow-inner ${
          isDark ? 'bg-[#080D1A] border-[#1F293D]' : 'bg-[#F8FAFC] border-slate-200'
        }`}>
          <svg className="absolute inset-0 w-full h-full opacity-15 pointer-events-none">
            <defs>
              <pattern id="mesh-grid" width="40" height="40" patternUnits="userSpaceOnUse">
                <path d="M 40 0 L 0 0 0 40" fill="none" stroke="#3B82F6" strokeWidth="0.5" />
              </pattern>
            </defs>
            <rect width="100%" height="100%" fill="url(#mesh-grid)" />
          </svg>

          <svg className="absolute inset-0 w-full h-full pointer-events-none">
            <defs>
              <marker id="mesh-arr-default" markerWidth="8" markerHeight="8" refX="16" refY="4" orient="auto">
                <polygon points="0 0, 8 4, 0 8" fill="#475569" />
              </marker>
              <marker id="mesh-arr-active" markerWidth="10" markerHeight="10" refX="16" refY="5" orient="auto">
                <polygon points="0 0, 10 5, 0 10" fill="#EF4444" />
              </marker>
            </defs>

            {edges.map((edge, idx) => {
              const p1 = nodePositions[edge.source];
              const p2 = nodePositions[edge.target];
              if (!p1 || !p2) return null;

              const isSelected = selectedEventUuid === edge.event_uuid;
              const isStepActive = activeStep === idx;
              const pairIdx = edgePairIndexMap[edge.id] || 0;
              const curveOffset = pairIdx === 0 ? 0 : pairIdx % 2 === 1 ? pairIdx * 25 : -pairIdx * 25;
              const midX = (p1.x + p2.x) / 2;
              const midY = (p1.y + p2.y) / 2 + curveOffset;

              return (
                <path
                  key={edge.id}
                  d={`M ${p1.x} ${p1.y} Q ${midX} ${midY} ${p2.x} ${p2.y}`}
                  fill="none"
                  stroke={isSelected ? '#3B82F6' : isStepActive ? '#EF4444' : '#64748B'}
                  strokeWidth={isStepActive || isSelected ? 3.5 : 2}
                  markerEnd={isStepActive ? 'url(#mesh-arr-active)' : 'url(#mesh-arr-default)'}
                />
              );
            })}
          </svg>

          {nodes.map(node => {
            const pos = nodePositions[node.id];
            if (!pos) return null;
            return (
              <div
                key={node.id}
                style={{ left: `${pos.x}px`, top: `${pos.y}px`, transform: 'translate(-50%, -50%)' }}
                className="absolute z-10 p-3 rounded-xl border backdrop-blur-md shadow-xl flex flex-col items-center"
              >
                <div className="p-2 rounded-lg bg-black/40 mb-1">{getNodeIcon(node.type)}</div>
                <span className="text-[11px] font-bold font-mono truncate max-w-[120px]">{node.label}</span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
