import React, { useEffect, useRef } from 'react';

export default function GlobeVisualization({ width = 420, height = 420, events = [], theme = 'light' }) {
  const canvasRef = useRef(null);
  const frameRef = useRef(null);
  const angleRef = useRef(0);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const W = canvas.width;
    const H = canvas.height;
    const cx = W / 2;
    const cy = H / 2 + 10;
    const R = Math.min(W, H) / 2 - 30;

    const ATTACK_NODES = [
      { lat: 55.7, lon: 37.6,  color: '#FF1493', size: 5, pulse: true,  label: null },
      { lat: 39.9, lon: 116.4, color: '#FF1493', size: 5, pulse: true,  label: null },
      { lat: 1.3,  lon: 103.8, color: '#FF69B4', size: 4, pulse: true,  label: null },
      { lat: 51.5, lon: -0.1,  color: '#00D4FF', size: 4, pulse: false, label: null },
      { lat: 48.8, lon: 2.3,   color: '#00D4FF', size: 3, pulse: false, label: null },
      { lat: 40.7, lon: -74.0, color: '#10B981', size: 6, pulse: true,  label: 'Exfil Target\n41,790,001' },
      { lat: 37.8, lon: -122.4,color: '#7C3AED', size: 4, pulse: true,  label: null },
      { lat: -33.9,lon: 18.4,  color: '#F59E0B', size: 3, pulse: false, label: null },
      { lat: 35.7, lon: 139.7, color: '#00D4FF', size: 4, pulse: true,  label: null },
      { lat: 55.9, lon: 23.3,  color: '#FF1493', size: 3, pulse: true,  label: null },
    ];

    const CONNECTIONS = [
      [0, 5], [1, 5], [2, 6], [3, 5], [9, 0],
    ];

    const toScreen = (lat, lon, rot) => {
      const phi = (90 - lat) * Math.PI / 180;
      const theta = (lon + rot) * Math.PI / 180;
      const x3 = R * Math.sin(phi) * Math.cos(theta);
      const y3 = R * Math.cos(phi);
      const z3 = R * Math.sin(phi) * Math.sin(theta);
      return { x: cx + x3, y: cy - y3, z: z3 };
    };

    const drawLatLine = (lat, rot, alpha) => {
      const phi = (90 - lat) * Math.PI / 180;
      const cosP = Math.cos(phi);
      const sinP = Math.sin(phi);
      const ry = cy - R * cosP;
      const rx = R * sinP;
      ctx.beginPath();
      ctx.ellipse(cx, ry, rx, rx * 0.28, 0, 0, Math.PI * 2);
      ctx.strokeStyle = `rgba(140, 100, 220, ${alpha})`;
      ctx.lineWidth = 0.5;
      ctx.stroke();
    };

    const drawLonLine = (lonBase, rot, alpha) => {
      const theta = (lonBase + rot) * Math.PI / 180;
      const theta2 = (lonBase + rot + 180) * Math.PI / 180;
      [theta, theta2].forEach(t => {
        ctx.beginPath();
        for (let la = -88; la <= 88; la += 3) {
          const phi = (90 - la) * Math.PI / 180;
          const x = cx + R * Math.sin(phi) * Math.cos(t);
          const y = cy - R * Math.cos(phi);
          if (la === -88) ctx.moveTo(x, y); else ctx.lineTo(x, y);
        }
        ctx.strokeStyle = `rgba(140, 100, 220, ${alpha})`;
        ctx.lineWidth = 0.5;
        ctx.stroke();
      });
    };

    const drawFrame = () => {
      ctx.clearRect(0, 0, W, H);
      const rot = angleRef.current;
      const time = Date.now() / 1000;
      const isDark = theme === 'dark' || document.documentElement.classList.contains('dark');

      // Outer atmosphere glow
      const atmo = ctx.createRadialGradient(cx, cy, R * 0.8, cx, cy, R * 1.35);
      if (isDark) {
        atmo.addColorStop(0, 'rgba(100, 40, 200, 0)');
        atmo.addColorStop(0.6, 'rgba(80, 30, 160, 0.06)');
        atmo.addColorStop(0.85, 'rgba(0, 212, 255, 0.05)');
        atmo.addColorStop(1, 'transparent');
      } else {
        atmo.addColorStop(0, 'rgba(99, 102, 241, 0.03)');
        atmo.addColorStop(0.6, 'rgba(147, 51, 234, 0.08)');
        atmo.addColorStop(0.85, 'rgba(6, 182, 212, 0.08)');
        atmo.addColorStop(1, 'transparent');
      }
      ctx.fillStyle = atmo;
      ctx.beginPath();
      ctx.arc(cx, cy, R * 1.35, 0, Math.PI * 2);
      ctx.fill();

      // Globe base
      const globeGrad = ctx.createRadialGradient(cx - R * 0.25, cy - R * 0.25, 0, cx, cy, R);
      if (isDark) {
        globeGrad.addColorStop(0, 'rgba(35, 15, 80, 0.98)');
        globeGrad.addColorStop(0.6, 'rgba(15, 8, 45, 0.98)');
        globeGrad.addColorStop(1, 'rgba(5, 3, 20, 0.98)');
      } else {
        globeGrad.addColorStop(0, 'rgba(30, 27, 75, 0.96)');
        globeGrad.addColorStop(0.5, 'rgba(15, 23, 42, 0.98)');
        globeGrad.addColorStop(1, 'rgba(2, 6, 23, 0.99)');
      }
      ctx.fillStyle = globeGrad;
      ctx.beginPath();
      ctx.arc(cx, cy, R, 0, Math.PI * 2);
      ctx.fill();

      // Outer globe border ring
      ctx.beginPath();
      ctx.arc(cx, cy, R, 0, Math.PI * 2);
      ctx.strokeStyle = isDark ? 'rgba(139, 92, 246, 0.5)' : 'rgba(99, 102, 241, 0.7)';
      ctx.lineWidth = 1.5;
      ctx.stroke();

      // Grid lines
      [-60, -30, 0, 30, 60].forEach(lat => {
        drawLatLine(lat, rot, isDark ? 0.18 : 0.25);
      });
      [0, 45, 90, 135].forEach(lon => {
        drawLonLine(lon, rot, isDark ? 0.14 : 0.22);
      });

      // Map nodes to screen coordinates
      const mapped = ATTACK_NODES.map((n, i) => ({
        ...n,
        pos: toScreen(n.lat, n.lon, rot),
        i
      }));

      // Draw connection arcs
      CONNECTIONS.forEach(([srcIdx, dstIdx]) => {
        const s = mapped[srcIdx];
        const d = mapped[dstIdx];
        if (!s || !d) return;
        if (s.pos.z < -R * 0.3 && d.pos.z < -R * 0.3) return;

        const mx = (s.pos.x + d.pos.x) / 2;
        const my = (s.pos.y + d.pos.y) / 2;
        const dist = Math.hypot(d.pos.x - s.pos.x, d.pos.y - s.pos.y);
        const arcHeight = Math.min(dist * 0.35, 65);
        const cpx = mx;
        const cpy = my - arcHeight;

        ctx.beginPath();
        ctx.moveTo(s.pos.x, s.pos.y);
        ctx.quadraticCurveTo(cpx, cpy, d.pos.x, d.pos.y);

        const arcGrad = ctx.createLinearGradient(s.pos.x, s.pos.y, d.pos.x, d.pos.y);
        arcGrad.addColorStop(0, 'rgba(255, 20, 147, 0.85)');
        arcGrad.addColorStop(0.5, 'rgba(0, 212, 255, 0.9)');
        arcGrad.addColorStop(1, 'rgba(16, 185, 129, 0.85)');
        ctx.strokeStyle = arcGrad;
        ctx.lineWidth = 1.6;
        ctx.setLineDash([3, 5]);
        ctx.stroke();
        ctx.setLineDash([]);
      });

      // Nodes
      mapped.forEach(n => {
        if (n.pos.z < -R * 0.4) return;
        const { x, y, z } = n.pos;
        const visibility = Math.max(0, (z + R) / (2 * R));
        const alpha = 0.4 + visibility * 0.6;

        // Pulse rings
        if (n.pulse) {
          const pr = n.size + 4 + Math.sin(time * 2.5 + n.i) * 3;
          const pulseGrad = ctx.createRadialGradient(x, y, 0, x, y, pr * 2.5);
          pulseGrad.addColorStop(0, n.color + Math.round(alpha * 100).toString(16).padStart(2, '0'));
          pulseGrad.addColorStop(0.4, n.color + '30');
          pulseGrad.addColorStop(1, 'transparent');
          ctx.fillStyle = pulseGrad;
          ctx.beginPath();
          ctx.arc(x, y, pr * 2.5, 0, Math.PI * 2);
          ctx.fill();
        }

        // Core glow
        const coreGlow = ctx.createRadialGradient(x, y, 0, x, y, n.size * 3);
        coreGlow.addColorStop(0, n.color);
        coreGlow.addColorStop(0.4, n.color + '80');
        coreGlow.addColorStop(1, 'transparent');
        ctx.fillStyle = coreGlow;
        ctx.beginPath();
        ctx.arc(x, y, n.size * 3, 0, Math.PI * 2);
        ctx.fill();

        // Core dot
        ctx.fillStyle = n.color;
        ctx.beginPath();
        ctx.arc(x, y, n.size, 0, Math.PI * 2);
        ctx.fill();
      });

      // Labels - with contrast pills on light theme
      ctx.textAlign = 'center';

      // Malicious Ingress - top right
      ctx.fillStyle = isDark ? 'rgba(200, 180, 255, 0.85)' : '#475569';
      ctx.font = 'bold 9px monospace';
      ctx.fillText('Malicious Ingress', cx + R * 0.52, cy - R * 0.62);
      ctx.fillStyle = '#FF1493';
      ctx.font = 'bold 11px monospace';
      ctx.fillText('12,320,300', cx + R * 0.52, cy - R * 0.62 + 15);

      // Exfil Target - bottom right
      ctx.fillStyle = isDark ? 'rgba(200, 180, 255, 0.85)' : '#475569';
      ctx.font = 'bold 9px monospace';
      ctx.textAlign = 'right';
      ctx.fillText('Exfil Target', cx + R * 0.95, cy + R * 0.72);
      ctx.fillStyle = '#10B981';
      ctx.font = 'bold 11px monospace';
      ctx.fillText('41,790,001', cx + R * 0.95, cy + R * 0.72 + 15);

      angleRef.current += 0.12;
      frameRef.current = requestAnimationFrame(drawFrame);
    };

    drawFrame();
    return () => { if (frameRef.current) cancelAnimationFrame(frameRef.current); };
  }, [theme]);

  const isDark = theme === 'dark';

  return (
    <canvas
      ref={canvasRef}
      width={width}
      height={height}
      className="max-w-full"
      style={{
        filter: isDark
          ? 'drop-shadow(0 0 25px rgba(124, 58, 237, 0.4))'
          : 'drop-shadow(0 8px 24px rgba(99, 102, 241, 0.2))'
      }}
    />
  );
}
