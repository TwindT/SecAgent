import { useNavigate } from 'react-router-dom';
import { Code2, Bug, ArrowRight, BarChart3, Shield, Zap } from 'lucide-react';
import Logo from './Logo';

function Hero() {
  const navigate = useNavigate();

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        flex: 1,
        padding: '0 24px',
      }}
    >
      {/* Logo */}
      <div className="animate-slide-up">
        <div style={{ margin: '0 auto 32px' }}>
          <Logo size={96} />
        </div>
      </div>

      {/* Title */}
      <div className="animate-slide-up" style={{ animationDelay: '60ms' }}>
        <h1
          className="gradient-text"
          style={{ fontSize: 42, fontWeight: 700, textAlign: 'center', marginBottom: 16 }}
        >
          SecAgent
        </h1>
      </div>

      {/* Subtitle */}
      <div className="animate-slide-up" style={{ animationDelay: '120ms' }}>
        <p
          style={{
            fontSize: 16,
            color: 'var(--text-secondary)',
            textAlign: 'center',
            maxWidth: 440,
            marginBottom: 40,
            lineHeight: 1.6,
          }}
        >
          基于大语言模型的智能安全分析平台，自动化代码漏洞检测与恶意代码分析
        </p>
      </div>

      {/* CTA Buttons */}
      <div
        className="animate-slide-up"
        style={{ animationDelay: '180ms', display: 'flex', gap: 16 }}
      >
        <button
          onClick={() => navigate('/submit?tab=code')}
          className="gradient-bg btn-press"
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 10,
            borderRadius: 14,
            padding: '14px 28px',
            fontSize: 15,
            fontWeight: 600,
            color: 'white',
            border: 'none',
            cursor: 'pointer',
            boxShadow: 'var(--shadow-brand)',
            transition: 'opacity 0.15s',
          }}
          onMouseEnter={(e) => { e.currentTarget.style.opacity = '0.9' }}
          onMouseLeave={(e) => { e.currentTarget.style.opacity = '1' }}
        >
          <Code2 size={18} />
          开始代码扫描
          <ArrowRight size={16} />
        </button>
        <button
          onClick={() => navigate('/submit?tab=malware')}
          className="btn-press"
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 10,
            borderRadius: 14,
            padding: '14px 28px',
            fontSize: 15,
            fontWeight: 600,
            color: 'var(--accent-start)',
            background: 'transparent',
            border: '1px solid var(--border-focus)',
            cursor: 'pointer',
            transition: 'background 0.15s',
          }}
          onMouseEnter={(e) => { e.currentTarget.style.background = 'rgba(91,163,255,0.06)' }}
          onMouseLeave={(e) => { e.currentTarget.style.background = 'transparent' }}
        >
          <Bug size={18} />
          上传恶意分析
        </button>
      </div>

      {/* Feature Cards */}
      <div
        className="animate-slide-up"
        style={{
          animationDelay: '280ms',
          display: 'grid',
          gridTemplateColumns: 'repeat(3, 1fr)',
          gap: 20,
          marginTop: 64,
          maxWidth: 720,
          width: '100%',
        }}
      >
        {[
          {
            icon: Shield,
            title: '智能分析',
            desc: 'AI Agent 自主调用工具链，深度推理安全风险',
            color: '#5BA3FF',
            bgColor: 'rgba(91,163,255,0.08)',
          },
          {
            icon: Zap,
            title: '实时反馈',
            desc: 'WebSocket 推送思考链，实时追踪分析过程',
            color: '#5EEAD4',
            bgColor: 'rgba(94,234,212,0.08)',
          },
          {
            icon: BarChart3,
            title: '专业报告',
            desc: 'CWE/ATT&CK 映射，可视化安全报告一键导出',
            color: '#F59E0B',
            bgColor: 'rgba(245,158,11,0.08)',
          },
        ].map((feature) => {
          const Icon = feature.icon;
          return (
            <div
              key={feature.title}
              style={{
                borderRadius: 16,
                border: '1px solid var(--border-light)',
                background: 'var(--bg-card)',
                padding: 24,
                textAlign: 'center',
                boxShadow: 'var(--shadow-sm)',
                transition: 'all 0.2s',
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.transform = 'translateY(-2px)';
                e.currentTarget.style.boxShadow = 'var(--shadow-md)';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.transform = 'translateY(0)';
                e.currentTarget.style.boxShadow = 'var(--shadow-sm)';
              }}
            >
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  borderRadius: 12,
                  width: 44,
                  height: 44,
                  background: feature.bgColor,
                  margin: '0 auto 12px',
                }}
              >
                <Icon size={22} style={{ color: feature.color }} />
              </div>
              <div style={{ fontWeight: 600, fontSize: 15, color: 'var(--text-primary)', marginBottom: 6 }}>
                {feature.title}
              </div>
              <div style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                {feature.desc}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

export default Hero;
