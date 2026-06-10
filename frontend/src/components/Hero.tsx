import { Button, Typography } from 'antd';
import { CodeOutlined, SecurityScanOutlined } from '@ant-design/icons';
import Logo from './Logo';

function Hero() {
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
      <div className="animate-slide-up">
        <div style={{ margin: '0 auto 32px' }}>
          <Logo size={96} />
        </div>
      </div>

      <div className="animate-slide-up" style={{ animationDelay: '60ms' }}>
        <Typography.Title
          level={1}
          className="gradient-text"
          style={{ fontSize: 42, fontWeight: 700, textAlign: 'center', marginBottom: 16 }}
        >
          SecAgent
        </Typography.Title>
      </div>

      <div className="animate-slide-up" style={{ animationDelay: '120ms' }}>
        <Typography.Paragraph
          style={{
            fontSize: 16,
            color: 'var(--text-secondary)',
            textAlign: 'center',
            maxWidth: 400,
            marginBottom: 40,
          }}
        >
          基于大语言模型的智能安全分析平台
        </Typography.Paragraph>
      </div>

      <div
        className="animate-slide-up"
        style={{ animationDelay: '180ms', display: 'flex', gap: 16 }}
      >
        <Button
          type="primary"
          size="large"
          icon={<CodeOutlined />}
          className="btn-gradient"
        >
          开始代码扫描
        </Button>
        <Button
          size="large"
          icon={<SecurityScanOutlined />}
          className="btn-outlined-accent"
        >
          上传恶意分析
        </Button>
      </div>
    </div>
  );
}

export default Hero;
