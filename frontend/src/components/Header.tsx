import { Typography } from 'antd';
import Logo from './Logo';

function Header() {
  return (
    <header
      className="glass glass-border-bottom"
      style={{
        position: 'sticky',
        top: 0,
        zIndex: 100,
        height: 56,
        padding: '0 24px',
        display: 'flex',
        alignItems: 'center',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <Logo size={32} />
        <Typography.Text
          className="gradient-text"
          style={{ fontSize: 16, fontWeight: 600 }}
        >
          SecAgent
        </Typography.Text>
      </div>
    </header>
  );
}

export default Header;
