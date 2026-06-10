import { Typography } from 'antd';

function Footer() {
  return (
    <footer
      style={{
        borderTop: '1px solid var(--border-light)',
        padding: 16,
        textAlign: 'center',
      }}
    >
      <Typography.Text style={{ color: 'var(--text-muted)', fontSize: 13 }}>
        SecAgent - 智能安全分析平台 ©2026
      </Typography.Text>
    </footer>
  );
}

export default Footer;
