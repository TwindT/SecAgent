import type { ThemeConfig } from 'antd';

const theme: ThemeConfig = {
  token: {
    colorPrimary: '#5BA3FF',
    colorBgContainer: '#FFFFFF',
    colorBgLayout: 'transparent',
    borderRadius: 12,
    fontFamily:
      "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'PingFang SC', 'Microsoft YaHei', sans-serif",
    fontSize: 14,
  },
  components: {
    Button: {
      primaryShadow: '0 8px 32px rgba(91,163,255,0.25)',
      borderRadius: 12,
    },
    Card: {
      borderRadiusLG: 16,
      boxShadowTertiary: '0 1px 3px rgba(0,0,0,0.04)',
    },
  },
};

export default theme;
