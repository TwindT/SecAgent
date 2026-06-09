import { Layout, Typography } from 'antd';

const { Header, Content, Footer } = Layout;
const { Title } = Typography;

function App() {
  return (
    <Layout className="min-h-screen" style={{ background: '#fefefe' }}>
      <Header 
        style={{ 
          background: 'rgba(255, 255, 255, 0.8)',
          backdropFilter: 'blur(20px)',
          padding: '16px 32px',
          borderBottom: '1px solid rgba(148, 163, 184, 0.1)',
          position: 'sticky',
          top: 0,
          zIndex: 100
        }}
      >
        <div className="flex items-center gap-3">
          <div 
            className="w-8 h-8 rounded-xl flex items-center justify-center"
            style={{
              background: 'linear-gradient(135deg, #5ba3ff 0%, #5eead4 100%)',
            }}
          >
            <span style={{ color: 'white', fontWeight: 'bold', fontSize: '14px' }}>S</span>
          </div>
          <Title 
            level={3} 
            style={{ 
              margin: 0, 
              fontSize: '16px',
              fontWeight: 600,
              background: 'linear-gradient(135deg, #5ba3ff 0%, #5eead4 100%)',
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent',
              backgroundClip: 'text'
            }}
          >
            SecAgent
          </Title>
        </div>
      </Header>

      <Content style={{ padding: '80px 24px', display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: 'calc(100vh - 120px)' }}>
        <div className="text-center">
          <div 
            className="w-24 h-24 mx-auto mb-8 rounded-3xl flex items-center justify-center"
            style={{
              background: 'linear-gradient(135deg, #5ba3ff 0%, #5eead4 100%)',
              boxShadow: '0 12px 40px rgba(91, 163, 255, 0.25)',
              transition: 'transform 0.3s ease, box-shadow 0.3s ease'
            }}
          >
            <Title 
              level={1} 
              style={{ 
                margin: 0, 
                fontSize: '48px',
                fontWeight: 700,
                color: 'white'
              }}
            >
              S
            </Title>
          </div>
          <Title 
            level={1} 
            style={{ 
              fontSize: '42px',
              fontWeight: 700,
              marginBottom: '16px'
            }}
          >
            <span className="gradient-text">SecAgent</span>
          </Title>
          <Typography.Paragraph style={{ fontSize: '16px', color: '#64748b', maxWidth: '400px', margin: '0 auto' }}>
            基于大语言模型的智能安全分析平台
          </Typography.Paragraph>
        </div>
      </Content>

      <Footer 
        style={{ 
          background: 'rgba(255, 255, 255, 0.6)',
          backdropFilter: 'blur(10px)',
          borderTop: '1px solid rgba(148, 163, 184, 0.08)',
          padding: '16px',
          textAlign: 'center'
        }}
      >
        <Typography.Text style={{ color: '#94a3b8', fontSize: '13px' }}>
          SecAgent - 智能安全分析平台 ©2026
        </Typography.Text>
      </Footer>
    </Layout>
  );
}

export default App;
