import { useState, useEffect } from 'react';
import { Layout, Typography, Button, Card, Space, Spin, Alert } from 'antd';
import { ShieldOutlined, CheckCircleOutlined, ServerOutlined } from '@ant-design/icons';
import axios from 'axios';

const { Header, Content, Footer } = Layout;
const { Title, Paragraph } = Typography;

interface Task {
  task_id: string;
  status: string;
}

function App() {
  const [tasks, setTasks] = useState<Task[]>([]);
  const [loading, setLoading] = useState(false);
  const [apiStatus, setApiStatus] = useState<'loading' | 'success' | 'error'>('loading');

  const fetchTasks = async () => {
    setLoading(true);
    try {
      const response = await axios.post('/api/tasks');
      setTasks(prev => [...prev, response.data]);
      setApiStatus('success');
    } catch (error) {
      console.error('Failed to create task:', error);
      setApiStatus('error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTasks();
  }, []);

  return (
    <Layout className="min-h-screen">
      <Header style={{ background: '#1a1a2e', padding: '0 24px' }}>
        <div className="flex items-center justify-between h-full">
          <div className="flex items-center gap-3">
            <ShieldOutlined style={{ fontSize: '28px', color: '#10b981' }} />
            <Title level={3} style={{ color: '#fff', margin: 0 }}>
              SecAgent
            </Title>
          </div>
          <div className="flex items-center gap-2">
            <ServerOutlined style={{ color: apiStatus === 'success' ? '#10b981' : '#ef4444' }} />
            <span className={`text-sm ${apiStatus === 'success' ? 'text-green-400' : 'text-red-400'}`}>
              {apiStatus === 'loading' ? '连接中...' : apiStatus === 'success' ? '已连接' : '连接失败'}
            </span>
          </div>
        </div>
      </Header>

      <Content style={{ padding: '40px 24px', background: '#0f0f1a' }}>
        <div className="max-w-4xl mx-auto">
          <div className="text-center mb-8">
            <Title level={1} style={{ color: '#fff', marginBottom: '16px' }}>
              安全智能分析平台
            </Title>
            <Paragraph style={{ color: '#9ca3af', fontSize: '16px' }}>
              基于大语言模型的代码漏洞检测与恶意代码分析系统
            </Paragraph>
          </div>

          <Space className="w-full justify-center mb-8" size="large">
            <Button
              type="primary"
              size="large"
              icon={<ShieldOutlined />}
              style={{ padding: '12px 32px', fontSize: '16px' }}
            >
              代码漏洞检测
            </Button>
            <Button
              type="default"
              size="large"
              style={{ padding: '12px 32px', fontSize: '16px' }}
            >
              恶意代码分析
            </Button>
          </Space>

          <Card
            title="系统状态"
            style={{ background: '#1a1a2e', borderColor: '#374151' }}
            headStyle={{ color: '#fff', borderBottomColor: '#374151' }}
          >
            <div className="grid grid-cols-3 gap-4">
              <Card
                size="small"
                style={{ background: '#16213e', borderColor: '#374151' }}
              >
                <div className="flex items-center gap-2">
                  <CheckCircleOutlined style={{ color: '#10b981' }} />
                  <span className="text-gray-300">API 状态</span>
                </div>
                <div className={`text-xl font-bold mt-2 ${apiStatus === 'success' ? 'text-green-400' : 'text-red-400'}`}>
                  {apiStatus === 'loading' ? '检测中' : apiStatus === 'success' ? '正常' : '异常'}
                </div>
              </Card>
              <Card
                size="small"
                style={{ background: '#16213e', borderColor: '#374151' }}
              >
                <div className="flex items-center gap-2">
                  <ServerOutlined style={{ color: '#3b82f6' }} />
                  <span className="text-gray-300">任务数量</span>
                </div>
                <div className="text-xl font-bold mt-2 text-blue-400">
                  {tasks.length}
                </div>
              </Card>
              <Card
                size="small"
                style={{ background: '#16213e', borderColor: '#374151' }}
              >
                <div className="flex items-center gap-2">
                  <ShieldOutlined style={{ color: '#f59e0b' }} />
                  <span className="text-gray-300">安全级别</span>
                </div>
                <div className="text-xl font-bold mt-2 text-yellow-400">
                  高
                </div>
              </Card>
            </div>
          </Card>

          <Card
            title="最近任务"
            style={{ background: '#1a1a2e', borderColor: '#374151', marginTop: '16px' }}
            headStyle={{ color: '#fff', borderBottomColor: '#374151' }}
          >
            {loading ? (
              <div className="flex justify-center py-8">
                <Spin size="large" />
              </div>
            ) : tasks.length > 0 ? (
              <div className="space-y-3">
                {tasks.map((task, index) => (
                  <div
                    key={task.task_id}
                    className="flex items-center justify-between p-3 rounded-lg"
                    style={{ background: '#16213e' }}
                  >
                    <div className="flex items-center gap-3">
                      <span className="text-gray-400">#{index + 1}</span>
                      <span className="text-gray-300">{task.task_id}</span>
                    </div>
                    <span
                      className={`px-3 py-1 rounded-full text-sm ${
                        task.status === 'pending'
                          ? 'bg-yellow-500/20 text-yellow-400'
                          : task.status === 'completed'
                          ? 'bg-green-500/20 text-green-400'
                          : 'bg-gray-500/20 text-gray-400'
                      }`}
                    >
                      {task.status === 'pending' ? '待处理' : task.status === 'completed' ? '已完成' : task.status}
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <Alert
                message="暂无任务"
                description="点击下方按钮创建新任务"
                type="info"
                showIcon
                style={{ background: '#16213e', borderColor: '#374151' }}
              />
            )}
            <div className="mt-4 flex justify-end">
              <Button onClick={fetchTasks} loading={loading}>
                创建新任务
              </Button>
            </div>
          </Card>
        </div>
      </Content>

      <Footer style={{ background: '#1a1a2e', color: '#9ca3af', textAlign: 'center' }}>
        SecAgent - 安全智能分析平台 ©2026
      </Footer>
    </Layout>
  );
}

export default App;
