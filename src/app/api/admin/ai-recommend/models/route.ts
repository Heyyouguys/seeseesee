import { NextRequest, NextResponse } from 'next/server';

// 获取可用模型列表
export async function POST(request: NextRequest) {
  try {
    const { apiUrl, apiKey } = await request.json();

    if (!apiUrl || !apiKey) {
      return NextResponse.json(
        { error: '请提供API地址和API密钥' },
        { status: 400 }
      );
    }

    // 构建模型列表API URL
    let modelsUrl = apiUrl.trim();

    // 移除末尾斜杠
    if (modelsUrl.endsWith('/')) {
      modelsUrl = modelsUrl.slice(0, -1);
    }

    // 如果URL以/v1结尾，添加/models
    if (modelsUrl.endsWith('/v1')) {
      modelsUrl = modelsUrl + '/models';
    } else if (modelsUrl.endsWith('/v4')) {
      // 智谱AI使用v4
      modelsUrl = modelsUrl + '/models';
    } else if (!modelsUrl.includes('/models')) {
      // 尝试添加/v1/models
      modelsUrl = modelsUrl + '/v1/models';
    }

    console.log('[AI Models] 获取模型列表:', modelsUrl);

    const response = await fetch(modelsUrl, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error('[AI Models] API错误:', response.status, errorText);
      return NextResponse.json(
        { error: `获取模型列表失败: HTTP ${response.status}` },
        { status: response.status }
      );
    }

    const data = await response.json();

    // OpenAI格式的响应: { data: [{ id: 'gpt-4', ... }, ...] }
    // 有些API可能直接返回数组
    let models: string[] = [];

    if (Array.isArray(data)) {
      models = data.map((m: { id?: string; name?: string }) => m.id || m.name).filter(Boolean);
    } else if (data.data && Array.isArray(data.data)) {
      models = data.data.map((m: { id?: string; name?: string }) => m.id || m.name).filter(Boolean);
    } else if (data.models && Array.isArray(data.models)) {
      models = data.models.map((m: { id?: string; name?: string }) => m.id || m.name).filter(Boolean);
    }

    // 按名称排序
    models.sort((a, b) => a.localeCompare(b));

    console.log('[AI Models] 获取到', models.length, '个模型');

    return NextResponse.json({ models });
  } catch (error) {
    console.error('[AI Models] 获取模型列表错误:', error);
    return NextResponse.json(
      { error: error instanceof Error ? error.message : '获取模型列表失败' },
      { status: 500 }
    );
  }
}