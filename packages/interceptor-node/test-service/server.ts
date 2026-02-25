/**
 * Test service for demonstrating the broker interceptor.
 *
 * This service exposes a /chat endpoint that forwards messages to OpenAI's API.
 * When run with the interceptor preload, all requests to api.openai.com
 * will be intercepted and routed through the broker.
 *
 * Usage:
 *   # Without interception (direct to OpenAI)
 *   OPENAI_API_KEY=sk-... npx tsx test-service/server.ts
 *
 *   # With interception (through broker)
 *   OPENAI_API_KEY=sk-... \
 *   BROKER_URL=http://localhost:3001 \
 *   BROKER_SESSION_TOKEN=test-token \
 *   BROKER_MANIFEST_PATH=$(pwd)/test-service/manifest.json \
 *   BROKER_FAIL_ON_MANIFEST_ERROR=false \
 *   BROKER_LOG_LEVEL=debug \
 *   node --import ./dist/preload.js test-service/server.js
 */

import * as http from 'node:http';

const PORT = parseInt(process.env.PORT || '3000', 10);
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;

if (!OPENAI_API_KEY) {
  console.error('Error: OPENAI_API_KEY environment variable is required');
  process.exit(1);
}

interface ChatRequest {
  message: string;
}

interface OpenAIMessage {
  role: 'system' | 'user' | 'assistant';
  content: string;
}

interface OpenAIEmbeddingRequest {
  model: string;
  input: string;
  encoding_format?: string;
}

interface OpenAIEmbeddingResponse {
  data: {
    object: string;
    embedding: number[];
    index: number;
  };
  object: string;
  model: string;
  usage: {
    prompt_tokens: number;
    total_tokens: number;
  };
}

interface OpenAIRequest {
  model: string;
  messages: OpenAIMessage[];
  max_tokens?: number;
}

interface OpenAIResponse {
  id: string;
  object: string;
  created: number;
  model: string;
  choices: Array<{
    index: number;
    message: {
      role: string;
      content: string;
    };
    finish_reason: string;
  }>;
  usage: {
    prompt_tokens: number;
    completion_tokens: number;
    total_tokens: number;
  };
}

/**
 * Call OpenAI Chat Completions API using the cheapest model (gpt-4o-mini).
 */
async function callOpenAI(message: string): Promise<string> {
  const requestBody: OpenAIRequest = {
    model: 'gpt-4o-mini', // Cheapest capable model
    messages: [
      {
        role: 'system',
        content: 'You are a helpful assistant. Keep responses concise.'
      },
      {
        role: 'user',
        content: message
      }
    ],
    max_tokens: 150
  };

  console.log(`[server] Calling OpenAI API with message: "${message.substring(0, 50)}..."`);

  const response = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${OPENAI_API_KEY}`
    },
    body: JSON.stringify(requestBody)
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`OpenAI API error: ${response.status} ${response.statusText} - ${errorText}`);
  }

  const data = (await response.json()) as OpenAIResponse;

  if (!data.choices || data.choices.length === 0) {
    throw new Error('OpenAI returned no choices');
  }

  return data.choices[0].message.content;
}

async function callOpenAIEmbedding(message: string): Promise<number[]> {
  const requestBody: OpenAIEmbeddingRequest = {
    model: 'gpt-4o-mini', // Cheapest capable model
    encoding_format: 'float',
    input: message
  };

  const response = await fetch('https://api.openai.com/v1/embeddings', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${OPENAI_API_KEY}`
    },
    body: JSON.stringify(requestBody)
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`OpenAI API error: ${response.status} ${response.statusText} - ${errorText}`);
  }

  const data = (await response.json()) as OpenAIEmbeddingResponse;

  if (!data.data || data.data.embedding.length === 0) {
    throw new Error('OpenAI returned no embeddings');
  }

  return data.data.embedding;
}

/**
 * Parse JSON body from incoming request.
 */
function parseBody(req: http.IncomingMessage): Promise<ChatRequest> {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', (chunk: Buffer) => {
      body += chunk.toString();
    });
    req.on('end', () => {
      try {
        const parsed = JSON.parse(body) as ChatRequest;
        resolve(parsed);
      } catch {
        reject(new Error('Invalid JSON body'));
      }
    });
    req.on('error', reject);
  });
}

/**
 * Send JSON response.
 */
function sendJSON(res: http.ServerResponse, status: number, data: unknown): void {
  res.writeHead(status, {'Content-Type': 'application/json'});
  res.end(JSON.stringify(data));
}

/**
 * Request handler.
 */
async function handleRequest(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
  const {method, url} = req;

  console.log(`[server] ${method} ${url}`);

  // Health check endpoint
  if (method === 'GET' && url === '/health') {
    sendJSON(res, 200, {status: 'ok'});
    return;
  }

  if (method === 'POST' && url === '/embed') {
    const body = await parseBody(req);
    const response = await callOpenAIEmbedding(body.message);
    sendJSON(res, 200, {response});
  }

  // Chat endpoint
  if (method === 'POST' && url === '/chat') {
    try {
      const body = await parseBody(req);

      if (!body.message || typeof body.message !== 'string') {
        sendJSON(res, 400, {error: 'Missing or invalid "message" field'});
        return;
      }

      const response = await callOpenAI(body.message);
      sendJSON(res, 200, {response});
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.error(`[server] Error: ${message}`);

      // Check if it's an interceptor-specific error
      if (error && typeof error === 'object' && 'name' in error) {
        const err = error as {name: string; approvalId?: string; reason?: string};
        if (err.name === 'ApprovalRequiredError') {
          sendJSON(res, 202, {
            status: 'approval_required',
            approval_id: err.approvalId,
            message: 'Request requires approval before execution'
          });
          return;
        }
        if (err.name === 'RequestDeniedError') {
          sendJSON(res, 403, {
            status: 'denied',
            reason: err.reason,
            message: 'Request was denied by policy'
          });
          return;
        }
      }

      sendJSON(res, 500, {error: message});
    }
    return;
  }

  // 404 for other routes
  sendJSON(res, 404, {error: 'Not found'});
}

// Create and start server
const server = http.createServer((req, res) => {
  handleRequest(req, res).catch(err => {
    console.error('[server] Unhandled error:', err);
    sendJSON(res, 500, {error: 'Internal server error'});
  });
});

server.listen(PORT, () => {
  console.log(`[server] Test service listening on http://localhost:${PORT}`);
  console.log(`[server] Endpoints:`);
  console.log(`  POST /chat  - Send a message to OpenAI (body: { "message": "..." })`);
  console.log(`  GET  /health - Health check`);
  console.log('');
  console.log(`[server] Example:`);
  console.log(`  curl -X POST http://localhost:${PORT}/chat \\`);
  console.log(`    -H "Content-Type: application/json" \\`);
  console.log(`    -d '{"message": "Hello, how are you?"}'`);
});
