export type ChatRole = 'system' | 'user' | 'assistant' | (string & {});

export interface ChatMessage {
  role: ChatRole;
  content: string;
}

export const ChatMessage = {
  system: (content: string): ChatMessage => ({ role: 'system', content }),
  user: (content: string): ChatMessage => ({ role: 'user', content }),
  assistant: (content: string): ChatMessage => ({ role: 'assistant', content }),
};

export interface ChatCompletionsRequest {
  model: string;
  messages: ChatMessage[];
  temperature?: number;
  max_tokens?: number;
  stream?: boolean;
  /** Extra OpenAI-compatible fields forwarded to the upstream provider. */
  [key: string]: unknown;
}

export interface Usage {
  prompt_tokens?: number;
  completion_tokens?: number;
  total_tokens?: number;
  [key: string]: unknown;
}

export interface ChatChoice {
  index: number;
  message?: ChatMessage;
  finish_reason?: string;
  [key: string]: unknown;
}

export interface ChatCompletionsResponse {
  id?: string;
  model?: string;
  choices: ChatChoice[];
  usage?: Usage;
  [key: string]: unknown;
}

export function firstText(resp: ChatCompletionsResponse): string | undefined {
  for (const c of resp.choices || []) {
    if (c?.message?.content) return String(c.message.content);
  }
  return undefined;
}
