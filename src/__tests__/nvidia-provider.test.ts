/**
 * Nvidia Build API provider — OpenAI-compatible wiring.
 * Nvidia's NIM inference endpoint (https://integrate.api.nvidia.com/v1) uses the
 * OpenAI wire protocol, so NvidiaAdapter reuses the OpenRouter adapter with Nvidia's
 * base URL. This pins that the provider resolves end-to-end so a refactor can't
 * silently drop it.
 */
import { describe, it, expect, afterEach } from 'vitest';
import { config, AVAILABLE_MODELS } from '../config/index.js';
import { createNvidiaBackbone } from '../llm/index.js';

const KEY = 'nvapi-abcdef123456789abcdef123456';

describe('Nvidia Build API provider wiring', () => {
  afterEach(() => { delete process.env.NVIDIA_API_KEY; });

  it('resolves the Nvidia base URL + default model + key from NVIDIA_API_KEY', () => {
    process.env.NVIDIA_API_KEY = KEY;
    const cfg = config.getLLMConfig('nvidia');
    expect(cfg.provider).toBe('nvidia');
    expect(cfg.baseUrl).toBe('https://integrate.api.nvidia.com/v1');
    expect(cfg.model).toBe('nvidia/llama-3.1-nemotron-ultra-253b-v1');
    expect(cfg.apiKey).toBe(KEY);
  });

  it('the Nvidia backbone validates and reports the nvidia provider', () => {
    process.env.NVIDIA_API_KEY = KEY;
    const bb = createNvidiaBackbone();
    expect(bb.getProvider()).toBe('nvidia');
    expect(bb.validateConfig().valid).toBe(true);
  });

  it('surfaces nvidia in AVAILABLE_MODELS and getConfiguredProviders', () => {
    process.env.NVIDIA_API_KEY = KEY;
    expect(AVAILABLE_MODELS.nvidia?.length).toBeGreaterThan(0);
    expect(config.getConfiguredProviders()).toContain('nvidia');
  });

  it('validateConfig fails when no key is set', () => {
    const bb = createNvidiaBackbone();
    const result = bb.validateConfig();
    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/Nvidia API key/i);
  });

  it('accepts a custom model override', () => {
    process.env.NVIDIA_API_KEY = KEY;
    const bb = createNvidiaBackbone(undefined, 'meta/llama-3.3-70b-instruct');
    expect(bb.getModel()).toBe('meta/llama-3.3-70b-instruct');
  });
});
