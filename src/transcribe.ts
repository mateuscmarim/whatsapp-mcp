/**
 * Voice note transcription through Google's Gemini API (the Interactions endpoint). Only runs when an agent
 * asks for it, and only when the operator set GEMINI_API_KEY. The audio leaves this server for Google.
 */

const ENDPOINT = 'https://generativelanguage.googleapis.com/v1beta/interactions';
const API_REVISION = '2026-05-20';
export const DEFAULT_GEMINI_MODEL = 'gemini-3.8-flash-lite';
/** Inline requests are capped at 20 MB in all; base64 grows the audio by a third. */
export const MAX_AUDIO_BYTES = 14 * 1024 * 1024;

const PROMPT =
  'Transcribe this WhatsApp voice message word for word, in the language it is spoken in. ' +
  'Reply with the transcript only: no preamble, no timestamps, no speaker labels, no translation. ' +
  'If there is no speech, reply exactly: [no speech]';

/** Gemini accepts the container type, not codec parameters ("audio/ogg; codecs=opus" -> "audio/ogg"). */
const baseMime = (mime: string) => mime.split(';')[0].trim().toLowerCase() || 'audio/ogg';

export async function transcribe(audio: { data: string; mime: string }, opts: { apiKey: string; model?: string }): Promise<string> {
  const res = await fetch(ENDPOINT, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-goog-api-key': opts.apiKey, 'Api-Revision': API_REVISION },
    body: JSON.stringify({
      model: opts.model || DEFAULT_GEMINI_MODEL,
      store: false, // don't keep the conversation on Google's side
      input: [
        { type: 'text', text: PROMPT },
        { type: 'audio', data: audio.data, mime_type: baseMime(audio.mime) },
      ],
    }),
  });
  const body: any = await res.json().catch(() => null);
  if (!res.ok) throw new Error(`Gemini ${res.status}: ${body?.error?.message ?? res.statusText}`);
  const text = outputText(body);
  if (!text) throw new Error('Gemini returned no text');
  return text;
}

/**
 * The model's text from an Interaction: the text blocks of its output steps, joined. Steps that echo the
 * input or carry thoughts are skipped.
 */
export function outputText(interaction: any): string {
  if (typeof interaction?.output_text === 'string') return interaction.output_text.trim();
  const parts: string[] = [];
  const collect = (node: any) => {
    if (!node || typeof node !== 'object') return;
    if (Array.isArray(node)) return node.forEach(collect);
    if (node.type === 'user_input' || node.type === 'thought' || node.type === 'thinking') return;
    if (node.type === 'text' && typeof node.text === 'string') parts.push(node.text);
    for (const k of ['steps', 'outputs', 'content', 'parts']) collect(node[k]);
  };
  collect(interaction?.steps ?? interaction?.outputs);
  return parts.join('').trim();
}
