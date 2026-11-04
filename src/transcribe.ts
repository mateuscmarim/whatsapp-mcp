/**
 * Voice note transcription through Google's Gemini API (the Interactions endpoint). Only runs when an agent
 * asks for it, and only when the operator set GEMINI_API_KEY. The audio leaves this server for Google.
 */

const ENDPOINT = 'https://generativelanguage.googleapis.com/v1beta/interactions';
const API_REVISION = '2026-05-20';
/**
 * The lite alias follows Google's current Flash-Lite. Tried against a pure tone, the lite models answered
 * [no speech] while the larger Flash models invented whole sentences, so bigger is not better here.
 */
export const DEFAULT_GEMINI_MODEL = 'gemini-flash-lite-latest';
/** Inline requests are capped at 20 MB in all; base64 grows the audio by a third. */
export const MAX_AUDIO_BYTES = 14 * 1024 * 1024;

/** Goes after the audio: asked first, the models were more willing to make up speech that wasn't there. */
const PROMPT =
  'You are a careful speech-to-text system. Transcribe only words that are actually spoken in the WhatsApp voice message above, ' +
  'word for word, in the language spoken. Never guess or invent words. ' +
  'If the audio has no intelligible human speech (silence, a tone, music, noise), reply exactly [no speech]. ' +
  'Reply with the transcript only: no preamble, no timestamps, no speaker labels, no translation.';

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
        { type: 'audio', data: audio.data, mime_type: baseMime(audio.mime) },
        { type: 'text', text: PROMPT },
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
