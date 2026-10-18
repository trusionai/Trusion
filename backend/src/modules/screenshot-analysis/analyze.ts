/**
 * Screenshot analysis = REAL OCR of the uploaded pixels, then the same evidence pipeline as SMS analysis on the
 * extracted text. The filename is never an input. Results are labelled as OCR-derived and never "completed" without
 * limitations, because OCR can mis-read text.
 */
import { createHash } from 'node:crypto';
import type { AnalysisStatus } from '../../shared/types.ts';
import type { Gateway } from '../ai-gateway/gateway.ts';
import type { PlanConfig } from '../entitlements/plans.ts';
import { sniffImage } from '../file-analysis/image.ts';
import type { ImageInfo } from '../file-analysis/image.ts';
import type { OcrEngine } from '../file-analysis/ocr.ts';
import { analyzeSms } from '../sms-analysis/analyze.ts';
import type { SmsResult } from '../sms-analysis/analyze.ts';

export interface ScreenshotResult extends Omit<SmsResult, 'assessment' | 'status'> {
  status: AnalysisStatus;
  assessment: SmsResult['assessment'] | 'no_text_found';
  source: 'screenshot_ocr';
  image: ImageInfo & { sha256: string; sizeBytes: number };
  ocr: { engine: string; version?: string; language: string; textLength: number; textPreview: string; previewTruncated: boolean };
}

export const MIN_TEXT_CHARS = 8;
const PREVIEW = 600;

export async function analyzeScreenshot(p: {
  image: Buffer; ocr: OcrEngine; ocrVersion?: string; gateway: Gateway; userId: string; plan: PlanConfig; requestId: string; allowExternal: boolean;
}): Promise<{ result: ScreenshotResult; sawAmbiguousProviderCost: boolean }> {
  const info = sniffImage(p.image);                                       // throws ImageRejected for non-images / bombs
  const raw = await p.ocr.recognize(p.image);                              // throws OcrError
  const text = raw.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '').replace(/[ \t]+/g, ' ').replace(/\n{3,}/g, '\n\n').trim().slice(0, p.plan.maxTextChars);
  const meta = {
    source: 'screenshot_ocr' as const,
    image: { ...info, sha256: createHash('sha256').update(p.image).digest('hex'), sizeBytes: p.image.length },
    ocr: { engine: p.ocr.name, version: p.ocrVersion, language: 'eng', textLength: text.length, textPreview: text.slice(0, PREVIEW), previewTruncated: text.length > PREVIEW },
  };
  const ocrLimits = ['Text was extracted by OCR (English language model only) and may contain recognition errors; image content that is not text (logos, layout, QR codes) was not analysed.'];
  if (text.length < MIN_TEXT_CHARS) {
    return { sawAmbiguousProviderCost: false, result: {
      ...meta, status: 'inconclusive', assessment: 'no_text_found',
      heuristic: { score: 0, indicators: [] }, urls: [], ai: { used: false, notUsedReason: 'no_text_extracted' },
      limitations: ['No readable text was found in the image, so nothing could be assessed.', ...ocrLimits],
      recommendedActions: ['Try a clearer, higher-resolution screenshot, or paste the message text directly.'],
    } };
  }
  const { result: sms, sawAmbiguousProviderCost } = await analyzeSms({ text, gateway: p.gateway, userId: p.userId, plan: p.plan, requestId: p.requestId, allowExternal: p.allowExternal });
  const status: AnalysisStatus = sms.status === 'completed' ? 'completed_with_limitations' : sms.status;
  return { sawAmbiguousProviderCost, result: { ...sms, ...meta, status, limitations: [...ocrLimits, ...sms.limitations] } };
}
