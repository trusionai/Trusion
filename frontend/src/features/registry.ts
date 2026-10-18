/**
 * Every feature entry point from the original prototype and its HONEST status in this build.
 * `available` features are wired to the real backend. Everything else is shown as unavailable with the reason,
 * and has NO run button, so no result can be fabricated for it.
 */
export type FeatureStatus = 'available' | 'unavailable' | 'not_migrated' | 'removed';
export interface FeatureEntry { id: string; label: string; status: FeatureStatus; route?: string; capability?: string; reason?: string; originalView: string }

const NO_FEED = 'No sourced intelligence feed is configured in the backend, and the prototype’s content for this area was not verified as real. It is not shown so it cannot be mistaken for live threat data.';
const NOT_AUDITED = 'Not migrated or audited in this release. It will not appear as working until it has been reviewed and connected to a real backend capability.';

export const FEATURES: FeatureEntry[] = [
  { id: 'message', label: 'Message analysis', status: 'available', route: '#/message', originalView: 'sms-scanner, scam-analyzer' },
  { id: 'url', label: 'Link scanner', status: 'available', route: '#/url', originalView: 'link-scanner' },
  { id: 'apk', label: 'APK static analysis', status: 'available', route: '#/apk', originalView: 'apk-scanner' },
  { id: 'screenshot', label: 'Screenshot analysis', status: 'available', route: '#/screenshot', capability: 'screenshot', originalView: 'screenshot-analyzer' },
  { id: 'breach-checker', label: 'Breach checker', status: 'removed', originalView: 'breach-checker', reason: 'The prototype produced "breach" results derived from the text you typed, not from any breach database. Showing them would be false. It returns only when a verified data source is integrated.' },
  { id: 'deepfake-center', label: 'Deepfake / image authenticity', status: 'unavailable', originalView: 'deepfake-center', reason: 'No validated detection model or evaluation exists. The prototype’s image-authenticity judgement was derived from the file name, not the image content.' },
  { id: 'voice-fraud-intelligence', label: 'Voice fraud intelligence', status: 'unavailable', originalView: 'voice-fraud-intelligence', reason: 'The backend has no audio-analysis pipeline.' },
  { id: 'riskradar', label: 'RiskRadar', status: 'unavailable', originalView: 'riskradar', reason: 'The prototype displayed hard-coded sample entries. ' + NO_FEED },
  { id: 'verification-center', label: 'Verification Center', status: 'unavailable', originalView: 'verification-center', reason: 'The prototype displayed hard-coded sample reports and ratings. ' + NO_FEED },
  { id: 'threat-intel', label: 'Threat intelligence', status: 'unavailable', originalView: 'threat-intel', reason: NO_FEED },
  { id: 'threat-map', label: 'Threat map', status: 'unavailable', originalView: 'threat-map', reason: NO_FEED },
  { id: 'intel-dashboard', label: 'Intel dashboard', status: 'unavailable', originalView: 'intel-dashboard', reason: NO_FEED },
  { id: 'scam-database', label: 'Scam database', status: 'unavailable', originalView: 'scam-database', reason: NO_FEED },
  { id: 'community', label: 'Community reports', status: 'unavailable', originalView: 'community', reason: 'There is no backend for community submissions, moderation or storage yet.' },
  { id: 'ai-agent', label: 'AI assistant', status: 'unavailable', originalView: 'ai-agent', reason: 'The prototype assistant produced locally generated replies. A backend chat route with consent, quota and output validation does not exist yet.' },
  { id: 'qr-scanner', label: 'QR scanner', status: 'not_migrated', originalView: 'qr-scanner', reason: 'Needs a QR-decoding library that could not be installed in this build environment.' },
  { id: 'investment-checker', label: 'Investment checker', status: 'not_migrated', originalView: 'investment-checker', reason: NOT_AUDITED },
  { id: 'server-audit', label: 'Server audit', status: 'not_migrated', originalView: 'server-audit', reason: NOT_AUDITED },
  { id: 'simulation-center', label: 'Simulation center', status: 'not_migrated', originalView: 'simulation-center', reason: NOT_AUDITED },
  { id: 'fake-profile', label: 'Fake profile check', status: 'not_migrated', originalView: 'fake-profile', reason: NOT_AUDITED },
  { id: 'photo-privacy', label: 'Photo privacy', status: 'not_migrated', originalView: 'photo-privacy', reason: NOT_AUDITED },
  { id: 'family-guardian', label: 'Family guardian', status: 'not_migrated', originalView: 'family-guardian', reason: NOT_AUDITED },
  { id: 'temp-email', label: 'Temporary email', status: 'not_migrated', originalView: 'temp-email', reason: NOT_AUDITED },
  { id: 'recovery', label: 'Recovery assistant', status: 'not_migrated', originalView: 'recovery', reason: NOT_AUDITED },
  { id: 'help-center', label: 'Help center', status: 'not_migrated', originalView: 'help-center', reason: 'Static help content has not been migrated.' },
];
export const findFeature = (id: string | undefined) => FEATURES.find((f) => f.id === id);
export const statusLabel = (s: FeatureStatus) => ({ available: 'Available', unavailable: 'Unavailable', not_migrated: 'Not migrated', removed: 'Removed' }[s]);
