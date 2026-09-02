import { AudioWaveform, Binary, Fingerprint, KeyRound, PackageOpen, ShieldCheck } from 'lucide-react'

export const pipelineStages = [
  { id: 'fingerprint', label: 'بصمة الإطار', caption: 'ربط بالسياق', icon: Fingerprint },
  { id: 'kdf', label: 'اشتقاق 3 مفاتيح', caption: 'فصل المجالات', icon: KeyRound },
  { id: 'pack', label: 'جهّز الملف', caption: 'بيانات وصفية + ضغط + حشو', icon: PackageOpen },
  { id: 'cipher', label: 'شفّر الكتل', caption: 'CBC يستدعي SPN لكل كتلة', icon: Binary },
  { id: 'payload', label: 'HMAC + حمولة', caption: 'توثيق قبل الفك', icon: ShieldCheck },
  { id: 'audio', label: 'مواضع + LSB', caption: 'إخفاء داخل PCM', icon: AudioWaveform },
] as const
