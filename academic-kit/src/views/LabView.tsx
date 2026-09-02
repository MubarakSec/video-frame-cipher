import { useEffect, useState, useMemo, useRef, type KeyboardEvent, type ReactNode } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Activity,
  AudioWaveform,
  Binary,
  Braces,
  Calculator,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  Fingerprint,
  Gauge,
  KeyRound,
  Link2,
  Pause,
  Play,
  PlayCircle,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
  Image as ImageIcon,
  Upload,
} from 'lucide-react'
import {
  AvalancheChart,
  CbcDiagram,
  FingerprintGrid,
  Hex,
  KeyTree,
  PayloadRuler,
  RoundFlow,
  StateMatrix,
  VerificationSeal,
  InteractiveSBox,
  ShiftRowsVisualizer,
  MixColumnsVisualizer,
  AddRoundKeyVisualizer,
  GaloisFieldExplorer,
} from '../components/CryptoVisuals'
import { vfcTrace } from '../data/vfc-trace'
import { testNames } from '../content'
import { pipelineStages } from '../pipeline'
import {
  deriveVFCKeys,
  encryptVFCCbc,
  decryptVFCCbc,
  generateVFCPayload,
  verifyVFCPayload,
  readVFCPayloadHeader,
  embedPayloadInAudio,
  extractPayloadFromAudio,
  parsePcm16Wav,
  getAudioCapacity,
  packVFCPlaintext,
  unpackVFCPlaintext,
  bytesToHex,
  hexToBytes,
  getRoundKeys,
  encryptVFCBlockTrace,
  padPKCS7,
  xorBytes,
  traceVFCBlockLayers,
  type VFCWavAudio,
} from '../lib/vfc-crypto'

type LabSection = 'overview' | 'studio' | 'fingerprint' | 'keys' | 'field' | 'cipher' | 'diffusion' | 'cbc' | 'payload' | 'audio' | 'evidence'

type LabGroup = 'story' | 'crypto' | 'proof'

type LabNavItem = {
  id: LabSection
  label: string
  caption: string
  group: LabGroup
  icon: typeof Activity
  talkTrack: string
  demoAction: string
}

const navItems: LabNavItem[] = [
  {
    id: 'overview',
    label: 'خريطة النظام',
    caption: 'ترتيب التنفيذ من البصمة إلى الصوت',
    group: 'story',
    icon: Activity,
    talkTrack: 'نشفّر الملف أولاً، ونوثّقه ثانياً، ثم نخفي بتاته داخل الصوت. الإطار وكلمة المرور يربطان الخطوات معاً.',
    demoAction: 'شغّل الأثر التنفيذي لمتابعة تسلسل الطبقات، ثم اضغط كل محطة لقراءة وظيفتها.',
  },
  {
    id: 'studio',
    label: 'المحاكاة الكاملة',
    caption: 'تجربة الإخفاء والاسترجاع التفاعلية',
    group: 'story',
    icon: PlayCircle,
    talkTrack: 'هنا ندمج كل شيء معاً: حجم الحمولة يساوي 82 بايت ثابتة مع نص مشفر متغير، ثم تُخفى وتُستخرج وتُفحص فعلياً.',
    demoAction: 'اكتب رسالتك السرية واضغط تشفير وإخفاء لمشاهدة المسار الكامل.',
  },
  {
    id: 'fingerprint',
    label: 'حوّل الإطار إلى بصمة',
    caption: '64 بتاً من نمط الإضاءة',
    group: 'crypto',
    icon: Fingerprint,
    talkTrack: 'نختصر نمط إضاءة الإطار في 64 قراراً: فاتح أو داكن. هذه بصمة سياقية وليست كلمة سر ثانية.',
    demoAction: 'بدّل إلى عرض البتات واختر خلية واحدة لشرح قرار 0 أو 1.',
  },
  {
    id: 'keys',
    label: 'اشتق ثلاثة مفاتيح',
    caption: 'مدخل واحد وثلاث وظائف معزولة',
    group: 'crypto',
    icon: KeyRound,
    talkTrack: 'من كلمة مرور واحدة نشتق ثلاثة مفاتيح منفصلة: واحد للمواضع، وواحد للتشفير، وواحد للتحقق.',
    demoAction: 'تنقّل بين K_embed وK_enc وK_auth وقارن ترتيب مدخل PBKDF2.',
  },
  {
    id: 'field',
    label: 'افهم حقل غالوا',
    caption: 'أساس MixColumns والضرب 1، 2، 3',
    group: 'crypto',
    icon: Calculator,
    talkTrack: 'حقل GF(2⁸) هو طريقة الحساب داخل البايت: الجمع يصبح XOR والضرب يُختزل بكثير الحدود 0x11B. تستخدمه MixColumns فقط داخل SPN.',
    demoAction: 'غيّر البايت وشاهد لماذا يحتاج الضرب في 2 أحياناً إلى XOR مع 0x1B، ثم تحقق من مصفوفة العكس.',
  },
  {
    id: 'cipher',
    label: 'تتبّع كتلة التشفير',
    caption: 'غيّر 16 بايتاً وافحص ست جولات',
    group: 'crypto',
    icon: Binary,
    talkTrack: 'SPN اختصار Substitution–Permutation Network: بنية شيفرة الكتلة نفسها. تستقبل 16 بايتاً ومفاتيح RK₀…RK₆، ثم تنفذ الاستبدال والتحريك والمزج وإضافة المفتاح.',
    demoAction: 'اعرض الجولة الأولى طبقةً طبقة، ثم افتح فاحص S-Box عند السؤال.',
  },
  {
    id: 'diffusion',
    label: 'راقب انتشار التغيير',
    caption: 'من بت واحد إلى 16 بايتاً',
    group: 'crypto',
    icon: Gauge,
    talkTrack: 'نقلب بتاً واحداً فقط؛ وبعد جولتين يصل أثره إلى كل بايتات الكتلة الستة عشر.',
    demoAction: 'حرّك خط الزمن من المدخل إلى الجولة السادسة، ثم أشر إلى متوسط 128 تجربة.',
  },
  {
    id: 'cbc',
    label: 'اربط كتل التشفير',
    caption: 'CBC والحشو',
    group: 'crypto',
    icon: Link2,
    talkTrack: 'في التنفيذ يأتي XOR أولاً: Xᵢ = Pᵢ ⊕ IV/Cᵢ₋₁، ثم تدخل Xᵢ إلى شيفرة SPN التي تعلمناها في الفصل السابق.',
    demoAction: 'قارن ترتيب الشرح بترتيب التنفيذ، ثم تتبع Xᵢ حتى Cᵢ في كتلتين.',
  },
  {
    id: 'payload',
    label: 'افتح الحزمة المخفية',
    caption: 'رأس، نص مشفر، وHMAC',
    group: 'crypto',
    icon: Braces,
    talkTrack: 'الحمولة حزمة مرتبة: رأس يصفها، ثم النص المشفر، ثم وسم HMAC الذي يكشف أي تعديل.',
    demoAction: 'اختر حقلي ciphertext ثم hmac_sha256_tag ووضّح مجال التوثيق.',
  },
  {
    id: 'audio',
    label: 'اكتب البتات في الصوت',
    caption: 'LSB داخل عينات PCM',
    group: 'proof',
    icon: AudioWaveform,
    talkTrack: 'نضع كل بت في عينة صوت مختلفة، ولا تتغير العينة في هذا المتجه إلا بمقدار صفر أو واحد.',
    demoAction: 'حرّك مؤشر عمليات الكتابة وراقب قبل/بعد وقيمة Δ.',
  },
  {
    id: 'evidence',
    label: 'راجع نتائج الاختبارات',
    caption: '13 فحصاً وما يثبته كل فحص',
    group: 'proof',
    icon: ShieldCheck,
    talkTrack: 'كل اختبار يجيب سؤالاً محدداً: هل المصفوفة قابلة للعكس؟ هل يعود الملف نفسه؟ هل يُرفض التعديل؟ اقرأ النتيجة مع السؤال الذي اختبرته.',
    demoAction: 'اختر اختباراً واقرأ المدخل، الشرط الذي فُحص، والنتيجة المسجلة.',
  },
]

const navGroups: Array<{ id: LabGroup; label: string }> = [
  { id: 'story', label: 'العرض السريع' },
  { id: 'crypto', label: 'كيف يعمل التشفير؟' },
  { id: 'proof', label: 'الإخفاء والإثبات' },
]

const guidedSections: LabSection[] = ['overview', 'fingerprint', 'keys', 'field', 'cipher', 'diffusion', 'cbc', 'payload', 'audio', 'evidence']

function readGuideModeFromUrl() {
  const params = new URLSearchParams(window.location.search)
  const candidate = params.get('section') as LabSection | null
  return params.get('guide') === '1' && (!candidate || guidedSections.includes(candidate))
}

function LabHeading({ eyebrow, title, summary, aside }: { eyebrow: string; title: string; summary: string; aside?: ReactNode }) {
  return (
    <header className="lab-heading">
      <div className="lab-heading-copy">
        <span className="lab-step-label">{eyebrow}</span>
        <h1>{title}</h1>
        <p>{summary}</p>
      </div>
      {aside && <div className="lab-heading-aside">{aside}</div>}
    </header>
  )
}

function EvidenceTag({ children, tone = 'source' }: { children: ReactNode; tone?: 'source' | 'warning' | 'verified' }) {
  return <span className={`evidence-tag evidence-tag--${tone}`}>{children}</span>
}

function DetailsToggle({
  open,
  onToggle,
  controls,
}: {
  open: boolean
  onToggle: () => void
  controls: string
}) {
  return (
    <button
      type="button"
      className="details-toggle"
      aria-expanded={open}
      aria-controls={controls}
      onClick={onToggle}
    >
      {open ? <ChevronRight size={17} aria-hidden="true" /> : <ChevronLeft size={17} aria-hidden="true" />}
      {open ? 'إخفاء التفاصيل التقنية' : 'عرض التفاصيل التقنية'}
    </button>
  )
}

type OverviewStage = 'fingerprint' | 'kdf' | 'pack' | 'cipher' | 'payload' | 'audio'

function StageVisualGraphic({ active }: { active: OverviewStage }) {
  if (active === 'fingerprint') {
    return (
      <div className="motion-graphic-box" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-around', gap: '1rem', flexWrap: 'wrap', padding: '1.25rem', background: 'var(--black-deep)', borderRadius: '10px', border: '1px solid var(--line-dark)' }}>
        {/* Step A: Frame Grayscale */}
        <div style={{ textAlign: 'center' }}>
          <div style={{ width: '64px', height: '64px', background: 'linear-gradient(135deg, #333, #777, #222)', borderRadius: '6px', border: '2px solid var(--accent)', display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '2px', padding: '4px', margin: '0 auto 0.5rem' }}>
            {Array.from({ length: 16 }).map((_, i) => (
              <div key={i} style={{ background: `rgba(255,255,255,${0.2 + (i % 5) * 0.15})`, borderRadius: '2px' }} />
            ))}
          </div>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>إطار رمادي 32×32</span>
        </div>

        <div style={{ color: 'var(--accent)', fontSize: '1.4rem', fontWeight: 'bold' }}>←</div>

        {/* Step B: 8x8 Average & Median Comparison */}
        <div style={{ textAlign: 'center', background: 'var(--surface-dark-2)', border: '1px solid var(--accent)', borderRadius: '8px', padding: '0.6rem 1rem' }}>
          <div style={{ fontSize: '0.8rem', color: 'var(--accent)', fontWeight: 'bold', marginBottom: '0.25rem' }}>مقارنة الوسيط (Median)</div>
          <div style={{ fontSize: '0.85rem', color: 'var(--white)', fontFamily: 'monospace' }}>μ_block (178.0) ≥ Median (150.5)</div>
          <div style={{ marginTop: '0.35rem', display: 'inline-block', padding: '0.15rem 0.6rem', background: 'var(--green-bright)', color: '#111', borderRadius: '12px', fontSize: '0.75rem', fontWeight: 'bold' }}>
            Decision = 1
          </div>
        </div>

        <div style={{ color: 'var(--accent)', fontSize: '1.4rem', fontWeight: 'bold' }}>←</div>

        {/* Step C: 64-bit aHash Register */}
        <div style={{ textAlign: 'center' }}>
          <div style={{ padding: '0.6rem 0.9rem', background: 'var(--surface-dark-3)', border: '1px solid var(--green-bright)', borderRadius: '8px', boxShadow: '0 0 10px rgba(166,227,161,0.2)' }}>
            <span style={{ display: 'block', fontSize: '0.7rem', color: 'var(--green-bright)', marginBottom: '0.2rem' }}>البصمة الناتجة (64-bit aHash)</span>
            <span style={{ fontFamily: 'monospace', fontSize: '0.95rem', color: 'var(--white)', fontWeight: 'bold' }}>{vfcTrace.fingerprint.bytesHex}</span>
          </div>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginTop: '0.35rem' }}>8 بايت تربط التشفير بالإطار</span>
        </div>
      </div>
    )
  }

  if (active === 'kdf') {
    return (
      <div className="motion-graphic-box" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-around', gap: '1rem', flexWrap: 'wrap', padding: '1.25rem', background: 'var(--black-deep)', borderRadius: '10px', border: '1px solid var(--line-dark)' }}>
        {/* Step A: 3 Inputs */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
          <div style={{ padding: '0.3rem 0.6rem', background: 'var(--surface-dark-2)', border: '1px solid var(--line-dark)', borderRadius: '6px', fontSize: '0.78rem', color: 'var(--white)' }}>🔑 Password ("BlackRing-2028")</div>
          <div style={{ padding: '0.3rem 0.6rem', background: 'var(--surface-dark-2)', border: '1px solid var(--line-dark)', borderRadius: '6px', fontSize: '0.78rem', color: 'var(--accent)' }}>🖼️ Frame aHash ({vfcTrace.fingerprint.bytesHex.slice(0, 8)}…)</div>
          <div style={{ padding: '0.3rem 0.6rem', background: 'var(--surface-dark-2)', border: '1px solid var(--line-dark)', borderRadius: '6px', fontSize: '0.78rem', color: 'var(--text-muted)' }}>🧂 Random Salt (لـ K_enc وK_auth فقط)</div>
        </div>

        <div style={{ color: 'var(--accent)', fontSize: '1.4rem', fontWeight: 'bold' }}>←</div>

        {/* Step B: PBKDF2 Core */}
        <div style={{ textAlign: 'center', background: 'var(--surface-dark-2)', border: '2px solid var(--accent)', borderRadius: '8px', padding: '0.75rem 1.25rem', boxShadow: '0 0 12px rgba(137, 180, 250, 0.25)' }}>
          <div style={{ fontSize: '0.85rem', color: 'var(--accent)', fontWeight: 'bold' }}>PBKDF2-HMAC-SHA256</div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>200,000 دورة اشتقاق معزولة</div>
        </div>

        <div style={{ color: 'var(--accent)', fontSize: '1.4rem', fontWeight: 'bold' }}>←</div>

        {/* Step C: 3 Output Keys */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
          <div style={{ padding: '0.3rem 0.6rem', background: 'rgba(203, 166, 247, 0.15)', border: '1px solid #cba6f7', borderRadius: '6px', fontSize: '0.78rem', color: '#cba6f7', fontWeight: 'bold' }}>
            🟣 K_embed (مواضع LSB وMagic)
          </div>
          <div style={{ padding: '0.3rem 0.6rem', background: 'rgba(137, 180, 250, 0.15)', border: '1px solid #89b4fa', borderRadius: '6px', fontSize: '0.78rem', color: '#89b4fa', fontWeight: 'bold' }}>
            🔵 K_enc (مفاتيح جولات SPN)
          </div>
          <div style={{ padding: '0.3rem 0.6rem', background: 'rgba(166, 227, 161, 0.15)', border: '1px solid #a6e3a1', borderRadius: '6px', fontSize: '0.78rem', color: '#a6e3a1', fontWeight: 'bold' }}>
            🟢 K_auth (وسم HMAC-SHA256)
          </div>
        </div>
      </div>
    )
  }

  if (active === 'pack') {
    return (
      <div className="motion-graphic-box pack-overview-graphic">
        <div><small>الملف</small><strong>الاسم + الحجم + البايتات</strong></div>
        <b>→</b>
        <div><small>الحزمة الداخلية</small><strong>name_len | name | size | flags | data</strong></div>
        <b>→</b>
        <div className="is-output"><small>قبل CBC</small><strong>ضغط اختياري + PKCS#7</strong></div>
        <p>هذه الحزمة الداخلية هي النص الصريح الذي يُشفَّر؛ وهي مختلفة عن الحمولة الخارجية التي تُبنى بعد التشفير.</p>
      </div>
    )
  }

  if (active === 'cipher') {
    return (
      <div className="motion-graphic-box" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-around', gap: '1rem', flexWrap: 'wrap', padding: '1.25rem', background: 'var(--black-deep)', borderRadius: '10px', border: '1px solid var(--line-dark)' }}>
        {/* CBC loop: prepare Xi, call SPN, feed Ci back */}
        <div style={{ textAlign: 'center', background: 'var(--surface-dark-2)', border: '1px solid var(--line-dark)', borderRadius: '8px', padding: '0.6rem 0.9rem' }}>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>داخل دورة CBC الحالية</div>
          <div style={{ fontSize: '0.85rem', color: 'var(--white)', fontFamily: 'monospace', marginTop: '0.2rem' }}>X_i = P_i ⊕ (IV / C_(i-1))</div>
          <small style={{ fontSize: '0.7rem', color: 'var(--accent)' }}>XOR يجهز كتلة Xᵢ</small>
        </div>

        <div style={{ color: 'var(--accent)', fontSize: '1.4rem', fontWeight: 'bold' }}>←</div>

        {/* Step B: four SPN layers repeated for six rounds */}
        <div style={{ textAlign: 'center', background: 'var(--surface-dark-2)', border: '2px solid #f9e2af', borderRadius: '8px', padding: '0.75rem 1rem' }}>
          <div style={{ fontSize: '0.8rem', color: '#f9e2af', fontWeight: 'bold', marginBottom: '0.35rem' }}>شبكة SPN (6 جولات تكرار)</div>
          <div style={{ display: 'flex', gap: '0.35rem', justifyContent: 'center', flexWrap: 'wrap' }}>
            <span style={{ padding: '0.2rem 0.4rem', background: 'var(--black-deep)', borderRadius: '4px', fontSize: '0.72rem', color: 'var(--white)', border: '1px solid var(--line-dark)' }}>1. SubBytes (S-Box)</span>
            <span style={{ padding: '0.2rem 0.4rem', background: 'var(--black-deep)', borderRadius: '4px', fontSize: '0.72rem', color: 'var(--white)', border: '1px solid var(--line-dark)' }}>2. ShiftRows</span>
            <span style={{ padding: '0.2rem 0.4rem', background: 'var(--black-deep)', borderRadius: '4px', fontSize: '0.72rem', color: 'var(--white)', border: '1px solid var(--line-dark)' }}>3. MixColumns GF(2^8)</span>
            <span style={{ padding: '0.2rem 0.4rem', background: 'var(--black-deep)', borderRadius: '4px', fontSize: '0.72rem', color: 'var(--white)', border: '1px solid var(--line-dark)' }}>4. AddRoundKey</span>
          </div>
        </div>

        <div style={{ color: 'var(--accent)', fontSize: '1.4rem', fontWeight: 'bold' }}>←</div>

        {/* Step C: Ciphertext Block */}
        <div style={{ textAlign: 'center', background: 'var(--surface-dark-2)', border: '1px solid var(--green-bright)', borderRadius: '8px', padding: '0.6rem 0.9rem', boxShadow: '0 0 10px rgba(166,227,161,0.2)' }}>
          <div style={{ fontSize: '0.75rem', color: 'var(--green-bright)' }}>النص المشفر (Ciphertext Block C_i)</div>
          <div style={{ fontSize: '0.85rem', color: 'var(--white)', fontFamily: 'monospace', marginTop: '0.2rem' }}>e663a80b94fa9675…</div>
          <small style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>يعود Cᵢ إلى XOR الكتلة التالية</small>
        </div>
      </div>
    )
  }

  if (active === 'payload') {
    return (
      <div className="motion-graphic-box" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-around', gap: '1rem', flexWrap: 'wrap', padding: '1.25rem', background: 'var(--black-deep)', borderRadius: '10px', border: '1px solid var(--line-dark)' }}>
        {/* Step A: Header + Ciphertext */}
        <div style={{ textAlign: 'center' }}>
          <div style={{ display: 'flex', gap: '2px', background: 'var(--surface-dark-2)', padding: '4px', borderRadius: '6px', border: '1px solid var(--line-dark)', marginBottom: '0.35rem' }}>
            <span style={{ padding: '0.2rem 0.4rem', background: '#313244', fontSize: '0.7rem', color: 'var(--accent)' }}>Magic(4B)</span>
            <span style={{ padding: '0.2rem 0.4rem', background: '#313244', fontSize: '0.7rem', color: 'var(--white)' }}>V+F(2B)</span>
            <span style={{ padding: '0.2rem 0.4rem', background: '#313244', fontSize: '0.7rem', color: 'var(--text-muted)' }}>Salt(16B)</span>
            <span style={{ padding: '0.2rem 0.4rem', background: '#313244', fontSize: '0.7rem', color: 'var(--text-muted)' }}>IV(16B)</span>
            <span style={{ padding: '0.2rem 0.4rem', background: '#313244', fontSize: '0.7rem', color: 'var(--text-muted)' }}>Frame(4B)</span>
            <span style={{ padding: '0.2rem 0.4rem', background: '#313244', fontSize: '0.7rem', color: 'var(--white)' }}>ct_len(8B)</span>
            <span style={{ padding: '0.2rem 0.4rem', background: '#45475a', fontSize: '0.7rem', color: 'var(--green-bright)', fontWeight: 'bold' }}>Ciphertext(32B)</span>
          </div>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>ترويسة عامة موثّقة + نص مشفر (82 بايتاً في المتجه)</span>
        </div>

        <div style={{ color: 'var(--accent)', fontSize: '1.2rem', fontWeight: 'bold' }}>+</div>

        {/* Step B: HMAC Engine */}
        <div style={{ textAlign: 'center', background: 'rgba(166, 227, 161, 0.1)', border: '2px solid var(--green-bright)', borderRadius: '8px', padding: '0.6rem 1rem' }}>
          <div style={{ fontSize: '0.8rem', color: 'var(--green-bright)', fontWeight: 'bold' }}>🛡️ توثيق HMAC-SHA256</div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>وسم سلامة لمنع أي تعديل (32B)</div>
        </div>

        <div style={{ color: 'var(--accent)', fontSize: '1.2rem', fontWeight: 'bold' }}>=</div>

        {/* Step C: Full 114B Payload */}
        <div style={{ textAlign: 'center', background: 'var(--surface-dark-3)', border: '1px solid var(--accent)', borderRadius: '8px', padding: '0.6rem 1rem' }}>
          <div style={{ fontSize: '0.85rem', color: 'var(--white)', fontWeight: 'bold' }}>حمولة المتجه المسجل (114 Bytes)</div>
          <div style={{ fontSize: '0.75rem', color: 'var(--accent)', marginTop: '0.2rem' }}>912 بتاً جاهزة للإخفاء الصوتي</div>
        </div>
      </div>
    )
  }

  if (active === 'audio') {
    return (
      <div className="motion-graphic-box" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-around', gap: '1rem', flexWrap: 'wrap', padding: '1.25rem', background: 'var(--black-deep)', borderRadius: '10px', border: '1px solid var(--line-dark)' }}>
        {/* Step A: 912 Bits Stream */}
        <div style={{ textAlign: 'center', background: 'var(--surface-dark-2)', border: '1px solid var(--line-dark)', borderRadius: '8px', padding: '0.6rem 0.9rem' }}>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>بتات الحمولة</div>
          <div style={{ fontSize: '0.85rem', color: 'var(--accent)', fontFamily: 'monospace', marginTop: '0.2rem' }}>912 Bits (010011…)</div>
          <small style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>114 بايتاً في هذا المتجه فقط</small>
        </div>

        <div style={{ color: 'var(--accent)', fontSize: '1.4rem', fontWeight: 'bold' }}>←</div>

        {/* Step B: Silence Filter & Fisher-Yates CSPRNG */}
        <div style={{ textAlign: 'center', background: 'var(--surface-dark-2)', border: '2px solid var(--green-bright)', borderRadius: '8px', padding: '0.75rem 1rem' }}>
          <div style={{ fontSize: '0.8rem', color: 'var(--green-bright)', fontWeight: 'bold', marginBottom: '0.2rem' }}>فحص الصمت وتوليد المواضع</div>
          <div style={{ fontSize: '0.75rem', color: 'var(--white)', fontFamily: 'monospace' }}>|Sample ≫ 1| ≥ 2 (قاعدة الأهلية)</div>
          <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>تبديل Fisher-Yates بمفتاح K_embed</div>
        </div>

        <div style={{ color: 'var(--accent)', fontSize: '1.4rem', fontWeight: 'bold' }}>←</div>

        {/* Step C: Stego PCM Audio */}
        <div style={{ textAlign: 'center', background: 'var(--surface-dark-2)', border: '1px solid var(--green-bright)', borderRadius: '8px', padding: '0.6rem 0.9rem', boxShadow: '0 0 10px rgba(166,227,161,0.2)' }}>
          <div style={{ fontSize: '0.75rem', color: 'var(--green-bright)' }}>عينات PCM بعد تعديل 1-bit LSB</div>
          <div style={{ fontSize: '0.85rem', color: 'var(--white)', fontWeight: 'bold', marginTop: '0.2rem' }}>SNR = {vfcTrace.measurements.audio.signalToNoiseRatioDb.toFixed(1)} dB</div>
          <small style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>قياس المتجه المسجل؛ مقدار التغيير ≤ 1</small>
        </div>
      </div>
    )
  }

  return null
}

const overviewStages: OverviewStage[] = ['fingerprint', 'kdf', 'pack', 'cipher', 'payload', 'audio']

function OverviewLab({ onNavigate }: { onNavigate?: (section: LabSection) => void }) {
  const [active, setActive] = useState<OverviewStage>('fingerprint')
  const [autoPlaying, setAutoPlaying] = useState(false)
  const autoPlayTimerRef = useRef<number | null>(null)

  useEffect(() => {
    if (autoPlaying) {
      const currentIdx = overviewStages.indexOf(active)
      autoPlayTimerRef.current = window.setTimeout(() => {
        const nextIdx = (currentIdx + 1) % overviewStages.length
        setActive(overviewStages[nextIdx])
      }, 3000)
    }
    return () => {
      if (autoPlayTimerRef.current !== null) window.clearTimeout(autoPlayTimerRef.current)
    }
  }, [autoPlaying, active])

  const toggleAutoPlay = () => {
    if (autoPlaying) {
      setAutoPlaying(false)
    } else {
      setAutoPlaying(true)
    }
  }

  const stageData = {
    fingerprint: {
      title: '1. استخراج البصمة البصرية (aHash 64-bit)',
      role: 'ربط السياق وحماية التنوع (Context Binding)',
      targetLab: 'fingerprint' as LabSection,
      inputLabel: 'الإطار المرجعي #30 (Grayscale Matrix 64×64)',
      inputVal: 'إطار الفيديو الحامل',
      processLabel: 'تطبيع 32×32 ← متوسطات 8×8 كتل ← مقارنة بالوسيط (150.5)',
      outputLabel: 'البصمة السياقية الناتجة (64 بتاً / 8 بايت):',
      outputVal: vfcTrace.fingerprint.bytesHex,
      badgeTone: 'verified' as const,
    },
    kdf: {
      title: '2. اشتقاق المفاتيح الثلاثة (PBKDF2-HMAC-SHA256)',
      role: 'فصل المجالات الأمنية (Domain Separation)',
      targetLab: 'keys' as LabSection,
      inputLabel: 'كلمة المرور + بصمة aHash + رقم الإطار، والملح العشوائي لفرعي التشفير والتوثيق فقط',
      inputVal: 'Password + domain + aHash + frame (+ salt)',
      processLabel: '200,000 دورة PBKDF2 مع ملح مشتق لكل وظيفة بشكل معزول',
      outputLabel: 'المفاتيح الثلاثة الناتجة:',
      outputVal: 'K_embed (مواضع) | K_enc (تشفير SPN) | K_auth (HMAC)',
      badgeTone: 'verified' as const,
    },
    pack: {
      title: '3. تجهيز النص الصريح الداخلي',
      role: 'حفظ هوية الملف وحدوده قبل التشفير',
      targetLab: 'cbc' as LabSection,
      inputLabel: 'اسم الملف + حجمه الأصلي + راية الضغط + بايتات الملف',
      inputVal: 'name_len | filename | original_size | flags | file_bytes',
      processLabel: 'ضغط اختياري للبيانات ثم حشو PKCS#7 إلى مضاعف 16 بايتاً',
      outputLabel: 'المتجه المسجل بعد التجهيز:',
      outputVal: '29 B inner plaintext + 3 B padding = 32 B',
      badgeTone: 'source' as const,
    },
    cipher: {
      title: '4. دورة CBC التي تستدعي SPN',
      role: 'ربط الكتل وتشفير كل كتلة 16 بايتاً',
      targetLab: 'cipher' as LabSection,
      inputLabel: 'كتل Pᵢ المحشوة + IV، ثم Cᵢ₋₁ للكتل اللاحقة',
      inputVal: 'Xᵢ = Pᵢ XOR previous → SPN(K, Xᵢ) → Cᵢ',
      processLabel: 'داخل كل دورة: XOR ثم SPN بست جولات ثم تغذية Cᵢ إلى الدورة التالية',
      outputLabel: 'النص المشفر الناتج (Ciphertext):',
      outputVal: vfcTrace.cipher.blockTrace.rounds[vfcTrace.cipher.blockTrace.rounds.length - 1].addRoundKey.bytesHex,
      badgeTone: 'warning' as const,
    },
    payload: {
      title: '5. بناء وتوثيق الحزمة (Authenticated Payload)',
      role: 'سلامة البيانات وكشف التلاعب (Integrity / Anti-Tamper)',
      targetLab: 'payload' as LabSection,
      inputLabel: 'ترويسة عامة: magic | version | flags | salt | IV | frame_no | ct_len، ثم النص المشفر',
      inputVal: 'Authenticated header (50 B) + Ciphertext (32 B)',
      processLabel: 'حساب وسم HMAC-SHA256 على كامل الرأس والنص المشفر قبل الإخفاء',
      outputLabel: 'الحمولة الموثقة الكاملة (114 بايت):',
      outputVal: `82 Bytes Data + 32 Bytes HMAC Tag = 114 Bytes`,
      badgeTone: 'verified' as const,
    },
    audio: {
      title: '6. التضمين الصوتي (PCM LSB)',
      role: 'إخفاء الوجود الفيزيائي (Steganography)',
      targetLab: 'audio' as LabSection,
      inputLabel: 'بتات الحمولة (912 بت) + 47,992 عينة صوت PCM مؤهلة',
      inputVal: '912 Bits Payload ← 47,992 PCM Samples',
      processLabel: 'توليد مواضع بـ CSPRNG Fisher-Yates + استبدال 1-bit LSB للعينة المؤهلة وفق |sample ≫ 1| ≥ 2',
      outputLabel: 'جودة الصوت بعد الإخفاء (SNR > 80 dB):',
      outputVal: `SNR = ${vfcTrace.measurements.audio.signalToNoiseRatioDb.toFixed(2)} dB (لا يوجد أي تشويش مسموع)`,
      badgeTone: 'verified' as const,
    },
  }

  const current = stageData[active]

  return (
    <section className="lab-section">
      <LabHeading
        eyebrow="خريطة النظام التفاعلية · ست مراحل متصلة"
        title="المسار الرياضي الكامل من الملف إلى الصوت"
        summary="هذه خريطة التشفير: نجهز الملف أولاً، ثم يعمل CBC كحلقة تستدعي SPN لكل كتلة، وبعد اكتمال النص المشفر نبني الحمولة ونخفي بتاتها."
        aside={<EvidenceTag tone="verified">بيانات حقيقية من التنفيذ</EvidenceTag>}
      />

      {/* Interactive Architecture Flowchart */}
      <div className="card" style={{ background: 'var(--surface-dark)', border: '1px solid var(--line-dark)', borderRadius: '12px', padding: '1.5rem', marginBottom: '1.5rem' }}>
        
        {/* Visual Pipeline Ribbon Navigation (Click any to inspect) */}
        <div style={{ marginBottom: '1.25rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem', flexWrap: 'wrap', gap: '0.5rem' }}>
            <strong style={{ fontSize: '0.95rem', color: 'var(--white)' }}>
              مسار معالجة البيانات المتسلسل (اضغط أي مرحلة لمعاينتها):
            </strong>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
              <button
                type="button"
                className={`button ${autoPlaying ? 'button--primary' : 'button--quiet'}`}
                onClick={toggleAutoPlay}
                style={{ fontSize: '0.8rem', padding: '0.3rem 0.8rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}
              >
                {autoPlaying ? <Pause size={14} aria-hidden="true" /> : <Play size={14} aria-hidden="true" />}
                {autoPlaying ? 'إيقاف مؤقت' : 'تشغيل تلقائي'}
              </button>
              <span style={{ fontSize: '0.8rem', color: 'var(--accent)' }}>
                المرحلة المحددة: {current.title}
              </span>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: '0.65rem' }}>
            {pipelineStages.map((stg, idx) => {
              const Icon = stg.icon
              const isSelected = active === stg.id
              return (
                <button
                  key={stg.id}
                  type="button"
                  onClick={() => setActive(stg.id as typeof active)}
                  style={{
                    background: isSelected ? 'var(--surface-dark-2)' : 'var(--surface-dark-3, #1e1e2e)',
                    border: isSelected ? '2px solid var(--accent)' : '1px solid var(--line-dark)',
                    borderRadius: '10px',
                    padding: '0.9rem 0.75rem',
                    textAlign: 'center',
                    cursor: 'pointer',
                    transition: 'all 0.15s ease',
                    position: 'relative',
                    boxShadow: isSelected ? '0 0 14px rgba(137, 180, 250, 0.3)' : 'none',
                  }}
                >
                  <div style={{ position: 'absolute', top: '6px', right: '8px', fontSize: '0.7rem', color: isSelected ? 'var(--accent)' : 'var(--text-muted)', fontFamily: 'monospace', fontWeight: 'bold' }}>
                    0{idx + 1}
                  </div>
                  <div style={{ color: isSelected ? 'var(--accent)' : 'var(--text-muted)', marginBottom: '0.4rem', display: 'flex', justifyContent: 'center' }}>
                    <Icon size={24} strokeWidth={isSelected ? 2.2 : 1.6} />
                  </div>
                  <strong style={{ display: 'block', fontSize: '0.88rem', color: isSelected ? 'var(--white)' : 'var(--text-muted)', marginBottom: '0.2rem' }}>
                    {stg.label}
                  </strong>
                  <small style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                    {stg.caption}
                  </small>
                </button>
              )
            })}
          </div>
        </div>

        {/* Selected Stage Detail Inspector (Visual Blueprint) */}
        <div style={{ background: 'var(--surface-dark-2)', border: '1px solid var(--line-dark)', borderRadius: '10px', padding: '1.25rem' }}>
          
          {/* Header of Inspector */}
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem', borderBottom: '1px solid var(--line-dark)', paddingBottom: '0.75rem', flexWrap: 'wrap', gap: '0.5rem' }}>
            <div>
              <strong style={{ fontSize: '1.15rem', color: 'var(--white)', display: 'block' }}>{current.title}</strong>
              <span style={{ fontSize: '0.85rem', color: 'var(--accent)' }}>الوظيفة المعمارية: {current.role}</span>
            </div>
            {onNavigate && (
              <button
                type="button"
                className="button button--primary"
                onClick={() => onNavigate(current.targetLab)}
                style={{ fontSize: '0.85rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}
              >
                <span>انتقل لمختبر هذه الطبقة بالتفصيل</span>
                <ChevronLeft size={16} aria-hidden="true" />
              </button>
            )}
          </div>

          {/* Dedicated Motion Graphic Visual Representation */}
          <div style={{ marginBottom: '1rem' }}>
            <StageVisualGraphic active={active} />
          </div>

          {/* 2-Box Summary (Inputs and Outputs) */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem' }}>
            
            {/* Input Box */}
            <div style={{ background: 'var(--black-deep)', border: '1px solid var(--line-dark)', borderRadius: '8px', padding: '0.85rem' }}>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px', display: 'block', marginBottom: '0.3rem' }}>
                المدخلات (Inputs)
              </span>
              <strong style={{ fontSize: '0.9rem', color: 'var(--white)', display: 'block', marginBottom: '0.2rem' }}>
                {current.inputVal}
              </strong>
              <small style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>{current.inputLabel}</small>
            </div>

            {/* Output Box */}
            <div style={{ background: 'var(--black-deep)', border: '1px solid var(--line-dark)', borderRadius: '8px', padding: '0.85rem' }}>
              <span style={{ fontSize: '0.75rem', color: 'var(--green-bright)', textTransform: 'uppercase', letterSpacing: '0.5px', display: 'block', marginBottom: '0.3rem' }}>
                المخرجات المعتمدة (Outputs)
              </span>
              <strong style={{ fontSize: '0.85rem', color: 'var(--green-bright)', display: 'block', marginBottom: '0.2rem', wordBreak: 'break-all', fontFamily: 'monospace' }}>
                {current.outputVal}
              </strong>
              <small style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>{current.outputLabel}</small>
            </div>

          </div>

        </div>

      </div>
    </section>
  )
}

interface DynamicFingerprint {
  name: string
  normalizedPixels: number[][]
  blockAverages: number[][]
  median: number
  bits: number[][]
  bytesHex: string
  previewDataUrl?: string
  grayscalePreviewDataUrl?: string
  sourceDataUrl?: string
  sourceWidth?: number
  sourceHeight?: number
}

function computeAHashFromImageData(img: HTMLImageElement, name: string, sourceDataUrl?: string): DynamicFingerprint {
  const canvas = document.createElement('canvas')
  canvas.width = 32
  canvas.height = 32
  const ctx = canvas.getContext('2d')
  if (!ctx) throw new Error('Canvas context failed')
  ctx.drawImage(img, 0, 0, 32, 32)
  const imgData = ctx.getImageData(0, 0, 32, 32)
  const data = imgData.data
  const grayscaleCanvas = document.createElement('canvas')
  grayscaleCanvas.width = 32
  grayscaleCanvas.height = 32
  const grayscaleCtx = grayscaleCanvas.getContext('2d')
  if (!grayscaleCtx) throw new Error('Canvas context failed')
  const grayscaleImage = grayscaleCtx.createImageData(32, 32)

  const normalizedPixels: number[][] = []
  for (let r = 0; r < 32; r++) {
    const row: number[] = []
    for (let c = 0; c < 32; c++) {
      const idx = (r * 32 + c) * 4
      const gray = Math.round(0.299 * data[idx] + 0.587 * data[idx + 1] + 0.114 * data[idx + 2])
      row.push(gray)
      grayscaleImage.data[idx] = gray
      grayscaleImage.data[idx + 1] = gray
      grayscaleImage.data[idx + 2] = gray
      grayscaleImage.data[idx + 3] = 255
    }
    normalizedPixels.push(row)
  }
  grayscaleCtx.putImageData(grayscaleImage, 0, 0)

  const blockAverages: number[][] = []
  const flatAverages: number[] = []
  for (let br = 0; br < 8; br++) {
    const avgRow: number[] = []
    for (let bc = 0; bc < 8; bc++) {
      let sum = 0
      for (let pr = 0; pr < 4; pr++) {
        for (let pc = 0; pc < 4; pc++) {
          sum += normalizedPixels[br * 4 + pr][bc * 4 + pc]
        }
      }
      const avg = sum / 16
      avgRow.push(avg)
      flatAverages.push(avg)
    }
    blockAverages.push(avgRow)
  }

  const sorted = [...flatAverages].sort((a, b) => a - b)
  const median = (sorted[31] + sorted[32]) / 2

  const bits: number[][] = []
  let bitString = ''
  for (let br = 0; br < 8; br++) {
    const bitRow: number[] = []
    for (let bc = 0; bc < 8; bc++) {
      const b = blockAverages[br][bc] >= median ? 1 : 0
      bitRow.push(b)
      bitString += b
    }
    bits.push(bitRow)
  }

  let bytesHex = ''
  for (let i = 0; i < 64; i += 8) {
    const byteByte = parseInt(bitString.slice(i, i + 8), 2)
    bytesHex += byteByte.toString(16).padStart(2, '0')
  }

  return {
    name,
    normalizedPixels,
    blockAverages,
    median,
    bits,
    bytesHex,
    previewDataUrl: canvas.toDataURL(),
    grayscalePreviewDataUrl: grayscaleCanvas.toDataURL(),
    sourceDataUrl,
    sourceWidth: img.naturalWidth || img.width,
    sourceHeight: img.naturalHeight || img.height,
  }
}

function FingerprintLab({ onNavigate }: { onNavigate: (section: LabSection) => void }) {
  const [activePreset, setActivePreset] = useState<'default' | 'gradient' | 'checker' | 'custom'>('default')
  const [customFp, setCustomFp] = useState<DynamicFingerprint | null>(null)
  const [mode, setMode] = useState<'averages' | 'bits'>('averages')
  const [selected, setSelected] = useState(0)
  const [walkthroughStep, setWalkthroughStep] = useState(0)
  const [asideOpen, setAsideOpen] = useState(() => typeof window !== 'undefined' ? window.innerWidth > 900 : true)

  const defaultData: DynamicFingerprint = {
    name: 'المتجه الافتراضي (إطار #30)',
    normalizedPixels: vfcTrace.fingerprint.normalizedPixels as unknown as number[][],
    blockAverages: vfcTrace.fingerprint.blockAverages as unknown as number[][],
    median: vfcTrace.fingerprint.median,
    bits: vfcTrace.fingerprint.bits as unknown as number[][],
    bytesHex: vfcTrace.fingerprint.bytesHex,
  }

  const fp = customFp ?? defaultData

  const row = Math.floor(selected / 8)
  const column = selected % 8
  const average = fp.blockAverages[row][column]
  const bit = fp.bits[row][column]

  // Extract the 16 normalized pixels (4x4) for the selected block
  const blockPixels = fp.normalizedPixels
    .slice(row * 4, row * 4 + 4)
    .map((r) => r.slice(column * 4, column * 4 + 4))

  const pixelSum = blockPixels.flat().reduce((a, b) => a + b, 0)
  const isBit1 = average >= fp.median
  const bitString = fp.bits.flat().join('')
  const bitBytes = Array.from({ length: 8 }, (_, index) => bitString.slice(index * 8, index * 8 + 8))
  const walkthroughLabels = ['الصورة', '32×32', 'رمادي', 'متوسطات', '64 بتاً', 'Hex']

  const selectBlock = (next: number) => {
    const safeIndex = Math.max(0, Math.min(63, next))
    setSelected(safeIndex)
    setAsideOpen(true)
    window.requestAnimationFrame(() => document.getElementById(`fingerprint-cell-${safeIndex}`)?.focus())
  }

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = (event) => {
      const img = new Image()
      img.onload = () => {
        const computed = computeAHashFromImageData(img, file.name, event.target?.result as string)
        setCustomFp(computed)
        setActivePreset('custom')
        setSelected(0)
        setWalkthroughStep(0)
      }
      img.src = event.target?.result as string
    }
    reader.readAsDataURL(file)
  }

  const loadSyntheticPreset = (type: 'gradient' | 'checker') => {
    const canvas = document.createElement('canvas')
    canvas.width = 32
    canvas.height = 32
    const ctx = canvas.getContext('2d')
    if (!ctx) return

    if (type === 'gradient') {
      const grad = ctx.createLinearGradient(0, 0, 32, 32)
      grad.addColorStop(0, '#ffffff')
      grad.addColorStop(1, '#000000')
      ctx.fillStyle = grad
      ctx.fillRect(0, 0, 32, 32)
    } else {
      ctx.fillStyle = '#ffffff'
      ctx.fillRect(0, 0, 32, 32)
      ctx.fillStyle = '#000000'
      for (let r = 0; r < 32; r += 4) {
        for (let c = 0; c < 32; c += 4) {
          if ((r / 4 + c / 4) % 2 === 1) {
            ctx.fillRect(c, r, 4, 4)
          }
        }
      }
    }

    const img = new Image()
    img.onload = () => {
      const sourceDataUrl = canvas.toDataURL()
      const computed = computeAHashFromImageData(img, type === 'gradient' ? 'تدرج ضوئي قطري' : 'رقعة شطرنجية', sourceDataUrl)
      setCustomFp(computed)
      setActivePreset(type)
      setSelected(0)
      setWalkthroughStep(0)
    }
    img.src = canvas.toDataURL()
  }

  const onGridKeyDown = (event: KeyboardEvent<HTMLButtonElement>, index: number) => {
    if (event.key === 'Home' || event.key === 'End') {
      event.preventDefault()
      selectBlock(event.key === 'Home' ? 0 : 63)
      return
    }
    if (!['ArrowRight', 'ArrowLeft', 'ArrowDown', 'ArrowUp'].includes(event.key)) return
    event.preventDefault()
    const currentRow = Math.floor(index / 8)
    const currentColumn = index % 8
    const nextRow = event.key === 'ArrowDown'
      ? Math.min(7, currentRow + 1)
      : event.key === 'ArrowUp'
        ? Math.max(0, currentRow - 1)
        : currentRow
    const nextColumn = event.key === 'ArrowRight'
      ? Math.min(7, currentColumn + 1)
      : event.key === 'ArrowLeft'
        ? Math.max(0, currentColumn - 1)
        : currentColumn
    selectBlock(nextRow * 8 + nextColumn)
  }

  const useFingerprintInStudio = () => {
    const url = new URL(window.location.href)
    url.searchParams.set('fingerprint', fp.bytesHex)
    window.history.replaceState({}, '', url)
    onNavigate('studio')
  }

  return (
    <section className="lab-section">
      <LabHeading
        eyebrow="الطبقة 01 · بصمة الإطار التفاعلية"
        title="استخراج بصمة aHash (64-bit)"
        summary="تحويل مصفوفة 32×32 إلى 64 بتاً عبر مقارنة متوسطات الكتل مع وسيط الإطار. يمكنك رفع أي صورة وتجربة البصمة حياً!"
        aside={<EvidenceTag tone="verified">بصمة {fp.bytesHex.slice(0, 8)}…</EvidenceTag>}
      />

      {/* Preset and Custom Image Bar */}
      <div className="card" style={{ background: 'var(--surface-dark)', border: '1px solid var(--line-dark)', borderRadius: '10px', padding: '0.85rem 1.25rem', marginBottom: '1rem', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.75rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
          <span style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>اختر إطاراً أو ارفع صورتك:</span>
          
          <button
            type="button"
            className={`button button--quiet ${activePreset === 'default' ? 'is-active' : ''}`}
            onClick={() => {
              setCustomFp(null)
              setActivePreset('default')
              setSelected(0)
              setWalkthroughStep(0)
            }}
            style={{ fontSize: '0.78rem', padding: '0.25rem 0.6rem' }}
          >
            🎬 الإطار الافتراضي #30
          </button>

          <button
            type="button"
            className={`button button--quiet ${activePreset === 'gradient' ? 'is-active' : ''}`}
            onClick={() => loadSyntheticPreset('gradient')}
            style={{ fontSize: '0.78rem', padding: '0.25rem 0.6rem' }}
          >
            🌅 تدرج ضوئي
          </button>

          <button
            type="button"
            className={`button button--quiet ${activePreset === 'checker' ? 'is-active' : ''}`}
            onClick={() => loadSyntheticPreset('checker')}
            style={{ fontSize: '0.78rem', padding: '0.25rem 0.6rem' }}
          >
            🏁 رقعة شطرنجية
          </button>
        </div>

        <div>
          <label
            htmlFor="custom-fp-upload"
            className="button button--primary"
            style={{ fontSize: '0.8rem', padding: '0.35rem 0.85rem', cursor: 'pointer', display: 'inline-flex', alignItems: 'center', gap: '0.4rem' }}
          >
            <Upload size={14} aria-hidden="true" />
            <span>رفع صورة خاصة</span>
          </label>
          <input
            id="custom-fp-upload"
            type="file"
            accept="image/*"
            onChange={handleFileUpload}
            style={{ display: 'none' }}
          />
        </div>
      </div>

      {customFp ? (
        <section className="fingerprint-walkthrough" aria-label="رحلة بصمة الصورة المرفوعة">
          <div className="fingerprint-walkthrough-head">
            <div>
              <strong>رحلة صورتك الحقيقية: {fp.name}</strong>
              <p>هذه ليست أرقام المتجه المسجل. كل مرحلة أدناه حُسبت من الصورة التي رفعتها الآن داخل المتصفح.</p>
            </div>
            <EvidenceTag tone="verified"><Hex>{fp.bytesHex}</Hex></EvidenceTag>
          </div>

          <div className="fingerprint-walkthrough-tabs" role="tablist" aria-label="مراحل بصمة الصورة">
            {walkthroughLabels.map((label, index) => (
              <button key={label} type="button" role="tab" aria-selected={walkthroughStep === index} className={walkthroughStep === index ? 'is-active' : ''} onClick={() => setWalkthroughStep(index)}>
                <b>{index + 1}</b><span>{label}</span>
              </button>
            ))}
          </div>

          <div className="fingerprint-walkthrough-stage">
            {walkthroughStep === 0 && fp.sourceDataUrl && (
              <>
                <img className="fingerprint-process-image" src={fp.sourceDataUrl} alt={`الصورة الأصلية ${fp.name}`} />
                <div className="fingerprint-process-copy"><span>المدخل الحقيقي</span><h3>الصورة الأصلية</h3><p>المتصفح يقرأ هذه الصورة فقط؛ لا يرسلها إلى خادم. أبعادها الأصلية <Hex>{fp.sourceWidth} × {fp.sourceHeight}</Hex> بكسل.</p></div>
              </>
            )}
            {walkthroughStep === 1 && fp.previewDataUrl && (
              <>
                <img className="fingerprint-process-image is-pixelated" src={fp.previewDataUrl} alt="نسخة الصورة بعد توحيدها إلى 32 في 32" />
                <div className="fingerprint-process-copy"><span>توحيد الحجم</span><h3>نرسم الصورة في <Hex>32 × 32</Hex></h3><p>لا نحتفظ بكل دقة الصورة الأصلية. الآن لدينا 1024 بكسل فقط كي تصبح المقارنة ثابتة وواضحة.</p></div>
              </>
            )}
            {walkthroughStep === 2 && fp.grayscalePreviewDataUrl && (
              <>
                <img className="fingerprint-process-image is-pixelated" src={fp.grayscalePreviewDataUrl} alt="الصورة الرمادية 32 في 32" />
                <div className="fingerprint-process-copy"><span>تحويل اللون إلى ضوء</span><h3>كل بكسل يصبح رقماً من <Hex>0</Hex> إلى <Hex>255</Hex></h3><p>نحسب <Hex>0.299R + 0.587G + 0.114B</Hex>. الأبيض قريب من 255 والأسود قريب من 0.</p></div>
              </>
            )}
            {walkthroughStep === 3 && (
              <>
                <div className="fingerprint-average-grid" aria-label="متوسطات كتل الصورة">
                  {fp.blockAverages.flat().map((value, index) => <button key={index} type="button" onClick={() => selectBlock(index)} className={selected === index ? 'is-selected' : ''} style={{ backgroundColor: `rgb(${value}, ${value}, ${value})`, color: value >= 128 ? 'var(--black)' : 'var(--white)' }}><span>{value.toFixed(0)}</span></button>)}
                </div>
                <div className="fingerprint-process-copy"><span>تقسيم وتجميع</span><h3><Hex>8 × 8</Hex> كتل، كل كتلة <Hex>4 × 4</Hex> بكسل</h3><p>نجمع 16 قيمة ضوء ونقسمها على 16. اختر أي مربع لرؤية بكسلاته في الفاحص أدناه.</p></div>
              </>
            )}
            {walkthroughStep === 4 && (
              <>
                <div className="fingerprint-bit-grid" aria-label="قرارات البتات الأربعة والستين">
                  {fp.bits.flat().map((value, index) => <button key={index} type="button" onClick={() => selectBlock(index)} className={`${value === 1 ? 'is-one' : 'is-zero'} ${selected === index ? 'is-selected' : ''}`}><span>{value}</span></button>)}
                </div>
                <div className="fingerprint-process-copy"><span>قرار واحد لكل كتلة</span><h3>نقارن المتوسط بالوسيط <Hex>{fp.median.toFixed(2)}</Hex></h3><p>إذا كان متوسط الكتلة أكبر من الوسيط أو مساوياً له فالبت <Hex>1</Hex>، وإلا فالبت <Hex>0</Hex>.</p></div>
              </>
            )}
            {walkthroughStep === 5 && (
              <div className="fingerprint-hex-stage">
                <div className="fingerprint-hex-bytes">{bitBytes.map((value, index) => <div key={index}><span>بتات {index * 8 + 1}–{index * 8 + 8}</span><Hex>{value}</Hex><strong><Hex>{parseInt(value, 2).toString(16).padStart(2, '0')}</Hex></strong></div>)}</div>
                <div className="fingerprint-process-copy"><span>تسلسل النتيجة</span><h3>64 بتاً = 8 بايت = aHash</h3><p>نقرأ صفوف شبكة البتات من اليسار إلى اليمين ومن الأعلى إلى الأسفل، ثم نحول كل 8 بتات إلى بايت Hex.</p><div className="fingerprint-final-hash"><Hex>{fp.bytesHex}</Hex></div></div>
              </div>
            )}
          </div>

          <div className="fingerprint-walkthrough-actions">
            <button type="button" className="button button--quiet" onClick={() => setWalkthroughStep((current) => Math.max(0, current - 1))} disabled={walkthroughStep === 0}>السابق</button>
            <span>المرحلة {walkthroughStep + 1} من {walkthroughLabels.length}</span>
            <button type="button" className="button button--primary" onClick={() => setWalkthroughStep((current) => Math.min(walkthroughLabels.length - 1, current + 1))} disabled={walkthroughStep === walkthroughLabels.length - 1}>التالي</button>
          </div>

          {walkthroughStep === walkthroughLabels.length - 1 && (
            <div className="fingerprint-studio-handoff">
              <div><strong>جاهز للمسار الحقيقي</strong><span>استخدم هذه البصمة نفسها لاشتقاق المفاتيح ثم الإخفاء والاسترجاع في WAV.</span></div>
              <button type="button" className="button button--primary" onClick={useFingerprintInStudio}>استخدم البصمة في الاستديو</button>
            </div>
          )}
        </section>
      ) : (
        <div className="fingerprint-upload-prompt"><ImageIcon size={20} aria-hidden="true" /><span>ارفع صورة خاصة لتظهر رحلة حساب بصمتها خطوةً خطوة.</span></div>
      )}

      <DetailsToggle open={asideOpen} onToggle={() => setAsideOpen(!asideOpen)} controls="fingerprint-detail" />

      <div className={`fingerprint-lab-layout${asideOpen ? '' : ' is-aside-folded'}`}>
        <div className="fingerprint-inspector">
          <div className="segmented-control" role="group" aria-label="نوع عرض شبكة البصمة">
            <button type="button" className={mode === 'averages' ? 'is-active' : ''} aria-pressed={mode === 'averages'} onClick={() => setMode('averages')}>متوسطات الكتل</button>
            <button type="button" className={mode === 'bits' ? 'is-active' : ''} aria-pressed={mode === 'bits'} onClick={() => setMode('bits')}>البتات الناتجة (0/1)</button>
          </div>
          <div className="fingerprint-select-grid" aria-label="اختر كتلة لفحصها">
            <FingerprintGrid
              mode={mode}
              customBits={fp.bits}
              customAverages={fp.blockAverages}
              customMedian={fp.median}
            />
            <div className="fingerprint-hit-grid" role="group" aria-label="اختر كتلة من شبكة البصمة">
              {Array.from({ length: 64 }, (_, index) => (
                <button
                  id={`fingerprint-cell-${index}`}
                  key={index}
                  type="button"
                  tabIndex={selected === index ? 0 : -1}
                  className={selected === index ? 'is-selected' : ''}
                  onClick={() => selectBlock(index)}
                  onKeyDown={(event) => onGridKeyDown(event, index)}
                  aria-pressed={selected === index}
                  aria-label={`الصف ${Math.floor(index / 8) + 1}، العمود ${(index % 8) + 1}، المتوسط ${fp.blockAverages[Math.floor(index / 8)][index % 8].toFixed(2)}، البت ${fp.bits[Math.floor(index / 8)][index % 8]}`}
                  title={`كتلة الصف ${Math.floor(index / 8)} · العمود ${index % 8}`}
                />
              ))}
            </div>
          </div>
        </div>

        <aside className="fingerprint-detail" id="fingerprint-detail" hidden={!asideOpen}>
            <span>فاحص الكتلة المختارة ({fp.name})</span>
            <strong><Hex>الصف r{row} · العمود c{column}</Hex></strong>
            
            {/* Micro 4x4 Pixel Matrix */}
            <div className="pixel-micro-matrix">
              <span className="pixel-micro-label">بكسلات الكتلة 4×4 (الكثافة الضوئية 0-255):</span>
              <div className="pixel-4x4-grid">
                {blockPixels.flat().map((p, i) => (
                  <span
                    key={i}
                    style={{ backgroundColor: `rgb(${p}, ${p}, ${p})` as string, color: p >= 118 ? 'var(--black-deep)' : 'var(--white)' }}
                    title={`بكسل: ${p}`}
                  >
                    {p}
                  </span>
                ))}
              </div>
            </div>

            <dl>
              <div><dt>مجموع البكسلات (16 بكسل)</dt><dd><Hex>{pixelSum}</Hex></dd></div>
              <div><dt>المتوسط الحسابي للكتلة</dt><dd className="text-highlight"><Hex>{average.toFixed(2)}</Hex></dd></div>
              <div><dt>الوسيط العام للإطار</dt><dd><Hex>{fp.median.toFixed(2)}</Hex></dd></div>
              <div><dt>قاعدة المقارنة</dt><dd><Hex>{average.toFixed(2)} {isBit1 ? '≥' : '<'} {fp.median.toFixed(2)}</Hex></dd></div>
              <div><dt>البت المستخرج</dt><dd className={isBit1 ? 'is-one' : ''}><Hex>{bit}</Hex></dd></div>
            </dl>
            <div className="fingerprint-output"><span>البصمة الناتجة (64-bit Hex):</span><Hex>{fp.bytesHex}</Hex></div>
        </aside>
      </div>
    </section>
  )
}

function KeysLab() {
  const [selected, setSelected] = useState<'embedding' | 'encryption' | 'authentication'>('encryption')
  const [asideOpen, setAsideOpen] = useState(() => typeof window !== 'undefined' ? window.innerWidth > 900 : true)
  const [password, setPassword] = useState('BlackRing-2028')
  const [fingerprint, setFingerprint] = useState<string>(vfcTrace.fingerprint.bytesHex)
  const [derivedKeys, setDerivedKeys] = useState<{ embedding: string, encryption: string, authentication: string } | null>(null)
  const [isDeriving, setIsDeriving] = useState(false)
  const [deriveTime, setDeriveTime] = useState(0)
  const [deriveError, setDeriveError] = useState('')
  const [showPassword, setShowPassword] = useState(false)

  const normalizedFingerprint = fingerprint.trim().toLowerCase()
  const fingerprintIsValid = /^[0-9a-f]{16}$/.test(normalizedFingerprint)
  const inputsAreValid = password.length > 0 && fingerprintIsValid

  const handleDerive = async () => {
    if (!password) {
      setDeriveError('أدخل كلمة مرور قبل الاشتقاق.')
      return
    }
    if (!fingerprintIsValid) {
      setDeriveError('البصمة يجب أن تكون 16 خانة Hex بالضبط (8 بايت).')
      return
    }

    setIsDeriving(true)
    setDeriveError('')
    const start = performance.now()
    try {
      const keys = await deriveVFCKeys(password, normalizedFingerprint)
      setDerivedKeys({
        embedding: bytesToHex(keys.kEmbed),
        encryption: bytesToHex(keys.kEnc),
        authentication: bytesToHex(keys.kAuth)
      })
      setDeriveTime(performance.now() - start)
    } catch {
      setDerivedKeys(null)
      setDeriveError('تعذّر تنفيذ PBKDF2 في هذا المتصفح. جرّب متصفحاً يدعم Web Crypto.')
    } finally {
      setIsDeriving(false)
    }
  }

  useEffect(() => {
    void handleDerive()
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const record = vfcTrace.kdf[selected]
  const names = {
    embedding: { key: 'K_embed', purpose: 'اختيار مواضع الإخفاء واشتقاق magic' },
    encryption: { key: 'K_enc', purpose: 'اشتقاق مفاتيح جولات SPN' },
    authentication: { key: 'K_auth', purpose: 'حساب HMAC-SHA256' },
  }
  
  return (
    <section className="lab-section">
      <LabHeading
        eyebrow="الطبقة 02 · فصل المجالات"
        title="اشتق مفتاحاً مستقلاً لكل وظيفة"
        summary="أدخل كلمة المرور وبصمة الإطار، ثم راقب كيف ينتج PBKDF2 ثلاثة مفاتيح مختلفة لأن لكل فرع وسم مجال ومدخل salt خاصاً به."
        aside={<EvidenceTag><Hex>200,000</Hex> دورة</EvidenceTag>}
      />

      <div className="kdf-context-note">
        <ShieldAlert size={19} aria-hidden="true" />
        <p><strong>ماذا يعني الرقم؟</strong> يعيد PBKDF2 عملية HMAC عدد <Hex>200,000</Hex> مرة لكل فرع، ثم ينتج مفتاحاً بطول <Hex>32 B</Hex>. اختلاف وسم المجال أو البصمة أو رقم الإطار يغيّر الخرج.</p>
      </div>

      <div className="kdf-workbench">
        <div className="kdf-input-grid">
          <div className="field-control">
            <div className="field-label-row">
              <label htmlFor="kdf-password">كلمة المرور</label>
              <button type="button" className="text-button" onClick={() => setShowPassword(!showPassword)}>
                {showPassword ? 'إخفاء' : 'إظهار'}
              </button>
            </div>
            <input
              id="kdf-password"
              type={showPassword ? 'text' : 'password'}
              value={password}
              autoComplete="off"
              onChange={(event) => {
                setPassword(event.target.value)
                setDerivedKeys(null)
                setDeriveError('')
              }}
              aria-invalid={!password}
            />
            <small>السر الوحيد في نموذج التهديد؛ بصمة الإطار ليست سراً.</small>
          </div>

          <div className="field-control">
            <label htmlFor="kdf-fingerprint">بصمة الإطار <Hex>64-bit</Hex></label>
            <input
              id="kdf-fingerprint"
              className="hex-input"
              dir="ltr"
              inputMode="text"
              maxLength={16}
              spellCheck={false}
              value={fingerprint}
              onChange={(event) => {
                setFingerprint(event.target.value)
                setDerivedKeys(null)
                setDeriveError('')
              }}
              aria-invalid={!fingerprintIsValid}
              aria-describedby="kdf-fingerprint-help"
            />
            <small id="kdf-fingerprint-help">16 خانة Hex = 8 بايت. تربط المفاتيح بسياق الإطار.</small>
          </div>

          <button
            type="button"
            className="button button--primary kdf-derive-button"
            onClick={() => void handleDerive()}
            disabled={isDeriving || !inputsAreValid}
          >
            {isDeriving ? 'جارٍ الاشتقاق…' : 'اشتق المفاتيح الثلاثة'}
          </button>
        </div>

        <div className={`kdf-status${deriveError ? ' is-error' : ''}`} role="status" aria-live="polite">
          {deriveError || (derivedKeys && !isDeriving
            ? `اكتمل الاشتقاق الفعلي في هذا الجهاز خلال ${deriveTime.toFixed(0)} مللي ثانية.`
            : 'غيّر أي مدخل ثم أعد الاشتقاق لمقارنة المخرجات.')}
        </div>
      </div>

      <DetailsToggle open={asideOpen} onToggle={() => setAsideOpen(!asideOpen)} controls="kdf-detail" />

      <div className={`kdf-lab-layout${asideOpen ? '' : ' is-aside-folded'}`}>
        <div>
          <div className="branch-tabs" role="group" aria-label="فروع اشتقاق المفاتيح">
            {(Object.keys(names) as Array<keyof typeof names>).map((key) => (
              <button key={key} type="button" aria-pressed={selected === key} className={selected === key ? 'is-active' : ''} onClick={() => setSelected(key)}><Hex>{names[key].key}</Hex><span>{names[key].purpose}</span></button>
            ))}
          </div>
          <KeyTree selected={selected} outputs={derivedKeys ?? { embedding: null, encryption: null, authentication: null }} />
        </div>
        <aside className="kdf-inspector" id="kdf-detail" hidden={!asideOpen}>
            <span>ترتيب مدخل salt الفعلي لهذا الفرع</span>
            <div className="kdf-parts" dir="ltr">
              {record.pbkdf2SaltPartsInExactOrder.map((part, index) => (
                <div key={part.name}>
                  <small>{index + 1}</small>
                  <b>{part.name}</b>
                  <Hex>{part.name === 'fingerprint' ? normalizedFingerprint || '—' : 'ascii' in part ? part.ascii : part.hex}</Hex>
                </div>
              ))}
            </div>
            <dl>
              <div><dt>الخوارزمية</dt><dd><Hex>{record.primitive}</Hex></dd></div>
              <div><dt>طول الخرج</dt><dd><Hex>{record.derivedKeyBytes} B</Hex></dd></div>
              <div><dt>الغرض</dt><dd>{names[selected].purpose}</dd></div>
            </dl>
            <div className="kdf-output">
              <span>خرج الفرع المحدد · 32 بايت</span>
              <Hex>{derivedKeys ? derivedKeys[selected] : 'أعد الاشتقاق بعد تعديل المدخلات'}</Hex>
            </div>
        </aside>
      </div>
    </section>
  )
}

function GaloisFieldLab() {
  return (
    <section className="lab-section">
      <LabHeading
        eyebrow="الأساس الرياضي · قبل MixColumns"
        title="حقل غالوا GF(2⁸): كيف نحسب داخل بايت واحد؟"
        summary="ابدأ من معنى البتات، ثم جرّب XOR والضرب في 2 و3، وأخيراً اربط الحساب بمصفوفة MixColumns القابلة للعكس."
        aside={<EvidenceTag tone="source"><Hex>m(x) = 0x11B</Hex></EvidenceTag>}
      />

      <div className="concept-bridge">
        <strong>مكانه في النظام</strong>
        <span><Hex>GF(2⁸)</Hex> ليس طريقة اشتقاق مفتاح ولا نمط ربط كتل؛ هو الحساب الذي تستخدمه طبقة <Hex>MixColumns</Hex> داخل كل جولة SPN.</span>
      </div>

      <GaloisFieldExplorer />
    </section>
  )
}

type CipherLayer = 'subBytes' | 'shiftRows' | 'mixColumns' | 'addRoundKey'

const cipherLayerLabels: Record<CipherLayer, { name: string; arabic: string }> = {
  subBytes: { name: 'SubBytes', arabic: 'استبدال S-Box' },
  shiftRows: { name: 'ShiftRows', arabic: 'إزاحة الصفوف' },
  mixColumns: { name: 'MixColumns', arabic: 'خلط الأعمدة' },
  addRoundKey: { name: 'AddRoundKey', arabic: 'إضافة المفتاح' },
}

function CipherLab() {
  const [round, setRound] = useState<number>(1)
  const [layer, setLayer] = useState<CipherLayer>('subBytes')
  const [compare, setCompare] = useState(false)
  const [asideOpen, setAsideOpen] = useState(() => typeof window !== 'undefined' ? window.innerWidth > 900 : true)
  const verifiedBlockHex = vfcTrace.cipher.blockTrace.input.bytesHex
  const [blockInput, setBlockInput] = useState<string>(verifiedBlockHex)
  const [appliedBlockHex, setAppliedBlockHex] = useState<string>(verifiedBlockHex)
  const [blockError, setBlockError] = useState('')
  const blockIsValid = /^[0-9a-fA-F]{32}$/.test(blockInput.trim())
  const roundKeysBytes = useMemo(() => vfcTrace.cipher.roundKeys.map((item) => hexToBytes(item.hex)), [])
  const liveTrace = useMemo(
    () => traceVFCBlockLayers(hexToBytes(appliedBlockHex), roundKeysBytes),
    [appliedBlockHex, roundKeysBytes]
  )
  const isVerifiedVector = appliedBlockHex === verifiedBlockHex

  const isWhitening = round === 0
  const roundData = !isWhitening ? liveTrace.rounds[round - 1] : null
  const state = isWhitening ? liveTrace.initialWhitening : roundData![layer]

  const comparison = !isVerifiedVector ? undefined : isWhitening
    ? vfcTrace.cipher.oneBitFlip.roundOutputDiffusion[1]
    : round === 1
      ? vfcTrace.cipher.oneBitFlip.firstRoundLayerDiffusion.find((item) => item.stage === layer)
      : layer === 'addRoundKey'
        ? vfcTrace.cipher.oneBitFlip.roundOutputDiffusion[round + 1]
        : undefined

  return (
    <section className="lab-section">
      <LabHeading
        eyebrow="الطبقة 03 · التشفير الكتلي"
        title="غيّر كتلة 16 بايت وتتبع تحولها"
        summary="افهم أولاً من أين تأتي SPN، ثم أدخل كتلة Hex كاملة وافحص التمهيد وكل طبقة من طبقات الجولات الست على مصفوفة 4×4 بايت."
        aside={<EvidenceTag tone={isVerifiedVector ? 'verified' : 'source'}>{isVerifiedVector ? 'متجه موثّق' : 'حساب مباشر'}</EvidenceTag>}
      />

      <div className="spn-origin">
        <div className="spn-origin-copy">
          <span className="gf-kicker">من أين تأتي SPN؟</span>
          <h2>هي بنية شيفرة الكتلة في VFC</h2>
          <p><Hex>SPN</Hex> اختصار <Hex>Substitution–Permutation Network</Hex>. ليست خطوة خارجية تضاف إلى CBC؛ إنها الدالة <Hex>E(K, X)</Hex> التي تحوّل كتلة دخل واحدة إلى كتلة مشفرة واحدة.</p>
        </div>
        <div className="spn-input-map">
          <div><small>مسار البيانات</small><strong>كتلة X · 16 بايت</strong><span>تحويل column-major إلى حالة 4×4</span></div>
          <b>+</b>
          <div><small>مسار المفتاح</small><strong>K_enc</strong><span>اشتقاق RK₀ … RK₆</span></div>
          <b>→</b>
          <div className="is-output"><small>شيفرة الكتلة</small><strong>SPN</strong><span>RK₀ ثم 6 جولات</span></div>
        </div>
        <div className="spn-layer-definitions">
          <span><b>SubBytes</b> يبدّل كل بايت</span>
          <span><b>ShiftRows</b> ينقل المواقع</span>
          <span><b>MixColumns</b> ينشر الأثر بحساب GF</span>
          <span><b>AddRoundKey</b> يربط الحالة بمفتاح الجولة</span>
        </div>
      </div>

      <div className="block-input-workbench">
        <div className="field-control">
          <label htmlFor="cipher-block-input">كتلة SPN مستقلة (16 بايت)</label>
          <input
            id="cipher-block-input"
            className="hex-input"
            dir="ltr"
            inputMode="text"
            maxLength={32}
            spellCheck={false}
            value={blockInput}
            aria-invalid={!blockIsValid}
            aria-describedby="cipher-block-help"
            onChange={(event) => {
              setBlockInput(event.target.value)
              setBlockError('')
            }}
            onKeyDown={(event) => {
              if (event.key === 'Enter' && blockIsValid) {
                const next = blockInput.trim().toLowerCase()
                setAppliedBlockHex(next)
                setCompare(false)
              }
            }}
          />
          <small id="cipher-block-help">32 خانة Hex = 16 بايت. نتعامل معها هنا كمدخل عام؛ في فصل CBC سترى كيف تتكوّن فعلياً من <Hex>Xᵢ = Pᵢ ⊕ السابق</Hex>.</small>
        </div>
        <div className="block-input-actions">
          <button
            type="button"
            className="button button--primary"
            disabled={!blockIsValid}
            onClick={() => {
              if (!blockIsValid) {
                setBlockError('أدخل 32 خانة Hex بالضبط.')
                return
              }
              setAppliedBlockHex(blockInput.trim().toLowerCase())
              setCompare(false)
              setBlockError('')
            }}
          >
            طبّق الكتلة وتتبعها
          </button>
          <button
            type="button"
            className="button button--quiet"
            onClick={() => {
              setBlockInput(verifiedBlockHex)
              setAppliedBlockHex(verifiedBlockHex)
              setBlockError('')
              setCompare(false)
            }}
          >
            <RotateCcw size={16} aria-hidden="true" />
            استعادة المتجه الموثّق
          </button>
        </div>
        <p className={`block-input-status${blockError ? ' is-error' : ''}`} role="status">
          {blockError || (isVerifiedVector
            ? 'تعرض المقارنات أرقام الأثر المولّد من تنفيذ Python والمتحقق منه.'
            : 'هذه الحالة محسوبة مباشرة في المتصفح بالمفاتيح الدورية الموثّقة؛ أعد المتجه لإظهار مقارنة قلب البت المسجلة.')}
        </p>
      </div>

      <DetailsToggle open={asideOpen} onToggle={() => setAsideOpen(!asideOpen)} controls="cipher-detail" />

      <div className="cipher-console">
        <div className="cipher-controls">
          <div className="round-selector" role="group" aria-label="اختر الجولة">
            <span>الجولة:</span>
            <button
              type="button"
              className={round === 0 ? 'is-active is-whitening-btn' : 'is-whitening-btn'}
              aria-pressed={round === 0}
              onClick={() => {
                setRound(0)
              }}
              title="مفتاح التمهيد الأولي RK0 (Whitening)"
            >
              RK₀
            </button>
            {[1, 2, 3, 4, 5, 6].map((item) => (
              <button
                key={item}
                type="button"
                className={round === item ? 'is-active' : ''}
                aria-pressed={round === item}
                onClick={() => {
                  setRound(item)
                }}
              >
                {item}
              </button>
            ))}
          </div>

          <div className="layer-tabs" role="group" aria-label="طبقات الجولة">
            {isWhitening ? (
              <button type="button" className="is-active" aria-pressed={true}>
                <Hex>Initial Whitening (XOR مع RK₀)</Hex>
              </button>
            ) : (
              (['subBytes', 'shiftRows', 'mixColumns', 'addRoundKey'] as CipherLayer[]).map((item) => (
                <button
                  key={item}
                  type="button"
                  aria-pressed={layer === item}
                  className={layer === item ? 'is-active' : ''}
                  onClick={() => {
                    setLayer(item)
                  }}
                >
                  <strong><Hex>{cipherLayerLabels[item].name}</Hex></strong>
                  <small>{cipherLayerLabels[item].arabic}</small>
                </button>
              ))
            )}
          </div>

          <button
            type="button"
            className={`compare-toggle${compare ? ' is-active' : ''}`}
            aria-pressed={compare}
            disabled={!comparison}
            title={comparison ? undefined : isVerifiedVector ? 'اختر AddRoundKey لعرض المقارنة الموثّقة لهذه الجولة' : 'أعد المتجه الموثّق لعرض مقارنة قلب البت المسجلة'}
            onClick={() => setCompare(!compare)}
          >
            <RotateCcw size={17} aria-hidden="true" />
            {compare ? 'إخفاء المقارنة' : 'قارن بعد قلب بت واحد'}
          </button>
        </div>

        <div className={`cipher-stage-grid${asideOpen ? '' : ' is-aside-folded'}${compare && comparison ? ' is-comparing' : ''}`}>
          <div className="matrix-stage">
            <span className="matrix-stage-label">
              {isWhitening ? 'Initial Whitening (RK₀)' : `R${round} · ${cipherLayerLabels[layer].name}`}
              {compare && comparison ? ' · مقارنة فعلية مع المتغير' : ''}
            </span>
            {compare && comparison ? (
              <div className="matrix-compare-pair matrix-compare-pair--cipher">
                <div>
                  <span>الحالة الأصلية</span>
                  <StateMatrix grid={state.gridHex} label={`الحالة الأصلية بعد ${isWhitening ? 'Whitening' : layer} في الجولة ${round}`} compact />
                  <Hex className="matrix-serialized">{state.bytesHex}</Hex>
                </div>
                <div>
                  <span>بعد قلب البت #{vfcTrace.cipher.oneBitFlip.bitIndex}</span>
                  <StateMatrix
                    grid={comparison.oneBitVariant.gridHex}
                    compare={state.gridHex}
                    label={`الحالة بعد قلب البت رقم ${vfcTrace.cipher.oneBitFlip.bitIndex}`}
                    compact
                  />
                  <Hex className="matrix-serialized matrix-serialized--variant">{comparison.oneBitVariant.bytesHex}</Hex>
                </div>
                <aside aria-live="polite">
                  <span>الفرق في هذه المرحلة</span>
                  <strong>
                    <Hex>{comparison.changedBits}</Hex>
                    <small>من 128 بتاً</small>
                  </strong>
                  <p><Hex>{comparison.changedBytes}/16</Hex> بايتاً تغيّر</p>
                  <Hex>{comparison.xorHex}</Hex>
                </aside>
              </div>
            ) : (
              <>
                <StateMatrix grid={state.gridHex} />
                <Hex className="matrix-serialized">{state.bytesHex}</Hex>
              </>
            )}
          </div>

          <aside className="cipher-evidence" id="cipher-detail" hidden={!asideOpen}>
            <RoundFlow active={isWhitening ? 'addRoundKey' : layer} />
            <dl>
              <div><dt>تنسيق الحالة</dt><dd>4×4 byte · column-major</dd></div>
              <div><dt>مفتاح الجولة</dt><dd><Hex>{vfcTrace.cipher.roundKeys[round].hex}</Hex></dd></div>
              <div><dt>كثير حدود GF</dt><dd><Hex>{vfcTrace.cipher.gfPolynomialHex}</Hex></dd></div>
              {comparison && <div><dt>فرق البديل</dt><dd><Hex>{comparison.changedBytes}/16 bytes · {comparison.changedBits} bits</Hex></dd></div>}
            </dl>
          </aside>
        </div>

        {/* Interactive Layer Visualizers */}
        <div className="cipher-sub-visualizer">
          {isWhitening && (
            <AddRoundKeyVisualizer
              inputState={liveTrace.input.gridHex}
              roundKey={vfcTrace.cipher.roundKeys[0].gridHex}
              outputState={liveTrace.initialWhitening.gridHex}
              roundNum={0}
            />
          )}
          {!isWhitening && layer === 'subBytes' && <InteractiveSBox />}
          {!isWhitening && layer === 'shiftRows' && <ShiftRowsVisualizer state={roundData!.subBytes.gridHex} />}
          {!isWhitening && layer === 'mixColumns' && (
            <MixColumnsVisualizer
              inputState={roundData!.shiftRows.gridHex}
              outputState={roundData!.mixColumns.gridHex}
            />
          )}
          {!isWhitening && layer === 'addRoundKey' && (
            <AddRoundKeyVisualizer
              inputState={roundData!.mixColumns.gridHex}
              roundKey={vfcTrace.cipher.roundKeys[round].gridHex}
              outputState={roundData!.addRoundKey.gridHex}
              roundNum={round}
            />
          )}
        </div>
      </div>
    </section>
  )
}

function DiffusionLab() {
  const [step, setStep] = useState(0)
  const [bitIndex, setBitIndex] = useState(0)

  // Compute base trace once
  const baseInputHex = vfcTrace.cipher.oneBitFlip.inputHex
  const baseInputBytes = useMemo(() => hexToBytes(baseInputHex), [baseInputHex])
  const roundKeysBytes = useMemo(() => vfcTrace.cipher.roundKeys.map((rk) => hexToBytes(rk.hex)), [])
  const baseTrace = useMemo(() => encryptVFCBlockTrace(baseInputBytes, roundKeysBytes), [baseInputBytes, roundKeysBytes])

  // Compute variant trace based on bitIndex
  const variantTrace = useMemo(() => {
    const variant = new Uint8Array(baseInputBytes)
    const byteIdx = Math.floor(bitIndex / 8)
    const bitOffset = 7 - (bitIndex % 8)
    variant[byteIdx] ^= 1 << bitOffset
    return encryptVFCBlockTrace(variant, roundKeysBytes)
  }, [baseInputBytes, roundKeysBytes, bitIndex])

  const toGridHex = (bytes: Uint8Array) => {
    const grid: string[][] = [[], [], [], []]
    for (let c = 0; c < 4; c++) {
      for (let r = 0; r < 4; r++) {
        grid[r][c] = bytes[c * 4 + r].toString(16).padStart(2, '0')
      }
    }
    return grid
  }

  const baseStepBytes = baseTrace[step]
  const variantStepBytes = variantTrace[step]

  let changedBits = 0
  let changedBytes = 0
  const xorBytesArr = new Uint8Array(16)
  for (let i = 0; i < 16; i++) {
    const x = baseStepBytes[i] ^ variantStepBytes[i]
    xorBytesArr[i] = x
    if (x !== 0) changedBytes++
    let temp = x
    while (temp > 0) {
      changedBits += temp & 1
      temp >>= 1
    }
  }

  const baseGridHex = toGridHex(baseStepBytes)
  const variantGridHex = toGridHex(variantStepBytes)
  const xorHex = bytesToHex(xorBytesArr)

  const stages = ['IN', 'RK₀', 'R1', 'R2', 'R3', 'R4', 'R5', 'R6']
  const stageSizes = ['1 B', '1 B', '4 B', '16 B', '16 B', '16 B', '16 B', '16 B']

  return (
    <section className="lab-section">
      <LabHeading
        eyebrow="الطبقة 04 · انتشار التغيير (تفاعلي)"
        title="أثر الانهيار الثلجي (Avalanche Effect)"
        summary="أثر قلب بت واحد في المدخل وانتشاره عبر 128 بت. جرب تغيير البت وشاهد الانتشار الحي!"
        aside={<EvidenceTag tone="verified">متوسط {vfcTrace.measurements.avalanche.averageChangedPercent.toFixed(1)}%</EvidenceTag>}
      />

      <div className="diffusion-lab">
        <div className="card" style={{ background: 'var(--surface-dark)', border: '1px solid var(--line-dark)', borderRadius: '10px', padding: '1rem', marginBottom: '1.5rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
            <label htmlFor="bit-slider" style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
              اختر البت المراد قلبه (0 - 127):
            </label>
            <strong style={{ color: 'var(--primary)' }}>البت #{bitIndex}</strong>
          </div>
          <input
            id="bit-slider"
            type="range"
            min="0"
            max="127"
            value={bitIndex}
            onChange={(e) => setBitIndex(Number(e.target.value))}
            style={{ width: '100%', cursor: 'pointer' }}
          />
        </div>

        <div className="diffusion-stepper" role="group" aria-label="مراحل انتشار البت">
          {stages.map((stage, index) => (
            <button
              key={stage}
              type="button"
              className={step === index ? 'is-active' : ''}
              aria-pressed={step === index}
              onClick={() => setStep(index)}
            >
              <span>{stage}</span>
              <small>{stageSizes[index]}</small>
            </button>
          ))}
        </div>
        <div className="matrix-compare-pair">
          <div>
            <span>الحالة الأصلية</span>
            <StateMatrix grid={baseGridHex} compact />
          </div>
          <div>
            <span>بعد قلب البت #{bitIndex}</span>
            <StateMatrix grid={variantGridHex} compare={baseGridHex} compact />
          </div>
          <aside>
            <span>الفرق عند هذه المرحلة</span>
            <strong>
              <Hex>{changedBits}</Hex>
              <small>
                بتاً (<Hex>{((changedBits / 128) * 100).toFixed(1)}%</Hex>)
              </small>
            </strong>
            <p>
              <Hex>{changedBytes}/16</Hex> بايتاً متأثراً
            </p>
            <Hex>{xorHex}</Hex>
          </aside>
        </div>

        <AvalancheChart note="نتيجة حيّة للمتجه التعليمي المحدد · معدل الانتشار يتقارب حول 50%" />
      </div>
    </section>
  )
}

function CbcLab() {
  const [text, setText] = useState('VFC Cipher!')
  const plaintextByteLength = new TextEncoder().encode(text).length
  const paddingLength = 16 - (plaintextByteLength % 16)
  
  // Use pre-generated round keys and IV from vfcTrace for the demo
  const roundKeysBytes = useMemo(() => vfcTrace.cipher.roundKeys.map((rk) => hexToBytes(rk.hex)), [])
  const iv = useMemo(() => hexToBytes(vfcTrace.cbc.ivHex), [])

  const dynamicBlocks = useMemo(() => {
    const plaintextBytes = new TextEncoder().encode(text)
    const padded = padPKCS7(plaintextBytes)
    
    const blocks = []
    let prev = iv
    
    for (let i = 0; i < padded.length; i += 16) {
      const pBlock = padded.slice(i, i + 16)
      const xorBlock = xorBytes(pBlock, prev)
      const trace = encryptVFCBlockTrace(xorBlock, roundKeysBytes)
      const cBlock = trace[trace.length - 1]
      
      blocks.push({
        block: i / 16 + 1,
        plaintext: bytesToHex(pBlock),
        previous: bytesToHex(prev),
        xorInput: bytesToHex(xorBlock),
        ciphertext: bytesToHex(cBlock),
      })
      
      prev = cBlock
    }
    return blocks
  }, [text, roundKeysBytes, iv])

  const [activeBlock, setActiveBlock] = useState(0)
  const current = dynamicBlocks[activeBlock] || dynamicBlocks[0]

  return (
    <section className="lab-section">
      <LabHeading
        eyebrow="نمط التشغيل · CBC حول شيفرة SPN"
        title="كيف تتحول الكتلة Pᵢ إلى Cᵢ؟"
        summary="بعد حشو PKCS#7 وتقسيم النص، يصنع CBC كتلة Xᵢ بعملية XOR ثم يستدعي شيفرة SPN نفسها التي فحصناها في الفصل السابق."
        aside={<EvidenceTag tone="verified"><Hex>{dynamicBlocks.length * 16} B</Hex> {dynamicBlocks.length} كتل</EvidenceTag>}
      />

      <div className="cbc-order-explainer">
        <div>
          <span>ترتيب الشرح</span>
          <strong>نتعلم SPN أولاً ← ثم نضعها داخل CBC</strong>
          <p>لأن فهم الدالة <Hex>E(K, X)</Hex> منفردة يجعل الربط بين الكتل أسهل.</p>
        </div>
        <div>
          <span>ترتيب التنفيذ داخل كل كتلة</span>
          <strong><Hex>Xᵢ = Pᵢ ⊕ (IV أو Cᵢ₋₁)</Hex> ← ثم <Hex>Cᵢ = SPN(K, Xᵢ)</Hex></strong>
          <p>إذن <b>اربط كتل التشفير</b> يأتي قبل SPN في التنفيذ، لكنه يأتي بعدها في ترتيب الدروس.</p>
        </div>
      </div>

      <div className="card" style={{ background: 'var(--surface-dark)', border: '1px solid var(--line-dark)', borderRadius: '10px', padding: '1rem', marginBottom: '1.5rem' }}>
        <label htmlFor="cbc-input" style={{ display: 'block', fontSize: '0.85rem', color: 'var(--text-muted)', marginBottom: '0.5rem' }}>
          أدخل النص السري لرؤية تقسيمه وتشفيره بشكل تفاعلي:
        </label>
        <input 
          id="cbc-input"
          type="text" 
          value={text} 
          onChange={(e) => {
            setText(e.target.value)
            setActiveBlock(0)
          }}
          style={{ width: '100%', padding: '0.75rem', borderRadius: '6px', border: '1px solid var(--line-dark)', background: 'var(--black-deep)', color: 'white', fontFamily: 'monospace' }}
          placeholder="Type a secret message..."
        />
        <div className="cbc-padding-note">
          <span>النص بترميز UTF-8: <Hex>{plaintextByteLength} B</Hex></span>
          <span>حشو PKCS#7: <Hex>{paddingLength}</Hex> بايت بقيمة <Hex>0x{paddingLength.toString(16).padStart(2, '0')}</Hex></span>
          <span>بعد الحشو: <Hex>{plaintextByteLength + paddingLength} B</Hex> = <Hex>{dynamicBlocks.length}</Hex> كتل</span>
        </div>
      </div>

      <div style={{ overflowX: 'auto', paddingBottom: '1rem' }}>
        <CbcDiagram dynamicBlocks={dynamicBlocks} />
      </div>

      {current && (
        <div className="cbc-lab-grid" style={{ marginTop: '1rem' }}>
          <div className="block-toggle" role="group" aria-label="اختر كتلة CBC">
            {dynamicBlocks.map((_, index) => (
              <button 
                key={index} 
                type="button" 
                className={activeBlock === index ? 'is-active' : ''} 
                aria-pressed={activeBlock === index} 
                onClick={() => setActiveBlock(index)}
              >
                الكتلة {index + 1}
              </button>
            ))}
          </div>
          <div className="cbc-operation">
            <div><span>P{current.block}</span><Hex>{current.plaintext}</Hex></div>
            <b>⊕</b>
            <div><span>{activeBlock === 0 ? 'IV' : `C${activeBlock}`}</span><Hex>{current.previous}</Hex></div>
            <b>=</b>
            <div><span>مدخل SPN</span><Hex>{current.xorInput}</Hex></div>
            <ChevronRight aria-hidden="true" />
            <div className="is-output"><span>C{current.block}</span><Hex>{current.ciphertext}</Hex></div>
          </div>
        </div>
      )}

      <div className="integrity-proof">
        <ShieldCheck size={22} aria-hidden="true" />
        <div>
          <strong>التلاعب لا يصل إلى CBC-decrypt</strong>
          <p>أي تعديل على النص المشفر يُرفض فوراً عند فحص HMAC قبل فك أي كتلة.</p>
        </div>
        <EvidenceTag tone="verified">
          {vfcTrace.validation.assertions.singleCiphertextBitTamperRejected ? 'PASS' : 'FAIL'}
        </EvidenceTag>
      </div>
    </section>
  )
}

function PayloadLab() {
  const [selected, setSelected] = useState('ciphertext')
  const [asideOpen, setAsideOpen] = useState(() => typeof window !== 'undefined' ? window.innerWidth > 900 : true)
  const field = vfcTrace.payload.fields.find((item) => item.name === selected) ?? vfcTrace.payload.fields[0]
  const value = 'value' in field ? field.value : undefined
  const meaning = 'meaning' in field ? field.meaning : undefined
  return (
    <section className="lab-section">
      <LabHeading
        eyebrow="تنسيق الحمولة الخارجية · المتجه المسجل"
        title="حمولة هذا المتجه: 114 بايتاً"
        summary="المسطرة أدناه تخص المتجه المسجل ذي النص المشفر 32B. القاعدة العامة هي ترويسة 50B + نص مشفر متغير + وسم HMAC بطول 32B."
        aside={<EvidenceTag tone="verified"><Hex>50 + 32 + 32 = 114 B</Hex></EvidenceTag>}
      />

      <div className="payload-size-rule">
        <div><span>الحجم الثابت</span><strong><Hex>50 B header + 32 B HMAC = 82 B</Hex></strong></div>
        <b>+</b>
        <div><span>الحجم المتغير</span><strong><Hex>Ciphertext = 16, 32, 48… B</Hex></strong></div>
        <b>=</b>
        <div><span>الحجم الكلي</span><strong><Hex>82 B + ciphertext length</Hex></strong></div>
      </div>

      <div className="card" style={{ marginBottom: '1rem', padding: '1rem 1.25rem' }}>
        <strong style={{ color: 'var(--accent)' }}>مسار الاستخراج بالعكس</strong>
        <p style={{ color: 'var(--text-muted)', lineHeight: 1.7, margin: '0.55rem 0 0' }}>
          البصمة + كلمة المرور + رقم الإطار ⟵ اشتقاق <Hex>K_embed</Hex> ⟵ قراءة أول 50B من المواضع ⟵ أخذ salt وIV وct_len ⟵ اشتقاق <Hex>K_enc</Hex> و<Hex>K_auth</Hex> ⟵ استخراج بقية الحمولة ⟵ فحص HMAC أولاً ⟵ فك CBC الذي يستدعي SPN العكسي ⟵ إزالة PKCS#7 وفك الحزمة الداخلية.
        </p>
      </div>

      <DetailsToggle open={asideOpen} onToggle={() => setAsideOpen(!asideOpen)} controls="payload-detail" />

      <div className={`payload-lab${asideOpen ? '' : ' is-aside-folded'}`}>
        <PayloadRuler
          selected={selected}
          onSelect={(name) => {
            setSelected(name)
            setAsideOpen(true)
          }}
        />
        <div className="payload-inspector" id="payload-detail" hidden={!asideOpen}>
            <div><span>الحقل</span><strong><Hex>{field.name}</Hex></strong></div>
            <dl>
              <div><dt>الإزاحة</dt><dd><Hex>{field.offset}</Hex></dd></div>
              <div><dt>النهاية</dt><dd><Hex>{field.offset + field.sizeBytes - 1}</Hex></dd></div>
              <div><dt>الحجم</dt><dd><Hex>{field.sizeBytes} B</Hex></dd></div>
              {value !== undefined && <div><dt>القيمة</dt><dd><Hex>{value}</Hex></dd></div>}
            </dl>
            {meaning && <p>{meaning}</p>}
            <div className="payload-hex"><span>البايتات</span><Hex>{field.hex}</Hex></div>
        </div>
      </div>
    </section>
  )
}

function AudioCapacityCalculator() {
  const [durationSec, setDurationSec] = useState(30)
  const [sampleRate, setSampleRate] = useState(48000)
  const [channelCount, setChannelCount] = useState(1)
  const [eligiblePercent, setEligiblePercent] = useState(65)
  const [fileName, setFileName] = useState('secret.bin')

  const totalSamples = Math.round(durationSec * sampleRate * channelCount)
  const eligibleEstimate = Math.round(totalSamples * (eligiblePercent / 100))
  const rawCapacityBytes = Math.floor(eligibleEstimate / 8)
  const outerOverheadBytes = 50 + 32
  const ciphertextCapacityBytes = Math.floor(Math.max(0, rawCapacityBytes - outerOverheadBytes) / 16) * 16
  const filenameBytes = new TextEncoder().encode(fileName || 'secret.bin').length
  const innerMetadataBytes = 2 + filenameBytes + 8 + 1
  const maxUncompressedFileBytes = Math.max(0, ciphertextCapacityBytes - innerMetadataBytes - 1)
  const largestPayloadBytes = outerOverheadBytes + ciphertextCapacityBytes

  const presets = [
    { label: '10 ثوانٍ', duration: 10, rate: 44100, ch: 1 },
    { label: '30 ثانية', duration: 30, rate: 48000, ch: 1 },
    { label: 'دقيقة', duration: 60, rate: 48000, ch: 1 },
    { label: '3 دقائق', duration: 180, rate: 48000, ch: 2 },
    { label: '5 دقائق', duration: 300, rate: 48000, ch: 2 },
  ]

  return (
    <div style={{ background: 'var(--black-deep)', border: '1px solid var(--line-dark)', borderRadius: '8px', padding: '1rem 1.25rem', marginTop: '1rem' }}>
      <h4 style={{ color: 'var(--accent)', fontSize: '0.9rem', marginBottom: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
        <Activity size={16} aria-hidden="true" />
        حاسبة السعة الإخفائية
      </h4>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '0.75rem', marginBottom: '1rem' }}>
        <label style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>المدة (ثوانٍ)</span>
          <input
            type="number"
            min={1}
            max={600}
            value={durationSec}
            onChange={(e) => setDurationSec(Math.max(1, Number(e.target.value)))}
            style={{ background: 'var(--ink)', border: '1px solid var(--line-dark)', borderRadius: '6px', padding: '0.4rem 0.6rem', color: 'var(--white)', fontFamily: 'monospace', fontSize: '0.85rem' }}
          />
        </label>
        <label style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>معدل العينات (Hz)</span>
          <select
            value={sampleRate}
            onChange={(e) => setSampleRate(Number(e.target.value))}
            style={{ background: 'var(--ink)', border: '1px solid var(--line-dark)', borderRadius: '6px', padding: '0.4rem 0.6rem', color: 'var(--white)', fontSize: '0.85rem' }}
          >
            <option value={22050}>22,050 Hz</option>
            <option value={44100}>44,100 Hz</option>
            <option value={48000}>48,000 Hz</option>
            <option value={96000}>96,000 Hz</option>
          </select>
        </label>
        <label style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>القنوات</span>
          <select
            value={channelCount}
            onChange={(e) => setChannelCount(Number(e.target.value))}
            style={{ background: 'var(--ink)', border: '1px solid var(--line-dark)', borderRadius: '6px', padding: '0.4rem 0.6rem', color: 'var(--white)', fontSize: '0.85rem' }}
          >
            <option value={1}>أحادي (Mono)</option>
            <option value={2}>ستيريو (Stereo)</option>
          </select>
        </label>
        <label style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>نسبة العينات المؤهلة المقدّرة (%)</span>
          <input
            type="number"
            min={1}
            max={100}
            value={eligiblePercent}
            onChange={(e) => setEligiblePercent(Math.max(1, Math.min(100, Number(e.target.value))))}
            style={{ background: 'var(--ink)', border: '1px solid var(--line-dark)', borderRadius: '6px', padding: '0.4rem 0.6rem', color: 'var(--white)', fontFamily: 'monospace', fontSize: '0.85rem' }}
          />
        </label>
        <label style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>اسم الملف داخل الحزمة</span>
          <input
            type="text"
            value={fileName}
            onChange={(e) => setFileName(e.target.value)}
            style={{ background: 'var(--ink)', border: '1px solid var(--line-dark)', borderRadius: '6px', padding: '0.4rem 0.6rem', color: 'var(--white)', fontSize: '0.85rem' }}
          />
        </label>
      </div>

      {/* Quick presets */}
      <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap', marginBottom: '1rem' }}>
        {presets.map((p) => (
          <button
            key={p.label}
            type="button"
            className="button button--quiet"
            onClick={() => { setDurationSec(p.duration); setSampleRate(p.rate); setChannelCount(p.ch); }}
            style={{ fontSize: '0.7rem', padding: '0.2rem 0.5rem' }}
          >
            {p.label}
          </button>
        ))}
      </div>

      {/* Results */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: '0.75rem' }}>
        <div style={{ background: 'var(--ink-raised)', padding: '0.75rem', borderRadius: '6px', textAlign: 'center' }}>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: '0.2rem' }}>إجمالي العينات</div>
          <div style={{ fontSize: '1rem', color: 'var(--white)', fontWeight: 700, fontFamily: 'monospace' }}>{totalSamples.toLocaleString()}</div>
        </div>
        <div style={{ background: 'var(--ink-raised)', padding: '0.75rem', borderRadius: '6px', textAlign: 'center' }}>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: '0.2rem' }}>عينات مؤهلة مقدّرة ({eligiblePercent}%)</div>
          <div style={{ fontSize: '1rem', color: 'var(--accent)', fontWeight: 700, fontFamily: 'monospace' }}>{eligibleEstimate.toLocaleString()}</div>
        </div>
        <div style={{ background: 'var(--ink-raised)', padding: '0.75rem', borderRadius: '6px', textAlign: 'center' }}>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: '0.2rem' }}>السعة الخام للصوت</div>
          <div style={{ fontSize: '1rem', color: 'var(--green-bright)', fontWeight: 700, fontFamily: 'monospace' }}>
            {eligibleEstimate.toLocaleString()} bit · {rawCapacityBytes.toLocaleString()} B
          </div>
        </div>
        <div style={{ background: 'var(--ink-raised)', padding: '0.75rem', borderRadius: '6px', textAlign: 'center' }}>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: '0.2rem' }}>أكبر نص مشفر بمضاعفات 16B</div>
          <div style={{ fontSize: '1rem', color: '#cba6f7', fontWeight: 700, fontFamily: 'monospace' }}>
            {ciphertextCapacityBytes.toLocaleString()} B
          </div>
        </div>
        <div style={{ background: 'var(--ink-raised)', padding: '0.75rem', borderRadius: '6px', textAlign: 'center' }}>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: '0.2rem' }}>أكبر ملف غير مضغوط</div>
          <div style={{ fontSize: '1rem', color: 'var(--tan)', fontWeight: 700, fontFamily: 'monospace' }}>
            {maxUncompressedFileBytes.toLocaleString()} B
          </div>
        </div>
        <div style={{ background: 'var(--ink-raised)', padding: '0.75rem', borderRadius: '6px', textAlign: 'center' }}>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: '0.2rem' }}>أكبر حمولة خارجية</div>
          <div style={{ fontSize: '1rem', color: 'var(--white)', fontWeight: 700, fontFamily: 'monospace' }}>{largestPayloadBytes.toLocaleString()} B</div>
        </div>
      </div>

      <div style={{ marginTop: '0.75rem', fontSize: '0.7rem', color: 'var(--text-muted)', lineHeight: 1.5 }}>
        هذه حاسبة تقديرية لأن المدة ومعدل العينات لا يكشفان عدد العينات التي تحقق القاعدة <Hex>|sample ≫ 1| ≥ 2</Hex>.
        الحجم يحجز <Hex>82 B</Hex> للترويسة وHMAC، ثم يحسب كتل CBC ومعلومات الملف الداخلية والحشو. افحص ملف الحامل نفسه للحصول على العدد الدقيق.
      </div>
    </div>
  )
}

function AudioLab() {
  const [sampleIndex, setSampleIndex] = useState(0)
  const sample = vfcTrace.audioEmbedding.embeddingExamples[sampleIndex]

  // Convert 16-bit signed integer to 16-bit binary string (two's complement)
  const to16BitBin = (num: number) => {
    const u16 = (num < 0 ? num + 65536 : num) & 0xffff
    return u16.toString(2).padStart(16, '0')
  }

  const beforeBin = to16BitBin(sample.before)
  const afterBin = to16BitBin(sample.after)

  return (
    <section className="lab-section">
      <LabHeading
        eyebrow="الطبقة الصوتية · تضمين PCM LSB"
        title="إخفاء بتات الحمولة داخل عينات صوت PCM"
        summary="استبدال البت الأقل أهمية (LSB) فقط في العينات التي تحقق |sample ≫ 1| ≥ 2، وبمواضع يرتبها CSPRNG."
        aside={<EvidenceTag tone="verified">SNR = {vfcTrace.measurements.audio.signalToNoiseRatioDb.toFixed(1)} dB</EvidenceTag>}
      />

      {/* Main Interactive Waveform & Sample Selector */}
      <div className="card" style={{ background: 'var(--surface-dark)', border: '1px solid var(--line-dark)', borderRadius: '12px', padding: '1.25rem', marginBottom: '1.5rem' }}>
        
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem', flexWrap: 'wrap', gap: '0.5rem' }}>
          <strong style={{ fontSize: '0.95rem', color: 'var(--white)' }}>
            موجة الصوت الحاملة (PCM 16-bit / 48kHz) ومواضع التضمين:
          </strong>
          <span style={{ fontSize: '0.8rem', color: 'var(--accent)', fontFamily: 'monospace' }}>
            البت #{sampleIndex + 1} من {vfcTrace.audioEmbedding.embeddingExamples.length} · موضع العينة #{sample.sampleIndex}
          </span>
        </div>

        {/* Live Audio Waveform SVG with Highlighted Selected Position */}
        <div style={{ background: '#0d0e15', borderRadius: '8px', border: '1px solid var(--line-dark)', padding: '0.75rem', marginBottom: '1rem', position: 'relative' }}>
          <svg viewBox="0 0 900 160" style={{ width: '100%', height: '160px', display: 'block', overflow: 'visible' }}>
            <defs>
              <linearGradient id="audioWaveGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#89b4fa" stopOpacity="0.35" />
                <stop offset="50%" stopColor="#89b4fa" stopOpacity="0.05" />
                <stop offset="100%" stopColor="#89b4fa" stopOpacity="0.35" />
              </linearGradient>
              <filter id="waveGlow" x="-10%" y="-10%" width="120%" height="120%">
                <feDropShadow dx="0" dy="0" stdDeviation="2" floodColor="#89b4fa" floodOpacity="0.8" />
              </filter>
            </defs>

            {/* Grid & Axis */}
            <rect x="0" y="0" width="900" height="160" fill="#0d0e15" rx="4" />
            <line x1="0" y1="25" x2="900" y2="25" stroke="rgba(255,255,255,0.06)" strokeDasharray="3 3" />
            <line x1="0" y1="80" x2="900" y2="80" stroke="rgba(255,255,255,0.2)" />
            <line x1="0" y1="135" x2="900" y2="135" stroke="rgba(255,255,255,0.06)" strokeDasharray="3 3" />

            {/* Y Axis Labels */}
            <text x="8" y="20" fill="#6c7086" fontSize="10" fontFamily="monospace">+16384</text>
            <text x="8" y="76" fill="#6c7086" fontSize="10" fontFamily="monospace">0 (Silence)</text>
            <text x="8" y="152" fill="#6c7086" fontSize="10" fontFamily="monospace">-16384</text>

            {/* Area Fill */}
            <polygon
              points={`0,80 ${Array.from({ length: 180 }, (_, i) => {
                const sampleIdx = Math.round((i / 179) * 47999)
                const val = ((0x9e37 * sampleIdx) % 36000) - 18000
                const y = 80 - (val / 18000) * 55
                const x = (i / 179) * 900
                return `${x.toFixed(1)},${y.toFixed(1)}`
              }).join(' ')} 900,80`}
              fill="url(#audioWaveGrad)"
            />

            {/* Glowing Waveform Polyline */}
            <polyline
              points={Array.from({ length: 180 }, (_, i) => {
                const sampleIdx = Math.round((i / 179) * 47999)
                const val = ((0x9e37 * sampleIdx) % 36000) - 18000
                const y = 80 - (val / 18000) * 55
                const x = (i / 179) * 900
                return `${x.toFixed(1)},${y.toFixed(1)}`
              }).join(' ')}
              fill="none"
              stroke="#89b4fa"
              strokeWidth="2.2"
              filter="url(#waveGlow)"
            />

            {/* Inactive embedding markers */}
            {vfcTrace.audioEmbedding.first32ShuffledPositions.slice(0, 16).map((pos, idx) => {
              const x = (pos / 47999) * 900
              const isCurr = idx === sampleIndex
              if (isCurr) return null
              return (
                <g key={pos} opacity="0.6">
                  <line
                    x1={x}
                    y1="15"
                    x2={x}
                    y2="145"
                    stroke="#cba6f7"
                    strokeWidth="1.2"
                    strokeDasharray="3 3"
                  />
                  <circle cx={x} cy={15} r="2.5" fill="#cba6f7" />
                </g>
              )
            })}

            {/* Current Active Sample Marker Needle */}
            {(() => {
              const activeX = (sample.sampleIndex / 47999) * 900
              const activeY = 80 - (sample.before / 18000) * 55
              return (
                <g>
                  {/* Vertical Glowing Line */}
                  <line
                    x1={activeX}
                    y1="5"
                    x2={activeX}
                    y2="155"
                    stroke="#a6e3a1"
                    strokeWidth="3"
                    style={{ filter: 'drop-shadow(0 0 6px rgba(166,227,161,0.9))' }}
                  />
                  {/* Target Node */}
                  <circle cx={activeX} cy={activeY} r="7" fill="#a6e3a1" stroke="#111" strokeWidth="2.5" />
                  <circle cx={activeX} cy={activeY} r="12" fill="none" stroke="#a6e3a1" strokeWidth="1.5" opacity="0.75" />
                  
                  {/* Badge Label */}
                  <rect
                    x={Math.max(10, Math.min(800, activeX - 45))}
                    y="8"
                    width="90"
                    height="20"
                    rx="4"
                    fill="#1e1e2e"
                    stroke="#a6e3a1"
                    strokeWidth="1"
                  />
                  <text
                    x={Math.max(10, Math.min(800, activeX - 45)) + 45}
                    y="22"
                    fill="#a6e3a1"
                    fontSize="11"
                    fontWeight="bold"
                    fontFamily="monospace"
                    textAnchor="middle"
                  >
                    #{sampleIndex + 1} ({sample.before})
                  </text>
                </g>
              )
            })()}
          </svg>
        </div>

        {/* Interactive Sample Slider */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', flexWrap: 'wrap' }}>
          <label htmlFor="audio-slider-input" style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
            تنقل بين عينات التضمين:
          </label>
          <input
            id="audio-slider-input"
            type="range"
            min={0}
            max={vfcTrace.audioEmbedding.embeddingExamples.length - 1}
            value={sampleIndex}
            onChange={(e) => setSampleIndex(Number(e.target.value))}
            style={{ flex: 1, minWidth: '200px', accentColor: 'var(--green-bright)', cursor: 'pointer' }}
          />
          <span style={{ fontSize: '0.85rem', color: 'var(--white)', fontFamily: 'monospace', background: 'var(--surface-dark-2)', padding: '0.2rem 0.6rem', borderRadius: '4px' }}>
            #{sampleIndex + 1}
          </span>
        </div>
      </div>

      {/* 16-Bit Binary Word Inspector (The Core Stego Visual) */}
      <div className="card" style={{ background: 'var(--surface-dark)', border: '1px solid var(--line-dark)', borderRadius: '12px', padding: '1.25rem', marginBottom: '1.5rem' }}>
        <h3 style={{ fontSize: '1rem', color: 'var(--white)', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <span>فاحص البتات الثنائية للعينات (16-bit Word LSB Replacement):</span>
        </h3>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem', marginBottom: '1.25rem' }}>
          
          {/* Box 1: Before Embedding */}
          <div style={{ background: 'var(--black-deep)', border: '1px solid var(--line-dark)', borderRadius: '8px', padding: '1rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
              <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>العينة الأصلية (قبل الإخفاء):</span>
              <strong style={{ fontSize: '0.95rem', color: 'var(--white)', fontFamily: 'monospace' }}>{sample.before}</strong>
            </div>
            
            {/* 16-bit binary strip */}
            <div style={{ display: 'flex', gap: '2px', direction: 'ltr', justifyContent: 'center', marginBottom: '0.5rem' }}>
              {beforeBin.split('').map((bit, i) => {
                const isLsb = i === 15
                return (
                  <span
                    key={i}
                    style={{
                      display: 'inline-block',
                      width: '16px',
                      height: '24px',
                      lineHeight: '24px',
                      textAlign: 'center',
                      fontSize: '0.75rem',
                      fontFamily: 'monospace',
                      fontWeight: isLsb ? 'bold' : 'normal',
                      background: isLsb ? 'rgba(137, 180, 250, 0.25)' : '#222',
                      border: isLsb ? '1.5px solid var(--accent)' : '1px solid #333',
                      borderRadius: '3px',
                      color: isLsb ? 'var(--accent)' : '#aaa',
                    }}
                  >
                    {bit}
                  </span>
                )
              })}
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textAlign: 'center' }}>
              البت الأخير (LSB): <span style={{ color: 'var(--accent)', fontWeight: 'bold' }}>{sample.beforeLsb}</span>
            </div>
          </div>

          {/* Box 2: After Embedding */}
          <div style={{ background: 'var(--black-deep)', border: '1px solid var(--green-bright)', borderRadius: '8px', padding: '1rem', boxShadow: '0 0 12px rgba(166, 227, 161, 0.15)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
              <span style={{ fontSize: '0.8rem', color: 'var(--green-bright)' }}>العينة المضمنة (بعد الإخفاء):</span>
              <strong style={{ fontSize: '0.95rem', color: 'var(--green-bright)', fontFamily: 'monospace' }}>{sample.after}</strong>
            </div>
            
            {/* 16-bit binary strip with green LSB */}
            <div style={{ display: 'flex', gap: '2px', direction: 'ltr', justifyContent: 'center', marginBottom: '0.5rem' }}>
              {afterBin.split('').map((bit, i) => {
                const isLsb = i === 15
                return (
                  <span
                    key={i}
                    style={{
                      display: 'inline-block',
                      width: '16px',
                      height: '24px',
                      lineHeight: '24px',
                      textAlign: 'center',
                      fontSize: '0.75rem',
                      fontFamily: 'monospace',
                      fontWeight: isLsb ? 'bold' : 'normal',
                      background: isLsb ? 'rgba(166, 227, 161, 0.35)' : '#222',
                      border: isLsb ? '1.5px solid var(--green-bright)' : '1px solid #333',
                      borderRadius: '3px',
                      color: isLsb ? 'var(--green-bright)' : '#aaa',
                    }}
                  >
                    {bit}
                  </span>
                )
              })}
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--green-bright)', textAlign: 'center' }}>
              تم استبدال LSB بالبت المطلوب: <span style={{ fontWeight: 'bold' }}>{sample.payloadBit}</span> (فرق السعة Δ = {sample.delta > 0 ? `+${sample.delta}` : sample.delta})
            </div>
          </div>

        </div>

        {/* Audio Quality Metric Bar */}
        <div style={{ background: 'var(--surface-dark-2)', border: '1px solid var(--line-dark)', borderRadius: '8px', padding: '0.75rem 1rem', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.75rem' }}>
          <div>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)', display: 'block' }}>مؤشر نقاء وجودة الصوت (SNR Ratio):</span>
            <strong style={{ fontSize: '1.1rem', color: 'var(--green-bright)' }}>{vfcTrace.measurements.audio.signalToNoiseRatioDb.toFixed(2)} dB</strong>
            <small style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block' }}>اجتاز متجه القياس المسجل شرط الاختبار: SNR {'>'} 80 dB. هذا قياس عددي لهذا الحامل، وليس حكماً مطلقاً على السمع.</small>
          </div>
          <div style={{ textAlign: 'left', direction: 'ltr' }}>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)', display: 'block' }}>Maximum Distortion:</span>
            <strong style={{ fontSize: '0.95rem', color: 'var(--white)', fontFamily: 'monospace' }}>|Δ| ≤ 1 (0.0015% of 16-bit range)</strong>
          </div>
        </div>

        {/* Interactive Capacity Calculator */}
        <AudioCapacityCalculator />

      </div>
    </section>
  )
}

function EvidenceLab() {
  const [selectedTest, setSelectedTest] = useState(1)
  const [asideOpen, setAsideOpen] = useState(() => typeof window !== 'undefined' ? window.innerWidth > 900 : true)

  const testExplanations: Record<number, string> = {
    1: 'يضرب MDS في معكوسها داخل GF(2⁸) ويتحقق من الحصول على مصفوفة الهوية.',
    2: 'يتحقق من أن S-Box تقابلية وأن جدولها المعكوس يعيد كل قيمة إلى مدخلها.',
    3: 'يشفر كتلة 16 بايت ثم يفكها ويتحقق من استرجاع الكتلة نفسها.',
    4: 'يقلب كل واحد من بتات الإدخال الـ128 على حدة ويقيس عدد بتات الخرج المتغيرة.',
    5: 'يتحقق من أن تغيير بايت واحد يصل إلى 16 من 16 بايتاً في خرج المتجه.',
    6: 'يحزم ملفاً نصياً ويستخرجه ويتحقق من تطابق البايتات.',
    7: 'يكرر اختبار الاسترجاع على حمولة صورة بحجم 4 KiB.',
    8: 'يكرر اختبار الاسترجاع على حمولة PDF بحجم 8 KiB.',
    9: 'يتحقق من رفض الحمولة عند استخدام كلمة مرور غير مطابقة.',
    10: 'يتحقق من رفض الحمولة عند تغيّر محتوى الإطار المرجعي.',
    11: 'يتحقق من رفض الحمولة عند قلب بت واحد في النص المشفر (HMAC قبل فك التشفير).',
    12: 'يقيس نسبة الإشارة إلى الضجيج ويتحقق من تجاوزها عتبة 80 dB (النتيجة 100.4 dB).',
    13: 'يجري اختبار كاي-تربيعي على بتات LSB للتأكد من عدم وجود انحياز إحصائي.',
  }

  return (
    <section className="lab-section">
      <LabHeading
        eyebrow="الطبقة 08 · الأدلة والتحقق"
        title="مصفوفة الاختبارات الـ 13 (اجتياز 100%)"
        summary="نتائج التحقق البرمجي التلقائي الشامل لجميع مكونات التشفير والإخفاء."
        aside={<VerificationSeal compact />}
      />

      <DetailsToggle open={asideOpen} onToggle={() => setAsideOpen(!asideOpen)} controls="evidence-detail" />

      <div className={`evidence-board${asideOpen ? '' : ' is-aside-folded'}`}>
        <div className="test-board">
          {vfcTrace.testSuite.results.map((test) => (
            <button
              key={test.index}
              type="button"
              className={`test-item-btn${selectedTest === test.index ? ' is-selected' : ''}`}
              aria-pressed={selectedTest === test.index}
              onClick={() => {
                setSelectedTest(test.index)
                setAsideOpen(true)
              }}
            >
              <CheckCircle2 size={18} aria-hidden="true" />
              <Hex>{String(test.index).padStart(2, '0')}</Hex>
              <span>{testNames[test.index - 1]}</span>
              <b>PASS</b>
            </button>
          ))}
        </div>
        <aside className="claims-audit" id="evidence-detail" hidden={!asideOpen}>
            <h2>الاختبار المحدد · <Hex>#{selectedTest}</Hex></h2>
            <div className="selected-test-detail">
              <strong>{testNames[selectedTest - 1]}</strong>
              <p>{testExplanations[selectedTest]}</p>
              <span className="badge-pill success">النتيجة المسجلة: PASS</span>
            </div>
        </aside>
      </div>
    </section>
  )
}

type StudioSecretFile = {
  name: string
  data: Uint8Array
}

type StudioBlockTrace = {
  index: number
  plaintext: string
  previous: string
  xorInput: string
  ciphertext: string
  spnStates: string[]
}

type StudioEncryptionStory = {
  filename: string
  sourceBytes: number
  packageBytes: number
  paddedBytes: number
  blocks: StudioBlockTrace[]
}

const shortHex = (hex: string, length = 48) => hex.length > length ? `${hex.slice(0, length)}…` : hex

function StudioLab() {
  const [studioMode, setStudioMode] = useState<'hide' | 'recover'>('hide')
  const [step, setStep] = useState<0 | 1 | 2 | 3 | 4 | 5>(0)
  const [secretMode, setSecretMode] = useState<'text' | 'file'>('text')
  const [secret, setSecret] = useState('ملف سري للغاية')
  const [secretFile, setSecretFile] = useState<StudioSecretFile | null>(null)
  const [password, setPassword] = useState('BlackRing-2028')
  const [frameNumber, setFrameNumber] = useState(30)
  const [carrier, setCarrier] = useState<{ name: string; audio: VFCWavAudio } | null>(null)
  const [recoveryCarrier, setRecoveryCarrier] = useState<{ name: string; audio: VFCWavAudio } | null>(null)
  const [recoveryResult, setRecoveryResult] = useState<{ filename: string; preview: string; byteLength: number; payloadBytes: number; url: string } | null>(null)
  const [recoveryError, setRecoveryError] = useState('')
  const [isRecovering, setIsRecovering] = useState(false)
  
  const [aHashHex, setAHashHex] = useState<string>(() => {
    const candidate = new URLSearchParams(window.location.search).get('fingerprint')?.toLowerCase()
    return candidate && /^[0-9a-f]{16}$/.test(candidate) ? candidate : vfcTrace.fingerprint.bytesHex
  })
  const [previewUrl, setPreviewUrl] = useState<string | null>(null)
  
  const [keys, setKeys] = useState<{ kEmbed: string, kEnc: string, kAuth: string } | null>(null)
  const [packedPlaintext, setPackedPlaintext] = useState<string>('')
  const [ciphertext, setCiphertext] = useState<string>('')
  const [encryptionStory, setEncryptionStory] = useState<StudioEncryptionStory | null>(null)
  const [selectedStoryBlock, setSelectedStoryBlock] = useState(0)
  const [payloadInfo, setPayloadInfo] = useState<{ header: string, ct: string, hmac: string, totalBytes: number } | null>(null)
  const [audioResult, setAudioResult] = useState<{ url: string, originalUrl: string, usedCount: number, changedCount: number, eligibleCount: number, sourceName: string } | null>(null)
  const [roundTrip, setRoundTrip] = useState<{ filename: string, preview: string, byteLength: number, exact: boolean } | null>(null)
  const [studioError, setStudioError] = useState<string>('')
  const [isProcessing, setIsProcessing] = useState(false)
  const carrierCapacity = useMemo(() => carrier ? getAudioCapacity(carrier.audio) : null, [carrier])
  const recoveryCapacity = useMemo(() => recoveryCarrier ? getAudioCapacity(recoveryCarrier.audio) : null, [recoveryCarrier])

  useEffect(() => () => {
    if (audioResult) {
      URL.revokeObjectURL(audioResult.url)
      URL.revokeObjectURL(audioResult.originalUrl)
    }
  }, [audioResult])

  useEffect(() => () => {
    if (recoveryResult) URL.revokeObjectURL(recoveryResult.url)
  }, [recoveryResult])

  // Verification scenario state
  const [verifyScenario, setVerifyScenario] = useState<'correct' | 'wrong_password' | 'wrong_frame' | 'tamper' | null>(null)

  const stepLabels = [
    'تجهيز الملف',
    'توليد المفاتيح',
    'CBC يستدعي SPN',
    'الحمولة والتوثيق',
    'الإخفاء والاستخراج',
    'التحقق والاسترجاع'
  ]

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = (event) => {
      const img = new Image()
      img.onload = () => {
        const computed = computeAHashFromImageData(img, file.name)
        setAHashHex(computed.bytesHex)
        setPreviewUrl(computed.previewDataUrl || null)
      }
      img.src = event.target?.result as string
    }
    reader.readAsDataURL(file)
  }

  const loadWav = async (file: File) => parsePcm16Wav(await file.arrayBuffer())

  const handleCarrierChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    setStudioError('')
    try {
      setCarrier({ name: file.name, audio: await loadWav(file) })
    } catch (error) {
      setCarrier(null)
      setStudioError(error instanceof Error ? error.message : 'تعذّرت قراءة حامل WAV.')
    }
  }

  const handleRecoveryCarrierChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    setRecoveryError('')
    setRecoveryResult(null)
    try {
      setRecoveryCarrier({ name: file.name, audio: await loadWav(file) })
    } catch (error) {
      setRecoveryCarrier(null)
      setRecoveryError(error instanceof Error ? error.message : 'تعذّرت قراءة ملف WAV.')
    }
  }

  const handleSecretFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    setStudioError('')
    setSecretMode('file')
    try {
      setSecretFile({ name: file.name, data: new Uint8Array(await file.arrayBuffer()) })
    } catch {
      setSecretFile(null)
      setStudioError('تعذّرت قراءة الملف السري. اختر ملفاً آخر ثم أعد المحاولة.')
    }
  }

  const handleStart = async () => {
    setIsProcessing(true)
    setStudioError('')
    setRoundTrip(null)
    setVerifyScenario(null)
    try {
      const salt = crypto.getRandomValues(new Uint8Array(16))
      const iv = crypto.getRandomValues(new Uint8Array(16))
      const options = { frameNumber, randomSaltHex: bytesToHex(salt) }
      const { kEmbed, kEnc, kAuth } = await deriveVFCKeys(password, aHashHex, options)
      setKeys({
        kEmbed: bytesToHex(kEmbed),
        kEnc: bytesToHex(kEnc),
        kAuth: bytesToHex(kAuth)
      })

      if (secretMode === 'file' && !secretFile) throw new Error('اختر الملف السري الذي تريد تشفيره أولاً.')
      const source = secretMode === 'file' && secretFile
        ? secretFile
        : { name: 'message.txt', data: new TextEncoder().encode(secret || ' ') }
      const innerPackage = packVFCPlaintext(source.name, source.data)
      setPackedPlaintext(bytesToHex(innerPackage))
      const padded = padPKCS7(innerPackage)
      const ctBytes = await encryptVFCCbc(innerPackage, kEnc, iv)
      setCiphertext(bytesToHex(ctBytes))
      const roundKeys = await getRoundKeys(kEnc)
      const blocks = Array.from({ length: padded.length / 16 }, (_, index) => {
        const offset = index * 16
        const plaintextBlock = padded.slice(offset, offset + 16)
        const previousBlock = index === 0 ? iv : ctBytes.slice(offset - 16, offset)
        const xorInput = xorBytes(plaintextBlock, previousBlock)
        return {
          index,
          plaintext: bytesToHex(plaintextBlock),
          previous: bytesToHex(previousBlock),
          xorInput: bytesToHex(xorInput),
          ciphertext: bytesToHex(ctBytes.slice(offset, offset + 16)),
          spnStates: encryptVFCBlockTrace(xorInput, roundKeys).map(bytesToHex),
        }
      })
      setEncryptionStory({
        filename: source.name,
        sourceBytes: source.data.length,
        packageBytes: innerPackage.length,
        paddedBytes: padded.length,
        blocks,
      })
      setSelectedStoryBlock(0)

      const payload = await generateVFCPayload(ctBytes, kEmbed, kAuth, iv, options)
      setPayloadInfo({
        header: bytesToHex(payload.header),
        ct: bytesToHex(payload.ciphertext),
        hmac: bytesToHex(payload.hmacTag),
        totalBytes: payload.fullPayload.length,
      })

      const audio = await embedPayloadInAudio(payload.fullPayload, kEmbed, carrier?.audio)
      setAudioResult({
        url: audio.modifiedAudioUrl,
        originalUrl: audio.originalAudioUrl,
        usedCount: audio.usedSampleCount,
        changedCount: audio.changedSampleCount,
        eligibleCount: audio.eligibleSampleCount,
        sourceName: carrier?.name ?? 'الحامل الاصطناعي المولّد',
      })

      const extractedPayload = await extractPayloadFromAudio(audio.embeddedSamples, kEmbed)
      const verified = await verifyVFCPayload(extractedPayload, kEmbed, kAuth)
      const decrypted = await decryptVFCCbc(verified.ciphertext, kEnc, verified.iv)
      const recovered = unpackVFCPlaintext(decrypted)
      setRoundTrip({
        filename: recovered.filename,
        preview: shortHex(bytesToHex(recovered.data)),
        byteLength: recovered.data.length,
        exact: bytesToHex(recovered.data) === bytesToHex(source.data),
      })

      setStep(1)
    } catch (error) {
      console.error(error)
      setStudioError(error instanceof Error ? error.message : 'تعذّر إكمال الجولة.')
      setStep(0)
    } finally {
      setIsProcessing(false)
    }
  }

  const handleRecover = async () => {
    if (!recoveryCarrier) {
      setRecoveryError('اختر ملف WAV المعدّل أولاً.')
      return
    }
    setIsRecovering(true)
    setRecoveryError('')
    setRecoveryResult(null)
    try {
      const contextKeys = await deriveVFCKeys(password, aHashHex, { frameNumber })
      const payload = await extractPayloadFromAudio(recoveryCarrier.audio.samples, contextKeys.kEmbed)
      const header = readVFCPayloadHeader(payload)
      if (header.frameNumber !== frameNumber) throw new Error(`الترويسة تحمل رقم الإطار ${header.frameNumber} بينما أدخلت ${frameNumber}.`)
      const keysFromHeader = await deriveVFCKeys(password, aHashHex, {
        frameNumber: header.frameNumber,
        randomSaltHex: bytesToHex(header.salt),
      })
      const verified = await verifyVFCPayload(payload, contextKeys.kEmbed, keysFromHeader.kAuth)
      const plain = await decryptVFCCbc(verified.ciphertext, keysFromHeader.kEnc, verified.iv)
      const recovered = unpackVFCPlaintext(plain)
      setRecoveryResult({
        filename: recovered.filename,
        preview: shortHex(bytesToHex(recovered.data)),
        byteLength: recovered.data.length,
        payloadBytes: payload.length,
        url: URL.createObjectURL(new Blob([new Uint8Array(recovered.data).buffer])),
      })
    } catch (error) {
      setRecoveryError(error instanceof Error ? error.message : 'فشل الاسترجاع.')
    } finally {
      setIsRecovering(false)
    }
  }

  return (
    <section className="lab-section">
      <LabHeading
        eyebrow="استديو المحاكاة الكاملة"
        title="أخفِ في WAV حقيقي، ثم أعد تحميله واستخرجه"
        summary="يمكنك استعمال الحامل الاصطناعي أو اختيار WAV PCM 16-bit من جهازك. نزّل الناتج، انتقل إلى الاسترجاع، وأعد تحميل الملف لإثبات المسار من البداية إلى النهاية."
      />

      <div className="studio-mode-switch" role="tablist" aria-label="وضع الاستديو">
        <button type="button" role="tab" aria-selected={studioMode === 'hide'} className={studioMode === 'hide' ? 'is-active' : ''} onClick={() => setStudioMode('hide')}>
          <Upload size={17} aria-hidden="true" /> إخفاء رسالة
        </button>
        <button type="button" role="tab" aria-selected={studioMode === 'recover'} className={studioMode === 'recover' ? 'is-active' : ''} onClick={() => setStudioMode('recover')}>
          <ShieldCheck size={17} aria-hidden="true" /> استرجاع من WAV
        </button>
      </div>

      <div hidden={studioMode !== 'hide'} className="card studio-workspace" style={{ background: 'var(--surface-dark)', border: '1px solid var(--line-dark)', borderRadius: '12px', padding: '1.5rem', marginBottom: '1.5rem', overflow: 'hidden' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '2rem', position: 'relative' }}>
          <div style={{ position: 'absolute', top: '15px', left: '0', right: '0', height: '2px', background: 'var(--line-dark)', zIndex: 0 }} />
          {stepLabels.map((label, idx) => (
            <div key={idx} style={{ position: 'relative', zIndex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '0.5rem', width: '20%' }}>
              <motion.div 
                animate={{
                  background: step >= idx ? 'var(--accent)' : 'var(--black-deep)',
                  borderColor: step >= idx ? 'var(--accent)' : 'var(--line-dark)',
                  color: step >= idx ? '#111' : 'var(--text-muted)'
                }}
                transition={{ duration: 0.4 }}
                style={{ 
                  width: '32px', height: '32px', borderRadius: '50%', 
                  border: '2px solid', display: 'flex', alignItems: 'center',
                  justifyContent: 'center', fontWeight: 'bold'
                }}
              >
                {idx + 1}
              </motion.div>
              <span style={{ fontSize: '0.8rem', color: step >= idx ? 'var(--white)' : 'var(--text-muted)', textAlign: 'center', fontWeight: step >= idx ? 'bold' : 'normal' }}>
                {label}
              </span>
            </div>
          ))}
        </div>

        <div style={{ minHeight: '300px', display: 'flex', flexDirection: 'column', justifyContent: 'center', position: 'relative' }}>
          <AnimatePresence mode="wait">
            {step === 0 && (
              <motion.div 
                key="step0"
                initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }}
                style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem', maxWidth: '400px', margin: '0 auto', width: '100%' }}
              >
                <div>
                  <label style={{ display: 'block', marginBottom: '0.5rem', fontSize: '0.85rem', color: 'var(--accent)' }}>صورة الإطار (لتوليد بصمة aHash):</label>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', background: 'var(--black-deep)', padding: '0.5rem', borderRadius: '6px', border: '1px solid var(--line-dark)' }}>
                    {previewUrl ? (
                      <img src={previewUrl} alt="Preview" style={{ width: '40px', height: '40px', borderRadius: '4px', objectFit: 'cover' }} />
                    ) : (
                      <div style={{ width: '40px', height: '40px', borderRadius: '4px', background: 'var(--surface-dark-2)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                        <ImageIcon size={20} color="var(--text-muted)" />
                      </div>
                    )}
                    <input type="file" accept="image/*" onChange={handleFileChange} style={{ fontSize: '0.8rem' }} />
                  </div>
                  <small style={{ display: 'block', marginTop: '0.5rem', color: 'var(--text-muted)', fontFamily: 'monospace' }}>البصمة: {aHashHex.slice(0, 16)}...</small>
                </div>
                <div className="studio-input-block">
                  <label htmlFor="studio-frame-number">رقم الإطار المستخدم في السياق:</label>
                  <input id="studio-frame-number" type="number" min={0} max={4294967295} value={frameNumber} onChange={(event) => setFrameNumber(Math.max(0, Number(event.target.value) || 0))} />
                </div>
                <div className="studio-input-block">
                  <label htmlFor="studio-carrier">حامل WAV اختياري:</label>
                  <input id="studio-carrier" type="file" accept="audio/wav,.wav" onChange={handleCarrierChange} />
                  {carrier && carrierCapacity ? (
                    <div className="studio-file-facts">
                      <strong>{carrier.name}</strong>
                      <span>{carrier.audio.sampleRate.toLocaleString()} Hz · {carrier.audio.channelCount === 1 ? 'Mono' : `${carrier.audio.channelCount} channels`}</span>
                      <span>{carrierCapacity.eligibleSamples.toLocaleString()} عينة مؤهلة · سعة خام {carrierCapacity.rawBytes.toLocaleString()}B</span>
                      <button type="button" onClick={() => setCarrier(null)}>العودة إلى الحامل الاصطناعي</button>
                    </div>
                  ) : (
                    <small>إن لم تختر ملفاً، يولّد الاستديو حاملاً PCM 16-bit مدته ثانيتان.</small>
                  )}
                </div>
                <div className="studio-secret-source">
                  <span className="studio-source-label">مصدر السر:</span>
                  <div className="studio-source-switch" role="tablist" aria-label="مصدر الملف السري">
                    <button type="button" role="tab" aria-selected={secretMode === 'text'} className={secretMode === 'text' ? 'is-active' : ''} onClick={() => setSecretMode('text')}>نص قصير</button>
                    <button type="button" role="tab" aria-selected={secretMode === 'file'} className={secretMode === 'file' ? 'is-active' : ''} onClick={() => setSecretMode('file')}>رفع ملف حقيقي</button>
                  </div>
                  {secretMode === 'text' ? (
                    <>
                      <label htmlFor="studio-secret-text">النص الصريح:</label>
                      <input id="studio-secret-text" type="text" value={secret} onChange={(e) => setSecret(e.target.value)} />
                    </>
                  ) : (
                    <>
                      <label htmlFor="studio-secret-file">اختر الملف السري:</label>
                      <input id="studio-secret-file" type="file" onChange={handleSecretFileChange} />
                      {secretFile ? (
                        <div className="studio-file-facts">
                          <strong>{secretFile.name}</strong>
                          <span>{secretFile.data.length.toLocaleString()} بايت قبل بناء الحزمة الداخلية</span>
                          <span dir="ltr">{shortHex(bytesToHex(secretFile.data), 28)}</span>
                        </div>
                      ) : <small>يمكن أن يكون صورة أو PDF أو نصاً أو أي ملف صغير يلائم سعة حامل الصوت.</small>}
                    </>
                  )}
                </div>
                <div>
                  <label style={{ display: 'block', marginBottom: '0.5rem', fontSize: '0.85rem', color: 'var(--accent)' }}>كلمة المرور:</label>
                  <input 
                    type="password" value={password} onChange={(e) => setPassword(e.target.value)}
                    style={{ width: '100%', padding: '0.75rem', borderRadius: '6px', border: '1px solid var(--line-dark)', background: 'var(--black-deep)', color: 'var(--white)', fontSize: '1rem' }}
                  />
                </div>
                <button 
                  className="button button--primary" 
                  style={{ marginTop: '1rem', padding: '0.75rem', fontSize: '1rem' }}
                  onClick={handleStart}
                  disabled={isProcessing}
                >
                  {isProcessing ? 'جاري التشفير...' : 'بدء التشفير الحقيقي'}
                </button>
                {studioError && (
                  <div role="alert" style={{ color: 'var(--red)', background: 'rgba(243, 139, 168, 0.08)', border: '1px solid var(--red)', borderRadius: '6px', padding: '0.75rem', fontSize: '0.8rem', lineHeight: 1.6 }}>
                    لم تكتمل الجولة: {studioError}
                  </div>
                )}
              </motion.div>
            )}

            {step === 1 && keys && (
              <motion.div 
                key="step1"
                initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: -20 }}
                style={{ textAlign: 'center', maxWidth: '600px', margin: '0 auto' }}
              >
                <h3 style={{ color: 'var(--accent)', marginBottom: '1rem' }}>توليد المفاتيح 🔑</h3>
                <p style={{ color: 'var(--text-muted)', marginBottom: '1.5rem', lineHeight: 1.6 }}>يتم اشتقاق ثلاثة مفاتيح حقيقية الآن عبر خوارزمية PBKDF2-HMAC-SHA256.</p>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', marginBottom: '2rem' }}>
                  <motion.div initial={{ scale: 0.95 }} animate={{ scale: 1 }} style={{ background: 'var(--black-deep)', padding: '0.75rem', borderRadius: '6px', border: '1px solid var(--line-dark)', display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ color: 'var(--green-bright)' }}>K_embed</span><span style={{ fontFamily: 'monospace', color: 'var(--white)' }}>{keys.kEmbed.slice(0, 32)}...</span>
                  </motion.div>
                  <motion.div initial={{ scale: 0.95 }} animate={{ scale: 1 }} transition={{ delay: 0.1 }} style={{ background: 'var(--black-deep)', padding: '0.75rem', borderRadius: '6px', border: '1px solid var(--line-dark)', display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ color: 'var(--accent)' }}>K_enc</span><span style={{ fontFamily: 'monospace', color: 'var(--white)' }}>{keys.kEnc.slice(0, 32)}...</span>
                  </motion.div>
                  <motion.div initial={{ scale: 0.95 }} animate={{ scale: 1 }} transition={{ delay: 0.2 }} style={{ background: 'var(--black-deep)', padding: '0.75rem', borderRadius: '6px', border: '1px solid var(--line-dark)', display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ color: '#cba6f7' }}>K_auth</span><span style={{ fontFamily: 'monospace', color: 'var(--white)' }}>{keys.kAuth.slice(0, 32)}...</span>
                  </motion.div>
                </div>
                <button className="button button--primary" onClick={() => setStep(2)}>التالي: تشفير الرسالة</button>
              </motion.div>
            )}

            {step === 2 && encryptionStory && (
              <motion.div 
                key="step2"
                initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: -20 }}
                style={{ textAlign: 'center', maxWidth: '600px', margin: '0 auto', width: '100%' }}
              >
                <h3 style={{ color: 'var(--accent)', marginBottom: '1rem' }}>حلقة CBC تستدعي SPN لكل كتلة 🔒</h3>
                <p style={{ color: 'var(--text-muted)', marginBottom: '1.5rem', lineHeight: 1.6 }}>أولاً بُنيت الحزمة الداخلية (اسم الملف والحجم والعَلَم والبيانات)، ثم أضيف PKCS#7. لكل كتلة يحسب CBC قيمة XOR ويرسلها إلى SPN. المعروض أدناه ناتج هذه الجولة، وليس مثالاً ثابتاً.</p>
                <div className="studio-file-summary">
                  <span><b>الملف:</b> {encryptionStory.filename}</span>
                  <span><b>الأصل:</b> {encryptionStory.sourceBytes.toLocaleString()}B</span>
                  <span><b>الحزمة:</b> {encryptionStory.packageBytes.toLocaleString()}B</span>
                  <span><b>بعد الحشو:</b> {encryptionStory.paddedBytes.toLocaleString()}B = {encryptionStory.blocks.length} كتلة</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'stretch', gap: '1rem', marginBottom: '2rem', flexWrap: 'wrap' }}>
                  <div style={{ background: 'var(--black-deep)', padding: '1rem', borderRadius: '8px', border: '1px solid var(--line-dark)', flex: '1 1 200px' }}>
                    <span style={{ display: 'block', color: 'var(--text-muted)', fontSize: '0.8rem', marginBottom: '0.5rem' }}>الحزمة الداخلية قبل الحشو</span>
                    <div style={{ wordBreak: 'break-all', fontFamily: 'monospace', color: 'var(--white)' }}>{packedPlaintext.slice(0, 64)}{packedPlaintext.length > 64 ? '...' : ''}</div>
                  </div>
                  <div style={{ color: 'var(--accent)', fontSize: '1.5rem', display: 'flex', alignItems: 'center' }}>←</div>
                  <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.8 }} style={{ background: 'rgba(137, 180, 250, 0.1)', padding: '1rem', borderRadius: '8px', border: '1px solid var(--accent)', flex: '1 1 200px' }}>
                    <span style={{ display: 'block', color: 'var(--accent)', fontSize: '0.8rem', marginBottom: '0.5rem' }}>النص المشفر (Ciphertext)</span>
                    <div style={{ wordBreak: 'break-all', fontFamily: 'monospace', color: 'var(--white)' }}>{ciphertext.slice(0, 64)}{ciphertext.length > 64 ? '...' : ''}</div>
                  </motion.div>
                </div>
                {encryptionStory.blocks.length > 0 && (() => {
                  const block = encryptionStory.blocks[selectedStoryBlock]
                  return (
                    <div className="studio-block-inspector">
                      <div className="studio-block-heading">
                        <div>
                          <h4>تتبّع كتلة CBC/SPN الفعلية</h4>
                          <p>هذه هي الكتلة {block.index + 1} من {encryptionStory.blocks.length}. في الأولى نستخدم IV؛ وفي البقية نستخدم Cᵢ₋₁.</p>
                        </div>
                        <label htmlFor="studio-block-picker">الكتلة
                          <select id="studio-block-picker" value={selectedStoryBlock} onChange={(event) => setSelectedStoryBlock(Number(event.target.value))}>
                            {encryptionStory.blocks.map((item) => <option key={item.index} value={item.index}>C{item.index + 1}</option>)}
                          </select>
                        </label>
                      </div>
                      <input className="studio-block-range" type="range" min={0} max={encryptionStory.blocks.length - 1} value={selectedStoryBlock} onChange={(event) => setSelectedStoryBlock(Number(event.target.value))} aria-label="اختيار كتلة CBC" />
                      <div className="studio-block-flow" dir="ltr">
                        <div><small>Pᵢ بعد الحشو</small><code>{block.plaintext}</code></div>
                        <span>⊕</span>
                        <div><small>{block.index === 0 ? 'IV' : 'Cᵢ₋₁'}</small><code>{block.previous}</code></div>
                        <span>→</span>
                        <div className="is-xor"><small>Xᵢ إلى SPN</small><code>{block.xorInput}</code></div>
                        <span>→</span>
                        <div className="is-cipher"><small>Cᵢ</small><code>{block.ciphertext}</code></div>
                      </div>
                      <div className="studio-spn-proof" dir="ltr">
                        <span>Xᵢ</span><b>→ RK₀ → R₁ → R₂ → R₃ → R₄ → R₅ → R₆ →</b><span>Cᵢ</span>
                        <code title="بعد Initial Whitening (RK₀)">{shortHex(block.spnStates[1], 20)}</code>
                        <code title="ناتج الجولة السادسة؛ وهو Cᵢ">{shortHex(block.spnStates[7], 20)}</code>
                      </div>
                      <p className="studio-block-note">كل R تتضمن SubBytes ثم ShiftRows ثم MixColumns (حساب GF(2⁸)) ثم AddRoundKey. ناتج الجولة السادسة أعلاه يساوي Cᵢ المعروض.</p>
                    </div>
                  )
                })()}
                <button className="button button--primary" onClick={() => setStep(3)}>التالي: تجميع الحمولة</button>
              </motion.div>
            )}

            {step === 3 && payloadInfo && (
              <motion.div 
                key="step3"
                initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: -20 }}
                style={{ textAlign: 'center', maxWidth: '600px', margin: '0 auto', width: '100%' }}
              >
                <h3 style={{ color: 'var(--accent)', marginBottom: '1rem' }}>تجميع الحمولة 📦</h3>
                <p style={{ color: 'var(--text-muted)', marginBottom: '1.5rem', lineHeight: 1.6 }}>تم دمج الترويسة العامة الموثّقة والنص المشفر وإضافة وسم HMAC. الحجم في هذه الجولة هو {payloadInfo.totalBytes}B، وليس رقماً ثابتاً.</p>
                <div style={{ display: 'flex', gap: '0.25rem', marginBottom: '2rem', flexWrap: 'wrap' }}>
                  <motion.div initial={{ flex: 0 }} animate={{ flex: 1 }} transition={{ duration: 0.5 }} style={{ background: '#f9e2af', color: '#111', padding: '0.75rem', fontSize: '0.75rem', fontWeight: 'bold', borderRadius: '4px', overflow: 'hidden' }}>
                    Header<br/><span style={{ fontWeight: 'normal', fontSize: '0.65rem', wordBreak: 'break-all' }}>{payloadInfo.header.slice(0, 16)}...</span>
                  </motion.div>
                  <motion.div initial={{ flex: 0 }} animate={{ flex: 3 }} transition={{ duration: 0.5, delay: 0.2 }} style={{ background: 'var(--accent)', color: '#111', padding: '0.75rem', fontSize: '0.75rem', fontWeight: 'bold', borderRadius: '4px', overflow: 'hidden' }}>
                    Ciphertext<br/><span style={{ fontWeight: 'normal', fontSize: '0.65rem', wordBreak: 'break-all' }}>{payloadInfo.ct.slice(0, 32)}...</span>
                  </motion.div>
                  <motion.div initial={{ flex: 0 }} animate={{ flex: 2 }} transition={{ duration: 0.5, delay: 0.4 }} style={{ background: 'var(--green-bright)', color: '#111', padding: '0.75rem', fontSize: '0.75rem', fontWeight: 'bold', borderRadius: '4px', overflow: 'hidden' }}>
                    HMAC tag<br/><span style={{ fontWeight: 'normal', fontSize: '0.65rem', wordBreak: 'break-all' }}>{payloadInfo.hmac.slice(0, 24)}...</span>
                  </motion.div>
                </div>
                <button className="button button--primary" onClick={() => setStep(4)}>التالي: الإخفاء في الصوت</button>
              </motion.div>
            )}

            {step === 4 && audioResult && (
              <motion.div 
                key="step4"
                initial={{ opacity: 0, scale: 0.9 }} animate={{ opacity: 1, scale: 1 }} exit={{ opacity: 0, scale: 0.9 }}
                style={{ textAlign: 'center', maxWidth: '600px', margin: '0 auto', width: '100%' }}
              >
                <h3 style={{ color: 'var(--green-bright)', marginBottom: '1rem' }}>الإخفاء بالصوت 🔊</h3>
                <div style={{ display: 'flex', justifyContent: 'center', marginBottom: '0.75rem' }}>
                  <EvidenceTag tone="source">الحامل: {audioResult.sourceName}</EvidenceTag>
                </div>
                <p style={{ color: 'var(--text-muted)', marginBottom: '1.5rem', lineHeight: 1.6 }}>
                  استُخدمت {audioResult.usedCount.toLocaleString()} عينة مؤهلة لحمل البتات من أصل {audioResult.eligibleCount.toLocaleString()}، وتغيّرت قيمة {audioResult.changedCount.toLocaleString()} عينة فقط.
                </p>
                <div className="studio-video-bridge">
                  <span>الملف السري</span><b>→</b><span>حزمة + CBC/SPN</span><b>→</b><span>Header + ciphertext + HMAC</span><b>→</b><span>بتات في WAV</span><b>→</b><span>مسار الصوت داخل فيديو VFC</span>
                  <small>هنا نسمع وننزّل حامل WAV قبل/بعد. أداة سطح المكتب هي التي تضع مسار الصوت المعدّل داخل حاوية الفيديو النهائية.</small>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '2rem' }}>
                  <div style={{ background: 'var(--surface-dark)', padding: '1.5rem', borderRadius: '8px', border: '1px solid var(--line-dark)' }}>
                    <h4 style={{ color: 'var(--white)', fontSize: '1rem', marginBottom: '1rem' }}>الصوت الأصلي (قبل الإخفاء)</h4>
                    <audio src={audioResult.originalUrl} controls style={{ width: '100%' }} />
                  </div>

                  <div style={{ background: 'var(--black-deep)', padding: '1.5rem', borderRadius: '8px', border: '1px solid var(--green-bright)', boxShadow: '0 0 15px rgba(166,227,161,0.15)' }}>
                    <h4 style={{ color: 'var(--white)', fontSize: '1rem', marginBottom: '1rem' }}>الصوت المعدّل (مخفي به السر)</h4>
                    <audio src={audioResult.url} controls style={{ width: '100%', marginBottom: '0.75rem' }} />
                    <a href={audioResult.url} download="vfc-stego.wav" className="button button--primary" style={{ display: 'inline-block', textDecoration: 'none', width: '100%' }}>تحميل WAV المعدّل</a>
                    <small style={{ display: 'block', marginTop: '0.75rem', color: 'var(--text-muted)', fontSize: '0.72rem', lineHeight: 1.6 }}>
                      نزّل الملف، ثم افتح تبويب «استرجاع من WAV» وأعد تحميله مع كلمة المرور والصورة ورقم الإطار نفسها.
                    </small>
                  </div>
                </div>
                <div style={{ display: 'flex', gap: '1rem', justifyContent: 'center' }}>
                  <button className="button button--quiet" onClick={() => { setStep(0); setAudioResult(null); }}>إعادة المحاكاة</button>
                  <button className="button button--primary" onClick={() => setStep(5)}>
                    <ShieldCheck size={16} aria-hidden="true" style={{ marginLeft: '0.35rem' }} />
                    عرض نتيجة الاستخراج والتحقق
                  </button>
                </div>
              </motion.div>
            )}

            {step === 5 && payloadInfo && roundTrip && (
              <motion.div
                key="step5"
                initial={{ opacity: 0, scale: 0.9 }} animate={{ opacity: 1, scale: 1 }} exit={{ opacity: 0, scale: 0.9 }}
                style={{ maxWidth: '600px', margin: '0 auto', width: '100%' }}
              >
                <div style={{ textAlign: 'center', marginBottom: '1.5rem' }}>
                  <h3 style={{ color: 'var(--accent)', marginBottom: '0.5rem' }}>نتيجة الاسترجاع الفعلية وسيناريوهات الرفض</h3>
                  <p style={{ color: 'var(--text-muted)', lineHeight: 1.6, fontSize: '0.85rem' }}>
                    نتيجة هذه الجولة حُسبت من العينات المعدّلة فعلياً. الأزرار الأخرى تشرح مسارات الرفض المتوقعة.
                  </p>
                </div>

                <div style={{ marginBottom: '1rem', padding: '1rem', borderRadius: '8px', border: `1px solid ${roundTrip.exact ? 'var(--green-bright)' : 'var(--red)'}`, background: roundTrip.exact ? 'rgba(166, 227, 161, 0.08)' : 'rgba(243, 139, 168, 0.08)', textAlign: 'center' }}>
                  <strong style={{ color: roundTrip.exact ? 'var(--green-bright)' : 'var(--red)' }}>
                    {roundTrip.exact ? '✓ تطابق بايتاً ببايت بعد الاستخراج والتحقق وفك التشفير' : '✗ لا تتطابق البيانات المسترجعة'}
                  </strong>
                  <div style={{ marginTop: '0.5rem', color: 'var(--white)', overflowWrap: 'anywhere' }}>{roundTrip.filename} · {roundTrip.byteLength.toLocaleString()}B · <span dir="ltr">{roundTrip.preview}</span></div>
                </div>

                <div style={{ display: 'grid', gap: '0.75rem' }}>
                  <button
                    type="button"
                    className="button button--quiet"
                    onClick={() => setVerifyScenario('correct')}
                    style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', padding: '1rem', textAlign: 'right', background: verifyScenario === 'correct' ? 'var(--surface-dark)' : undefined }}
                  >
                    <CheckCircle2 size={18} style={{ color: 'var(--green-bright)', flexShrink: 0 }} />
                    <div>
                      <div style={{ fontWeight: 700, color: 'var(--white)', fontSize: '0.85rem' }}>نتيجة هذه الجولة — فتح ناجح</div>
                      <div style={{ color: 'var(--text-muted)', fontSize: '0.75rem', marginTop: '0.2rem' }}>استخراج البتات → HMAC صالح → CBC/SPN decrypt → فك الحزمة الداخلية</div>
                    </div>
                  </button>

                  <button
                    type="button"
                    className="button button--quiet"
                    onClick={() => setVerifyScenario('wrong_password')}
                    style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', padding: '1rem', textAlign: 'right', background: verifyScenario === 'wrong_password' ? 'var(--surface-dark)' : undefined }}
                  >
                    <ShieldAlert size={18} style={{ color: 'var(--red)', flexShrink: 0 }} />
                    <div>
                      <div style={{ fontWeight: 700, color: 'var(--white)', fontSize: '0.85rem' }}>كلمة مرور خاطئة — رفض HMAC</div>
                      <div style={{ color: 'var(--text-muted)', fontSize: '0.75rem', marginTop: '0.2rem' }}> HMAC-SHA256 يغطي الهيدر والنص المشفر كاملين. كلمة مختلفة = مفتاح K_auth مختلف = وسم لا يتطابق</div>
                    </div>
                  </button>

                  <button
                    type="button"
                    className="button button--quiet"
                    onClick={() => setVerifyScenario('wrong_frame')}
                    style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', padding: '1rem', textAlign: 'right', background: verifyScenario === 'wrong_frame' ? 'var(--surface-dark)' : undefined }}
                  >
                    <ShieldAlert size={18} style={{ color: 'var(--amber)', flexShrink: 0 }} />
                    <div>
                      <div style={{ fontWeight: 700, color: 'var(--white)', fontSize: '0.85rem' }}>رقم إطار خاطئ — رفض الاسترجاع</div>
                      <div style={{ color: 'var(--text-muted)', fontSize: '0.75rem', marginTop: '0.2rem' }}> إطار مختلف = بصمة مختلفة = مفاتيح ومواضع مختلفة → تفشل علامة magic أو HMAC</div>
                    </div>
                  </button>

                  <button
                    type="button"
                    className="button button--quiet"
                    onClick={() => setVerifyScenario('tamper')}
                    style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', padding: '1rem', textAlign: 'right', background: verifyScenario === 'tamper' ? 'var(--surface-dark)' : undefined }}
                  >
                    <ShieldAlert size={18} style={{ color: 'var(--red)', flexShrink: 0 }} />
                    <div>
                      <div style={{ fontWeight: 700, color: 'var(--white)', fontSize: '0.85rem' }}>تشوّه الحمولة — كشف التعديل</div>
                      <div style={{ color: 'var(--text-muted)', fontSize: '0.75rem', marginTop: '0.2rem' }}>قلب بت واحد في الترويسة أو النص المشفر يغيّر الرسالة الموثّقة، فيفشل فحص HMAC.</div>
                    </div>
                  </button>
                </div>

                {verifyScenario && (
                  <motion.div
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    style={{
                      marginTop: '1.5rem',
                      padding: '1.25rem',
                      borderRadius: '8px',
                      border: `1px solid ${verifyScenario === 'correct' ? 'var(--green-bright)' : 'var(--red)'}`,
                      background: verifyScenario === 'correct' ? 'rgba(166, 227, 161, 0.08)' : 'rgba(243, 139, 168, 0.08)',
                    }}
                  >
                    {verifyScenario === 'correct' && (
                      <>
                        <h4 style={{ color: 'var(--green-bright)', fontSize: '0.95rem', marginBottom: '0.75rem', textAlign: 'center' }}>
                          <CheckCircle2 size={18} style={{ verticalAlign: 'middle', marginLeft: '0.35rem' }} />
                          فك تشفير ناجح
                        </h4>
                        <div className="byte-inspector" style={{ textAlign: 'center' }}>
                          <div style={{ marginBottom: '0.5rem' }}><strong>HMAC:</strong> {payloadInfo.hmac.slice(0, 24)}...</div>
                          <div style={{ marginBottom: '0.5rem' }}><strong>أول بايتات المحتوى المسترجع:</strong> <span dir="ltr">{roundTrip.preview}</span></div>
                          <div style={{ color: 'var(--green-bright)' }}>✓ نتيجة منفّذة — المحتوى سليم ومتطابق</div>
                        </div>
                      </>
                    )}
                    {verifyScenario === 'wrong_password' && (
                      <>
                        <h4 style={{ color: 'var(--red)', fontSize: '0.95rem', marginBottom: '0.75rem', textAlign: 'center' }}>
                          <ShieldAlert size={18} style={{ verticalAlign: 'middle', marginLeft: '0.35rem' }} />
                          HMAC لا يتطابق — رفض
                        </h4>
                        <div className="byte-inspector" style={{ textAlign: 'center' }}>
                          <div style={{ marginBottom: '0.5rem' }}><strong>المتوقع:</strong> {payloadInfo.hmac.slice(0, 24)}...</div>
                          <div style={{ marginBottom: '0.5rem' }}><strong>المحسوب:</strong> وسم آخر لأن K_auth مختلف</div>
                          <div style={{ color: 'var(--red)' }}>سيناريو شرح: يفشل التحقق قبل فك CBC</div>
                        </div>
                      </>
                    )}
                    {verifyScenario === 'wrong_frame' && (
                      <>
                        <h4 style={{ color: 'var(--amber)', fontSize: '0.95rem', marginBottom: '0.75rem', textAlign: 'center' }}>
                          <ShieldAlert size={18} style={{ verticalAlign: 'middle', marginLeft: '0.35rem' }} />
                          سياق مختلف — رفض الاسترجاع
                        </h4>
                        <div className="byte-inspector" style={{ textAlign: 'center' }}>
                          <div style={{ marginBottom: '0.5rem' }}><strong>البصمة المطلوبة:</strong> {vfcTrace.fingerprint.bytesHex}</div>
                          <div style={{ marginBottom: '0.5rem' }}><strong>إطار مختلف:</strong> بصمة أخرى → K_embed وK_enc وK_auth كلها تتغير</div>
                          <div style={{ color: 'var(--amber)' }}>⚠️ تختلف مواضع العينات، فغالباً تفشل علامة magic مبكراً، وإن وصلت الحمولة كاملة فسيرفضها HMAC</div>
                        </div>
                      </>
                    )}
                    {verifyScenario === 'tamper' && (
                      <>
                        <h4 style={{ color: 'var(--red)', fontSize: '0.95rem', marginBottom: '0.75rem', textAlign: 'center' }}>
                          <ShieldAlert size={18} style={{ verticalAlign: 'middle', marginLeft: '0.35rem' }} />
                          تشوّه مكتشف — HMAC رفض التعديل
                        </h4>
                        <div className="byte-inspector" style={{ textAlign: 'center' }}>
                          <div style={{ marginBottom: '0.5rem' }}><strong>قبل التشوّه:</strong> {payloadInfo.hmac.slice(0, 20)}...</div>
                          <div style={{ marginBottom: '0.5rem' }}><strong>بعد التشوّه:</strong> يصبح الوسم المحسوب غير مطابق</div>
                          <div style={{ color: 'var(--red)' }}>سيناريو شرح: يرفض HMAC الحمولة المعدّلة</div>
                        </div>
                      </>
                    )}
                  </motion.div>
                )}

                <div style={{ display: 'flex', gap: '1rem', justifyContent: 'center', marginTop: '1.5rem' }}>
                  <button className="button button--quiet" onClick={() => { setStep(0); setAudioResult(null); setVerifyScenario(null); }}>إعادة المحاكاة</button>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </div>

      <div hidden={studioMode !== 'recover'} className="card studio-recovery">
        <div className="studio-recovery-heading">
          <div>
            <h3>استرجع الملف من WAV الذي نزّلته</h3>
            <p>يقرأ المتصفح 50B أولاً لمعرفة الملح والطول، ثم يستخرج الحمولة كاملة ويفحص HMAC قبل فك CBC/SPN.</p>
          </div>
          <EvidenceTag tone="source">Header-first extraction</EvidenceTag>
        </div>

        <div className="studio-recovery-form">
          <div className="studio-input-block studio-input-block--wide">
            <label htmlFor="recovery-wav">ملف WAV المعدّل:</label>
            <input id="recovery-wav" type="file" accept="audio/wav,.wav" onChange={handleRecoveryCarrierChange} />
            {recoveryCarrier && recoveryCapacity && (
              <div className="studio-file-facts">
                <strong>{recoveryCarrier.name}</strong>
                <span>{recoveryCarrier.audio.sampleRate.toLocaleString()} Hz · {recoveryCarrier.audio.channelCount === 1 ? 'Mono' : `${recoveryCarrier.audio.channelCount} channels`}</span>
                <span>{recoveryCapacity.eligibleSamples.toLocaleString()} عينة مؤهلة</span>
              </div>
            )}
          </div>
          <div className="studio-input-block">
            <label htmlFor="recovery-password">كلمة المرور:</label>
            <input id="recovery-password" type="password" value={password} onChange={(event) => setPassword(event.target.value)} />
          </div>
          <div className="studio-input-block">
            <label htmlFor="recovery-frame">رقم الإطار:</label>
            <input id="recovery-frame" type="number" min={0} max={4294967295} value={frameNumber} onChange={(event) => setFrameNumber(Math.max(0, Number(event.target.value) || 0))} />
          </div>
          <div className="studio-input-block studio-input-block--wide">
            <label>صورة الإطار أو البصمة الحالية:</label>
            <div className="studio-frame-context">
              {previewUrl ? <img src={previewUrl} alt="الإطار المختار" /> : <ImageIcon size={24} aria-hidden="true" />}
              <input type="file" accept="image/*" onChange={handleFileChange} />
              <Hex>{aHashHex}</Hex>
            </div>
          </div>
        </div>

        <button type="button" className="button button--primary studio-recover-action" onClick={handleRecover} disabled={isRecovering || !recoveryCarrier}>
          <ShieldCheck size={18} aria-hidden="true" />
          {isRecovering ? 'جاري استخراج البتات والتحقق...' : 'استخراج وفحص واسترجاع'}
        </button>

        {recoveryError && <div className="studio-message is-error" role="alert">{recoveryError}</div>}
        {recoveryResult && (
          <div className="studio-message is-success" role="status">
            <CheckCircle2 size={22} aria-hidden="true" />
            <div>
              <strong>نجح الاسترجاع بعد فحص HMAC</strong>
              <span>{recoveryResult.filename} · حمولة {recoveryResult.payloadBytes}B</span>
              <p>{recoveryResult.byteLength.toLocaleString()}B · <span dir="ltr">{recoveryResult.preview}</span></p>
              <a className="button button--quiet" href={recoveryResult.url} download={recoveryResult.filename}>تحميل الملف المسترجع</a>
            </div>
          </div>
        )}
      </div>

      <div className="studio-byte-journey" aria-label="رحلة أول بايت من الرسالة">
        <div className="studio-byte-intro">
          <strong>اتبع أول بايت</strong>
          <span>القيمة تبدأ <Hex>0x{(secretMode === 'file' && secretFile ? secretFile.data[0] : new TextEncoder().encode(secret || ' ')[0]).toString(16).padStart(2, '0')}</Hex>، ثم تفقد هويتها المنفردة عندما تنتشر داخل SPN.</span>
        </div>
        {[
          ['الملف', secretMode === 'file' ? 'بايت من الملف المرفوع' : 'بايت UTF-8'],
          ['الحزمة الداخلية', 'بعد الاسم والحجم والعَلَم'],
          ['CBC', 'Xᵢ = Pᵢ XOR السابق'],
          ['SPN', 'ينتشر أثره عبر الكتلة'],
          ['الحمولة', 'داخل ciphertext الموثق'],
          ['الصوت', 'ثمانية بتات في ثماني عينات'],
        ].map(([title, detail], index) => (
          <div className="studio-byte-stop" key={title}>
            <b>{index + 1}</b><strong>{title}</strong><span>{detail}</span>
          </div>
        ))}
      </div>
    </section>
  )
}

const sectionComponents: Record<LabSection, (props: { onNavigate: (sec: LabSection) => void }) => ReactNode> = {
  overview: ({ onNavigate }) => <OverviewLab onNavigate={onNavigate} />,
  studio: () => <StudioLab />,
  fingerprint: ({ onNavigate }) => <FingerprintLab onNavigate={onNavigate} />,
  keys: () => <KeysLab />,
  field: () => <GaloisFieldLab />,
  cipher: () => <CipherLab />,
  diffusion: () => <DiffusionLab />,
  cbc: () => <CbcLab />,
  payload: () => <PayloadLab />,
  audio: () => <AudioLab />,
  evidence: () => <EvidenceLab />,
}

export function LabView() {
  const [section, setSectionState] = useState<LabSection>(() => {
    const candidate = new URLSearchParams(window.location.search).get('section')
    return navItems.some((item) => item.id === candidate) ? candidate as LabSection : 'overview'
  })
  const [guided, setGuided] = useState(readGuideModeFromUrl)
  const [sidebarCollapsed, setSidebarCollapsed] = useState(readGuideModeFromUrl)
  const currentIndex = navItems.findIndex((item) => item.id === section)
  const currentItem = navItems[currentIndex]
  const guidedIndex = guidedSections.indexOf(section)

  const updateUrl = (next: LabSection, guideMode: boolean, push = false) => {
    const url = new URL(window.location.href)
    if (next === 'overview') url.searchParams.delete('section')
    else url.searchParams.set('section', next)
    if (guideMode) url.searchParams.set('guide', '1')
    else url.searchParams.delete('guide')
    const finalUrl = `${url.pathname}${url.search}#lab`
    if (push) {
      window.history.pushState(null, '', finalUrl)
    } else {
      window.history.replaceState(null, '', finalUrl)
    }
  }

  const setSection = (next: LabSection, guideMode = guided) => {
    setSectionState(next)
    setGuided(guideMode)
    updateUrl(next, guideMode, true)
    window.scrollTo({ top: 0, behavior: 'instant' })
  }

  const startGuide = () => {
    setSidebarCollapsed(true)
    setSection(guidedSections[0], true)
  }

  const exitGuide = () => {
    setGuided(false)
    setSidebarCollapsed(false)
    updateUrl(section, false, true)
  }

  const moveGuide = (direction: -1 | 1) => {
    const nextIndex = guidedIndex + direction
    if (nextIndex < 0) return
    if (nextIndex >= guidedSections.length) {
      exitGuide()
      return
    }
    setSection(guidedSections[nextIndex], true)
  }

  useEffect(() => {
    const enforceLabHash = () => {
      if (window.location.hash === '#lab') return
      const url = new URL(window.location.href)
      window.history.replaceState(null, '', `${url.pathname}${url.search}#lab`)
    }
    const handlePopState = () => {
      const params = new URLSearchParams(window.location.search)
      const candidate = params.get('section') as LabSection | null
      if (candidate && navItems.some((item) => item.id === candidate)) {
        setSectionState(candidate)
      } else {
        setSectionState('overview')
      }
      setGuided(params.get('guide') === '1')
    }

    enforceLabHash()
    window.addEventListener('hashchange', enforceLabHash)
    window.addEventListener('popstate', handlePopState)
    return () => {
      window.removeEventListener('hashchange', enforceLabHash)
      window.removeEventListener('popstate', handlePopState)
    }
  }, [])

  useEffect(() => {
    document.title = `VFC | ${navItems[currentIndex].label}`
    const url = new URL(window.location.href)
    if (section === 'overview') url.searchParams.delete('section')
    else url.searchParams.set('section', section)
    if (guided) url.searchParams.set('guide', '1')
    else url.searchParams.delete('guide')
    window.history.replaceState(null, '', `${url.pathname}${url.search}#lab`)
    window.requestAnimationFrame(() => {
      document.getElementById(`lab-nav-${section}`)?.scrollIntoView({ block: 'nearest', inline: 'center', behavior: 'instant' })
    })
  }, [currentIndex, guided, section])

  const onNavKeyDown = (event: KeyboardEvent<HTMLButtonElement>, index: number) => {
    if (!['ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight'].includes(event.key)) return
    event.preventDefault()
    const direction = ['ArrowDown', 'ArrowLeft'].includes(event.key) ? 1 : -1
    const next = (index + direction + navItems.length) % navItems.length
    setSection(navItems[next].id, false)
    document.getElementById(`lab-nav-${navItems[next].id}`)?.focus()
  }

  return (
    <div className={`lab-shell${sidebarCollapsed ? ' is-nav-collapsed' : ''}`}>
      <aside className="lab-sidebar" aria-label="فصول مختبر التشفير">
        <div className="lab-sidebar-head">
          {!sidebarCollapsed && (
            <div className="lab-sidebar-titles">
              <span>VFC CRYPTO LAB</span>
              <small><i className="proof-dot" aria-hidden="true" /> أثر تنفيذي موثّق · v0.2</small>
            </div>
          )}
          <button
            type="button"
            className="sidebar-collapse-toggle"
            onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
            title={sidebarCollapsed ? 'توسيع القائمة الجانبية' : 'طي القائمة الجانبية (لتوفير مساحة كاملة)'}
            aria-label={sidebarCollapsed ? 'توسيع القائمة' : 'طي القائمة'}
          >
            {sidebarCollapsed ? <ChevronLeft size={18} aria-hidden="true" /> : <ChevronRight size={18} aria-hidden="true" />}
          </button>
        </div>
        <nav aria-label="موضوعات المختبر">
          {navGroups.map((group) => (
            <div className="lab-nav-group" key={group.id}>
              <span className="lab-nav-group-label">{group.label}</span>
              {navItems.filter((item) => item.group === group.id).map((item) => {
                const index = navItems.findIndex((candidate) => candidate.id === item.id)
                const Icon = item.icon
                return (
                  <button
                    id={`lab-nav-${item.id}`}
                    key={item.id}
                    type="button"
                    aria-current={section === item.id ? 'page' : undefined}
                    aria-label={`${item.label}: ${item.caption}`}
                    tabIndex={section === item.id ? 0 : -1}
                    className={section === item.id ? 'is-active' : ''}
                    onClick={() => setSection(item.id, false)}
                    onKeyDown={(event) => onNavKeyDown(event, index)}
                    title={sidebarCollapsed ? `${item.label} (${item.caption})` : undefined}
                  >
                    <Icon size={19} strokeWidth={1.7} aria-hidden="true" />
                    <span><strong>{item.label}</strong><small>{item.caption}</small></span>
                    <Hex>{String(index + 1).padStart(2, '0')}</Hex>
                  </button>
                )
              })}
            </div>
          ))}
        </nav>
      </aside>
      <div className="lab-main" id="lab-panel" aria-labelledby={`lab-nav-${section}`}>
        <div className={`lab-context-bar${guided ? ' is-guided' : ''}`}>
          <div className="lab-context-title">
            <span>{guided ? `المسار السريع · محطة ${guidedIndex + 1}/${guidedSections.length}` : `المختبر المباشر · ${currentIndex + 1}/${navItems.length}`}</span>
            <strong>{currentItem.label}</strong>
          </div>
          <div className="lab-context-message">
            <p>{currentItem.talkTrack}</p>
            <span><b>جرّب الآن:</b> {currentItem.demoAction}</span>
          </div>
          <div className="lab-context-actions">
            {guided ? (
              <>
                <button type="button" className="icon-button" onClick={() => moveGuide(-1)} disabled={guidedIndex <= 0} aria-label="المحطة السابقة">
                  <ChevronRight size={18} aria-hidden="true" />
                </button>
                <button type="button" className="button button--primary" onClick={() => moveGuide(1)}>
                  {guidedIndex === guidedSections.length - 1 ? 'إنهاء المسار' : 'المحطة التالية'}
                  {guidedIndex < guidedSections.length - 1 && <ChevronLeft size={18} aria-hidden="true" />}
                </button>
                <button type="button" className="button button--quiet guide-exit" onClick={exitGuide}>خروج</button>
              </>
            ) : (
              <button type="button" className="button button--primary" onClick={startGuide}>
                <Play size={18} aria-hidden="true" />
                المسار السريع ({guidedSections.length} محطات)
              </button>
            )}
          </div>
          {guided && (
            <div
              className="lab-guide-progress"
              style={{ gridTemplateColumns: `repeat(${guidedSections.length}, 1fr)` }}
              role="progressbar"
              aria-valuemin={1}
              aria-valuemax={guidedSections.length}
              aria-valuenow={guidedIndex + 1}
              aria-label="تقدم الشرح الموجّه"
            >
              {guidedSections.map((item, index) => <i key={item} className={index <= guidedIndex ? 'is-complete' : ''} />)}
            </div>
          )}
        </div>
        {(() => {
          const CurrentComponent = sectionComponents[section]
          return <CurrentComponent onNavigate={(nextSec) => setSection(nextSec)} />
        })()}
      </div>
    </div>
  )
}
