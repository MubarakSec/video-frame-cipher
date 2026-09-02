import { useState, useEffect, useRef, type CSSProperties, type ReactNode } from 'react'
import {
  Braces,
  Check,
  FileKey2,
  KeyRound,
  Link2,
} from 'lucide-react'
import { vfcTrace } from '../data/vfc-trace'
import { pipelineStages } from '../pipeline'

export function Hex({ children, className = '' }: { children: ReactNode; className?: string }) {
  return (
    <bdi dir="ltr" className={`hex ${className}`.trim()}>
      {children}
    </bdi>
  )
}

type Matrix = readonly (readonly string[])[]

export function StateMatrix({
  grid,
  compare,
  label = 'حالة الشيفرة 4×4 بايت',
  compact = false,
  emphasize,
  onCellClick,
  selectedCell,
}: {
  grid: Matrix
  compare?: Matrix
  label?: string
  compact?: boolean
  emphasize?: number[]
  onCellClick?: (r: number, c: number) => void
  selectedCell?: { r: number; c: number } | null
}) {
  return (
    <div className={`state-matrix-wrap${compact ? ' is-compact' : ''}`}>
      <table className="state-matrix" aria-label={label}>
        <thead>
          <tr>
            <th><span className="sr-only">إحداثيات الصف والعمود</span></th>
            {[0, 1, 2, 3].map((column) => <th key={column} scope="col">c{column}</th>)}
          </tr>
        </thead>
        <tbody>
          {grid.map((row, rowIndex) => (
            <tr key={rowIndex}>
              <th scope="row">r{rowIndex}</th>
              {row.map((value, columnIndex) => {
                const serializedIndex = columnIndex * 4 + rowIndex
                const changed = compare ? compare[rowIndex]?.[columnIndex] !== value : false
                const marked = emphasize?.includes(serializedIndex)
                const isSelected = selectedCell?.r === rowIndex && selectedCell?.c === columnIndex
                const cellClasses = [
                  changed || marked ? 'is-changed' : '',
                  isSelected ? 'is-selected-cell' : '',
                  onCellClick ? 'is-clickable' : '',
                ].filter(Boolean).join(' ') || undefined

                return (
                  <td
                    key={`${rowIndex}-${columnIndex}`}
                    className={cellClasses}
                    onClick={onCellClick ? () => onCellClick(rowIndex, columnIndex) : undefined}
                    role={onCellClick ? 'button' : undefined}
                    tabIndex={onCellClick ? 0 : undefined}
                    onKeyDown={onCellClick ? (e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault()
                        onCellClick(rowIndex, columnIndex)
                      }
                    } : undefined}
                    aria-label={`الصف ${rowIndex}، العمود ${columnIndex}: ${value}${changed ? '، مختلف' : ''}${isSelected ? '، محدد' : ''}`}
                  >
                    <Hex>{value.toUpperCase()}</Hex>
                    {(changed || marked) && <span className="change-mark" aria-hidden="true">×</span>}
                  </td>
                )
              })}
            </tr>
          ))}
        </tbody>
      </table>
      {!compact && <p className="matrix-note">التسلسل إلى البايتات عموديّ الأعمدة (Column-major order)</p>}
    </div>
  )
}

export function FingerprintGrid({
  mode = 'bits',
  customBits,
  customAverages,
  customMedian,
}: {
  mode?: 'bits' | 'averages'
  customBits?: readonly (readonly number[])[] | number[][]
  customAverages?: readonly (readonly number[])[] | number[][]
  customMedian?: number
}) {
  const bits = customBits ?? vfcTrace.fingerprint.bits
  const averages = customAverages ?? vfcTrace.fingerprint.blockAverages
  const median = customMedian ?? vfcTrace.fingerprint.median
  const values = mode === 'bits' ? bits : averages

  return (
    <div
      className={`fingerprint-grid fingerprint-grid--${mode}`}
      role="img"
      aria-label={mode === 'bits'
        ? `شبكة بصمة من 64 بت`
        : `متوسطات 64 كتلة، الوسيط ${median.toFixed(2)}`}
    >
      {values.flatMap((row, rowIndex) => row.map((value, columnIndex) => (
        <span
          key={`${rowIndex}-${columnIndex}`}
          className={Number(value) >= (mode === 'bits' ? 1 : median) ? 'is-one' : 'is-zero'}
          title={`r${rowIndex}, c${columnIndex}: ${mode === 'bits' ? value : Number(value).toFixed(2)}`}
        >
          {mode === 'bits' ? value : Math.round(Number(value))}
        </span>
      )))}
    </div>
  )
}

export function PipelineDiagram({
  active,
  onSelect,
  compact = false,
}: {
  active?: string
  onSelect?: (id: string) => void
  compact?: boolean
}) {
  return (
    <div className={`crypto-pipeline${compact ? ' is-compact' : ''}`} role={onSelect ? 'group' : 'img'} aria-label="مسار VFC الكامل">
      {pipelineStages.map((stage, index) => {
        const Icon = stage.icon
        const content = (
          <>
            <span className="pipeline-index">{String(index + 1).padStart(2, '0')}</span>
            <Icon size={compact ? 18 : 22} strokeWidth={1.6} aria-hidden="true" />
            <span>
              <strong>{stage.label}</strong>
              {!compact && <small>{stage.caption}</small>}
            </span>
            <span className="trace-node" aria-hidden="true" />
          </>
        )
        return (
          <div key={stage.id} className="pipeline-segment">
            {onSelect ? (
              <button
                type="button"
                className={active === stage.id ? 'is-active' : ''}
                aria-pressed={active === stage.id}
                onClick={() => onSelect(stage.id)}
              >
                {content}
              </button>
            ) : (
              <div className={active === stage.id ? 'is-active' : ''}>{content}</div>
            )}
            {index < pipelineStages.length - 1 && <span className="pipeline-link" aria-hidden="true">←</span>}
          </div>
        )
      })}
    </div>
  )
}

const keyLabels = {
  embedding: { short: 'K_embed', arabic: 'مواضع الإخفاء', tone: 'tan' },
  encryption: { short: 'K_enc', arabic: 'مفتاح الشيفرة', tone: 'red' },
  authentication: { short: 'K_auth', arabic: 'مفتاح HMAC', tone: 'paper' },
} as const

export function KeyTree({
  selected = 'encryption',
  outputs,
}: {
  selected?: keyof typeof keyLabels
  outputs?: Partial<Record<keyof typeof keyLabels, string | null>>
}) {
  return (
    <div className="key-tree" role="img" aria-label="اشتقاق ثلاثة مفاتيح مفصولة المجالات من كلمة المرور والسياق">
      <div className="key-tree-source">
        <KeyRound size={20} aria-hidden="true" />
        <span>كلمة المرور</span>
        <b>PBKDF2</b>
        <small><Hex>200,000</Hex> دورة خلط</small>
      </div>

      <svg className="key-tree-svg-branches" viewBox="0 0 600 60" preserveAspectRatio="none" aria-hidden="true">
        {/* Main stem from source */}
        <line x1="300" y1="0" x2="300" y2="30" stroke="var(--tan)" strokeWidth="2.5" />
        
        {/* Horizontal connector bar */}
        <line x1="100" y1="30" x2="500" y2="30" stroke="var(--tan)" strokeWidth="2.5" />

        {/* Branch 1 (K_embed) */}
        <line x1="100" y1="30" x2="100" y2="60" stroke={selected === 'embedding' ? 'var(--tan)' : 'var(--line-dark)'} strokeWidth="2.5" />
        <circle cx="100" cy="58" r="4" fill={selected === 'embedding' ? 'var(--tan)' : 'var(--line-dark)'} />

        {/* Branch 2 (K_enc) */}
        <line x1="300" y1="30" x2="300" y2="60" stroke={selected === 'encryption' ? 'var(--tan)' : 'var(--line-dark)'} strokeWidth="2.5" />
        <circle cx="300" cy="58" r="4" fill={selected === 'encryption' ? 'var(--tan)' : 'var(--line-dark)'} />

        {/* Branch 3 (K_auth) */}
        <line x1="500" y1="30" x2="500" y2="60" stroke={selected === 'authentication' ? 'var(--tan)' : 'var(--line-dark)'} strokeWidth="2.5" />
        <circle cx="500" cy="58" r="4" fill={selected === 'authentication' ? 'var(--tan)' : 'var(--line-dark)'} />
      </svg>

      <div className="key-tree-outputs">
        {(Object.keys(keyLabels) as Array<keyof typeof keyLabels>).map((key) => {
          const record = vfcTrace.kdf[key]
          const label = keyLabels[key]
          const output = outputs ? outputs[key] : record.outputHex
          return (
            <div key={key} className={`${selected === key ? 'is-selected' : ''} tone-${label.tone}`}>
              <strong><Hex>{label.short}</Hex></strong>
              <span>{label.arabic}</span>
              <small>{record.pbkdf2SaltPartsInExactOrder.some((part) => part.name === 'random salt') ? 'مع ملح عشوائي' : 'بلا ملح عشوائي'}</small>
              <Hex className="key-preview">{output ? `${output.slice(0, 12)}…` : 'بانتظار الاشتقاق'}</Hex>
            </div>
          )
        })}
      </div>
    </div>
  )
}

export function RoundFlow({ active = 'mixColumns' }: { active?: string }) {
  const layers = [
    { id: 'subBytes', label: 'SubBytes', sub: 'استبدال غير خطي' },
    { id: 'shiftRows', label: 'ShiftRows', sub: 'نقل بين الأعمدة' },
    { id: 'mixColumns', label: 'MixColumns', sub: 'مزج داخل GF(2⁸)' },
    { id: 'addRoundKey', label: 'AddRoundKey', sub: 'XOR مع RKᵣ' },
  ]
  return (
    <div className="round-flow" aria-label="طبقات الجولة الكاملة">
      {layers.map((layer, index) => (
        <div key={layer.id} className="round-flow-item">
          <div className={active === layer.id ? 'is-active' : ''}>
            <span>{index + 1}</span>
            <strong><Hex>{layer.label}</Hex></strong>
            <small>{layer.sub}</small>
          </div>
          {index < layers.length - 1 && <span aria-hidden="true">→</span>}
        </div>
      ))}
    </div>
  )
}

export function ShiftRowsVisualizer({ state }: { state: Matrix }) {
  const shifts = [0, 1, 2, 3]
  return (
    <div className="shiftrows-visualizer">
      <h2>محاكاة حركة إزاحة الصفوف (ShiftRows Mechanism)</h2>
      <p className="shiftrows-desc">
        تُزاح بايتات كل صف دورياً نحو اليسار بمقدار رقم الصف <Hex>r</Hex> (<Hex>c ⟵ (c + r) mod 4</Hex>) لنقل تأثير التغيير بين الأعمدة.
      </p>
      <div className="shiftrows-rows-list">
        {shifts.map((shift, r) => {
          const originalRow = [state[r][0], state[r][1], state[r][2], state[r][3]]
          const shiftedRow = [
            originalRow[shift % 4],
            originalRow[(shift + 1) % 4],
            originalRow[(shift + 2) % 4],
            originalRow[(shift + 3) % 4],
          ]
          return (
            <div key={r} className="shiftrows-row-card">
              <div className="row-meta">
                <span>الصف {r}:</span>
                <small>{shift === 0 ? 'بلا إزاحة (0 خانات)' : `إزاحة يسار ${shift} خانات (<<< ${shift})`}</small>
              </div>
              <div className="row-cells-track" dir="ltr">
                <div className="row-cells before" dir="ltr" title={`الصف ${r} قبل الإزاحة (c0..c3)`}>
                  {originalRow.map((b, i) => (
                    <span key={i} title={`c${i}: 0x${b}`}><Hex>{b}</Hex></span>
                  ))}
                </div>
                <span className="shift-arrow-icon" aria-hidden="true">→</span>
                <div className="row-cells after" dir="ltr" title={`الصف ${r} بعد الإزاحة`}>
                  {shiftedRow.map((b, i) => {
                    const originalCol = (i + shift) % 4
                    const isWrapped = originalCol < shift
                    return (
                      <span
                        key={i}
                        className={shift > 0 ? (isWrapped ? 'is-shifted is-wrapped' : 'is-shifted') : ''}
                        title={`الناتج في c${i} (أصله c${originalCol}): 0x${b}`}
                      >
                        <Hex>{b}</Hex>
                      </span>
                    )
                  })}
                </div>
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

export function CbcDiagram({ compact = false, dynamicBlocks }: { compact?: boolean, dynamicBlocks?: any[] }) {
  const blocks = dynamicBlocks || vfcTrace.cbc.blocks
  return (
    <div className={`cbc-diagram${compact ? ' is-compact' : ''}`} role="img" tabIndex={0} aria-label="تسلسل كتلتين في نمط CBC">
      {blocks.map((block, index) => (
        <div className="cbc-block" key={block.block || index + 1}>
          <div className="cbc-value">
            <span>{index === 0 ? 'IV' : `C${index}`}</span>
            <Hex>{block.previousHex ? block.previousHex.slice(0, 8) : block.previous?.slice(0, 8)}…</Hex>
          </div>
          <div className="cbc-xor" aria-label="عملية XOR">⊕</div>
          <div className="cbc-value">
            <span>P{block.block || index + 1}</span>
            <Hex>{block.plaintextHex ? block.plaintextHex.slice(0, 8) : block.plaintext?.slice(0, 8)}…</Hex>
          </div>
          <div className="cbc-arrow" aria-hidden="true">→</div>
          <div className="cbc-cipher">
            <FileKey2 size={22} aria-hidden="true" />
            <span>SPN</span>
          </div>
          <div className="cbc-arrow" aria-hidden="true">→</div>
          <div className="cbc-value is-output">
            <span>C{block.block || index + 1}</span>
            <Hex>{block.ciphertextHex ? block.ciphertextHex.slice(0, 8) : block.ciphertext?.slice(0, 8)}…</Hex>
          </div>
          {index === 0 && (
            <div className="cbc-chain-note" aria-label="الناتج C1 يعود إلى مدخل XOR في الكتلة التالية">
              <Link2 size={16} aria-hidden="true" />
              <span><Hex>C1</Hex> يعود إلى <Hex>XOR</Hex> التالي</span>
              <b aria-hidden="true">↪</b>
            </div>
          )}
        </div>
      ))}
    </div>
  )
}

export function PayloadRuler({
  selected,
  onSelect,
  compact = false,
}: {
  selected?: string
  onSelect?: (name: string) => void
  compact?: boolean
}) {
  const total = vfcTrace.payload.totalBytes
  return (
    <div
      className={`payload-ruler${compact ? ' is-compact' : ''}`}
      role={onSelect ? 'group' : 'img'}
      tabIndex={onSelect ? undefined : 0}
      aria-label={`خريطة حمولة المتجه المسجل بطول ${vfcTrace.payload.totalBytes} بايت`}
    >
      <div className="payload-offsets" aria-hidden="true">
        <span>0</span><span>6</span><span>22</span><span>38</span><span>50</span><span>82</span><span>114</span>
      </div>
      <div className="payload-fields" aria-label={`حقول حمولة المتجه المسجل بطول ${total} بايت`}>
        {vfcTrace.payload.fields.map((field) => {
          const style = { '--field-weight': Math.max(field.sizeBytes, 5) } as CSSProperties
          const content = (
            <>
              <strong><Hex>{field.name}</Hex></strong>
              {!compact && <span>{field.sizeBytes} B</span>}
            </>
          )
          return onSelect ? (
            <button
              key={field.name}
              type="button"
              style={style}
              className={`${selected === field.name ? 'is-selected' : ''} field-${field.name}`}
              onClick={() => onSelect(field.name)}
              aria-pressed={selected === field.name}
            >
              {content}
            </button>
          ) : (
            <div key={field.name} style={style} className={`field-${field.name}`}>{content}</div>
          )
        })}
      </div>
      <div className="authenticated-bracket">
        <Braces size={16} aria-hidden="true" />
        HMAC يغطي البايتات <Hex>0…81</Hex>؛ الوسم نفسه خارج النطاق
      </div>
    </div>
  )
}

function fixtureSample(index: number) {
  return ((0x9e37 * index) % 36_000) - 18_000
}

export function AudioWaveformVisual({ compact = false }: { compact?: boolean }) {
  const width = 900
  const height = compact ? 130 : 210
  const middle = height / 2
  const pointCount = 240
  const points = Array.from({ length: pointCount }, (_, i) => {
    const sampleIndex = Math.round((i / (pointCount - 1)) * 47_999)
    const y = middle - (fixtureSample(sampleIndex) / 18_000) * (middle - 16)
    const x = (i / (pointCount - 1)) * width
    return `${x.toFixed(1)},${y.toFixed(1)}`
  }).join(' ')
  const markers = vfcTrace.audioEmbedding.first32ShuffledPositions.slice(0, compact ? 8 : 14)

  return (
    <div className="waveform-visual">
      <svg viewBox={`0 0 ${width} ${height}`} role="img" aria-labelledby="wave-title wave-desc">
        <title id="wave-title">الموجة الحتمية ومواضع الإخفاء</title>
        <desc id="wave-desc">مقطع من حامل المتجه التعليمي الاصطناعي، والخطوط المعلّمة هي أول مواضع Fisher–Yates.</desc>
        <line x1="0" y1={middle} x2={width} y2={middle} className="wave-axis" />
        <polyline points={points} className="wave-line" />
        {markers.map((position, index) => {
          const x = (position / 47_999) * width
          return (
            <g key={position} className="wave-marker">
              <line x1={x} y1="8" x2={x} y2={height - 8} />
              {!compact && <text x={x + 4} y={16 + (index % 2) * 14}>{index + 1}</text>}
            </g>
          )
        })}
      </svg>
      <div className="wave-legend">
        <span><i className="legend-wave" /> حامل PCM التعليمي</span>
        <span><i className="legend-position" /> موضع مشتق من <Hex>K_embed</Hex></span>
      </div>
    </div>
  )
}

function gmul(a: number, b: number): number {
  let p = 0
  let aa = a & 0xff
  let bb = b & 0xff
  for (let i = 0; i < 8; i++) {
    if (bb & 1) p ^= aa
    const high = aa & 0x80
    aa = (aa << 1) & 0xff
    if (high) aa ^= 0x1b
    bb >>= 1
  }
  return p & 0xff
}

function bytePolynomial(value: number) {
  if (value === 0) return '0'
  const superscripts = ['⁰', '¹', '²', '³', '⁴', '⁵', '⁶', '⁷']
  return Array.from({ length: 8 }, (_, index) => 7 - index)
    .filter((power) => value & (1 << power))
    .map((power) => power === 0 ? '1' : power === 1 ? 'x' : `x${superscripts[power]}`)
    .join(' + ')
}

function byteHex(value: number) {
  return value.toString(16).padStart(2, '0').toUpperCase()
}

export function GaloisFieldExplorer() {
  const [a, setA] = useState(0x83)
  const [b, setB] = useState(0x53)
  const xor = a ^ b
  const shifted = (a << 1) & 0xff
  const reduced = (a & 0x80) !== 0
  const timesTwo = gmul(a, 2)
  const timesThree = gmul(a, 3)

  const updateByte = (raw: string, setter: (value: number) => void) => {
    const clean = raw.replace(/^0x/i, '').slice(0, 2)
    if (/^[0-9a-fA-F]{1,2}$/.test(clean)) setter(parseInt(clean, 16))
  }

  const renderMatrix = (matrix: readonly (readonly number[])[], label: string) => (
    <div className="gf-matrix" aria-label={label}>
      {matrix.flatMap((row, rowIndex) => row.map((cell, columnIndex) => (
        <Hex key={`${rowIndex}-${columnIndex}`}>{cell.toString(16).toUpperCase()}</Hex>
      )))}
    </div>
  )

  return (
    <div className="gf-explorer">
      <div className="gf-intro-grid">
        <section>
          <span className="gf-kicker">الفكرة الأولى</span>
          <h2>البايت كثير حدود، لا عدداً عادياً</h2>
          <p>في <Hex>GF(2⁸)</Hex> تمثل كل بتة وجود حد من حدود كثير الحدود. لذلك لا يوجد حمل عند الجمع: كل معامل إما صفر أو واحد.</p>
          <label htmlFor="gf-byte-a">البايت A</label>
          <div className="gf-byte-control">
            <span>0x</span>
            <input id="gf-byte-a" type="text" value={byteHex(a)} onChange={(event) => updateByte(event.target.value, setA)} dir="ltr" maxLength={2} />
            <input type="range" min="0" max="255" value={a} onChange={(event) => setA(Number(event.target.value))} aria-label="قيمة البايت A" />
          </div>
          <div className="gf-byte-reading" dir="ltr">
            <Hex>{a.toString(2).padStart(8, '0')}</Hex>
            <span>⇔</span>
            <Hex>{bytePolynomial(a)}</Hex>
          </div>
        </section>

        <section>
          <span className="gf-kicker">الفكرة الثانية</span>
          <h2>الجمع هو XOR</h2>
          <p>جمع المعاملات بترديد 2 يعني أن <Hex>1 + 1 = 0</Hex>. لهذا تجمع البايتات بعملية XOR بلا حمل.</p>
          <label htmlFor="gf-byte-b">البايت B</label>
          <div className="gf-byte-control">
            <span>0x</span>
            <input id="gf-byte-b" type="text" value={byteHex(b)} onChange={(event) => updateByte(event.target.value, setB)} dir="ltr" maxLength={2} />
          </div>
          <div className="gf-equation" dir="ltr">
            <Hex>0x{byteHex(a)}</Hex><b> XOR </b><Hex>0x{byteHex(b)}</Hex><b> = </b><Hex>0x{byteHex(xor)}</Hex>
          </div>
          <small dir="ltr">{a.toString(2).padStart(8, '0')} ⊕ {b.toString(2).padStart(8, '0')} = {xor.toString(2).padStart(8, '0')}</small>
        </section>
      </div>

      <section className="gf-reduction-board">
        <div>
          <span className="gf-kicker">الفكرة الثالثة</span>
          <h2>الضرب في 2: إزاحة ثم اختزال عند الحاجة</h2>
          <p>نزيح البتات يساراً. إذا خرج الحد <Hex>x⁸</Hex> من البايت، نختزله بكثير الحدود <Hex>x⁸ + x⁴ + x³ + x + 1 = 0x11B</Hex>. بعد إسقاط بتة <Hex>x⁸</Hex> يظهر الثابت <Hex>0x1B</Hex>.</p>
        </div>
        <div className="gf-reduction-steps" dir="ltr">
          <div><span>1 · shift</span><Hex>0x{byteHex(a)} &lt;&lt; 1 = 0x{byteHex(shifted)}</Hex></div>
          <div className={reduced ? 'is-active' : ''}><span>2 · reduce</span><Hex>{reduced ? `0x${byteHex(shifted)} XOR 0x1B` : 'MSB = 0 → no reduction'}</Hex></div>
          <div><span>result</span><strong><Hex>2 · 0x{byteHex(a)} = 0x{byteHex(timesTwo)}</Hex></strong></div>
          <div><span>×3</span><Hex>3 · A = (2 · A) XOR A = 0x{byteHex(timesThree)}</Hex></div>
        </div>
      </section>

      <section className="gf-matrix-proof">
        <div className="gf-proof-copy">
          <span className="gf-kicker">مكانه داخل VFC</span>
          <h2>MixColumns هي التي تستخدم هذا الحساب</h2>
          <p>كل عمود من الحالة يُضرب في مصفوفة MDS. الأرقام 1 و2 و3 معاملات داخل <Hex>GF(2⁸)</Hex>، ثم تُجمع النواتج بـ XOR. لا يستخدم CBC ولا اشتقاق المفاتيح هذه العملية.</p>
          <p>وجود مصفوفة عكسية يجعل التحويل قابلاً للعكس: ضرب العكس في MDS يعيد مصفوفة الهوية.</p>
        </div>
        <div className="gf-matrix-equation" dir="ltr">
          <div><span>MDS⁻¹</span>{renderMatrix(vfcTrace.cipher.inverseMds, 'مصفوفة MDS العكسية')}</div>
          <b>×</b>
          <div><span>MDS</span>{renderMatrix(vfcTrace.cipher.mds, 'مصفوفة MDS')}</div>
          <b>=</b>
          <div><span>Identity</span>{renderMatrix(vfcTrace.cipher.inverseTimesMds, 'مصفوفة الهوية')}</div>
        </div>
      </section>
    </div>
  )
}

export function InteractiveSBox() {
  const [selectedByte, setSelectedByte] = useState<number>(0x42)
  const [inputHex, setInputHex] = useState<string>('42')
  const [showFullTable, setShowFullTable] = useState(false)

  const hex = selectedByte.toString(16).padStart(2, '0').toUpperCase()
  const binary = selectedByte.toString(2).padStart(8, '0')
  const row = Math.floor(selectedByte / 16)
  const col = selectedByte % 16
  const sboxVal = vfcTrace.cipher.sbox[selectedByte]
  const sboxHex = sboxVal.toString(16).padStart(2, '0').toUpperCase()
  const invVal = vfcTrace.cipher.inverseSbox[sboxVal]
  const invHex = invVal.toString(16).padStart(2, '0').toUpperCase()

  const presets = [0x00, 0x42, 0x53, 0x7D, 0x8F, 0xAA, 0xC6, 0xFF]

  const handleByteSelect = (val: number) => {
    const clamped = Math.max(0, Math.min(255, val))
    setSelectedByte(clamped)
    setInputHex(clamped.toString(16).padStart(2, '0').toUpperCase())
  }

  const handleInputChange = (raw: string) => {
    setInputHex(raw)
    const clean = raw.trim().replace(/^0x/i, '')
    if (clean.length > 0) {
      const parsed = parseInt(clean, 16)
      if (!isNaN(parsed) && parsed >= 0 && parsed <= 255) {
        setSelectedByte(parsed)
      }
    }
  }

  const handleInputBlur = () => {
    setInputHex(hex)
  }

  return (
    <div className="interactive-sbox-card">
      <div className="sbox-card-header">
        <div>
          <h2>فاحص S-Box: من البايت المدخل إلى البايت البديل</h2>
          <p>اختر بايتاً. الأربع بتات العليا تحدد صف الجدول، والأربع السفلى تحدد العمود؛ الخانة عند تقاطعهما هي الناتج.</p>
        </div>
        <div className="preset-buttons">
          <span>أمثلة سريعة:</span>
          {presets.map((p) => (
            <button
              key={p}
              type="button"
              className={selectedByte === p ? 'is-active' : ''}
              onClick={() => handleByteSelect(p)}
            >
              <Hex>0x{p.toString(16).padStart(2, '0').toUpperCase()}</Hex>
            </button>
          ))}
        </div>
      </div>

      <div className="sbox-interactive-grid">
        <div className="sbox-input-col">
          <label htmlFor="sbox-byte-input">البايت المدخل (0x00 .. 0xFF):</label>
          <div className="sbox-input-group">
            <input
              id="sbox-byte-input"
              type="text"
              maxLength={4}
              value={inputHex}
              onChange={(e) => handleInputChange(e.target.value)}
              onBlur={handleInputBlur}
              className="sbox-hex-input"
              dir="ltr"
              placeholder="42"
              aria-label="قيمة البايت بنظام الستة عشري"
            />
            <input
              type="range"
              min="0"
              max="255"
              value={selectedByte}
              onChange={(e) => handleByteSelect(Number(e.target.value))}
              className="sbox-slider"
              aria-label="اختر قيمة البايت من صفر إلى 255"
            />
          </div>
          <div className="sbox-bit-breakdown">
            <span>التمثيل الثنائي:</span>
            <div className="bits-strip" dir="ltr">
              {binary.split('').map((b, i) => (
                <span key={i} className={b === '1' ? 'bit-one' : 'bit-zero'}>{b}</span>
              ))}
            </div>
            <small>إحداثيات S-Box: الصف <Hex>0x{row.toString(16).toUpperCase()}</Hex> · العمود <Hex>0x{col.toString(16).toUpperCase()}</Hex></small>
          </div>
        </div>

        <div className="sbox-results-col">
          <div className="sbox-math-step">
            <div className="step-badge">1. استبدال S-Box</div>
            <div className="step-content">
              <span>S( <Hex>0x{hex}</Hex> ) =</span>
              <strong className="text-highlight"><Hex>0x{sboxHex}</Hex></strong>
              <small>({sboxVal} بالأساس العشري)</small>
            </div>
          </div>

          <div className="sbox-math-step">
            <div className="step-badge">2. الإثبات التقابلي المعكوس</div>
            <div className="step-content">
              <span>S⁻¹( <Hex>0x{sboxHex}</Hex> ) =</span>
              <strong className="text-success"><Hex>0x{invHex}</Hex></strong>
              <span className="badge-pill success">مطابقة تامة ✓</span>
            </div>
          </div>

          <p className="sbox-boundary-note">هنا ينتهي دور <Hex>S-Box</Hex>. حساب <Hex>GF(2⁸)</Hex> يظهر لاحقاً في <Hex>MixColumns</Hex>، لذلك له مختبر مستقل.</p>
        </div>
      </div>

      {/* Full 16x16 S-Box Table */}
      <div style={{ marginTop: '1.25rem', borderTop: '1px solid var(--line-dark)', paddingTop: '1rem' }}>
        <button
          type="button"
          className="button button--quiet"
          onClick={() => setShowFullTable(!showFullTable)}
          style={{ fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: showFullTable ? '1rem' : 0 }}
        >
          <span>{showFullTable ? '−' : '+'}</span>
          الجدول الكامل (256 خانة) — الضغط لعرض جميع مدخلات S-Box
        </button>
        {showFullTable && (
          <div className="sbox-full-table-wrap">
            <table className="sbox-full-table" role="grid" aria-label="جدول S-Box الكامل 16×16">
              <thead>
                <tr>
                  <th></th>
                  {Array.from({ length: 16 }, (_, i) => (
                    <th key={i}>0x{i.toString(16).toUpperCase()}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {Array.from({ length: 16 }, (_, row) => (
                  <tr key={row}>
                    <th>0x{row.toString(16).toUpperCase()}</th>
                    {Array.from({ length: 16 }, (_, col) => {
                      const idx = row * 16 + col
                      const val = vfcTrace.cipher.sbox[idx]
                      const valHex = val.toString(16).padStart(2, '0').toUpperCase()
                      const isSelected = idx === selectedByte
                      return (
                        <td
                          key={col}
                          className={isSelected ? 'is-selected' : ''}
                          onClick={() => handleByteSelect(idx)}
                          title={`S(0x${idx.toString(16).padStart(2, '0').toUpperCase()}) = 0x${valHex}`}
                        >
                          {valHex}
                        </td>
                      )
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
            <div style={{ marginTop: '0.75rem', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              انقر على أي خانة لاختيارها. الصف يمثل الـ4 بتاً العليا (MSB) والعمود يمثل الـ4 بتاً السفلى (LSB) من المدخل.
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

export function MixColumnsVisualizer({
  inputState,
  outputState,
}: {
  inputState: Matrix
  outputState: Matrix
}) {
  const [selectedCol, setSelectedCol] = useState<number>(0)
  const mds = vfcTrace.cipher.mds

  const colIn = [
    parseInt(inputState[0][selectedCol], 16),
    parseInt(inputState[1][selectedCol], 16),
    parseInt(inputState[2][selectedCol], 16),
    parseInt(inputState[3][selectedCol], 16),
  ]

  const rowCalcs = mds.map((row) => {
    const terms = [
      gmul(row[0], colIn[0]),
      gmul(row[1], colIn[1]),
      gmul(row[2], colIn[2]),
      gmul(row[3], colIn[3]),
    ]
    const out = terms[0] ^ terms[1] ^ terms[2] ^ terms[3]
    return {
      coeffs: row,
      terms,
      outHex: out.toString(16).padStart(2, '0').toUpperCase(),
    }
  })

  return (
    <div className="layer-interactive-card mixcolumns-visualizer">
      <div className="layer-card-header">
        <div>
          <h3>محاكاة خلط الأعمدة عبر مصفوفة MDS في <Hex>GF(2⁸)</Hex></h3>
          <p>
            تُضرب كل خانة في مصفوفة الانتشار الخطية الدائرية (Circulant Matrix) باستخدام كثير الحدود <Hex>{vfcTrace.cipher.gfPolynomialHex}</Hex>.
            كل بايت في عمود الخرج يعتمد على بايتات عمود المدخل الأربعة كاملة لنشر التغيير.
          </p>
        </div>
        <div className="col-selector-tabs" role="group" aria-label="اختر عمود الحساب">
          <span>اختر العمود:</span>
          {[0, 1, 2, 3].map((c) => (
            <button
              key={c}
              type="button"
              aria-pressed={selectedCol === c}
              className={selectedCol === c ? 'is-active' : ''}
              onClick={() => setSelectedCol(c)}
            >
              العمود <Hex>c{c}</Hex>
            </button>
          ))}
        </div>
      </div>

      <div className="mixcolumns-calc-grid">
        <div className="matrix-col-preview">
          <span className="col-title">مدخل العمود <Hex>c{selectedCol}</Hex> (بعد ShiftRows):</span>
          <div className="vector-cells" dir="ltr">
            {colIn.map((_, r) => (
              <div key={r} className="vector-cell">
                <small>r{r}</small>
                <strong><Hex>0x{inputState[r][selectedCol].toUpperCase()}</Hex></strong>
              </div>
            ))}
          </div>
        </div>

        <div className="mixcolumns-math-steps">
          <span className="col-title">حسابات صفوف العمود <Hex>c{selectedCol}</Hex> (MDS × Col):</span>
          <div className="mix-rows-list">
            {rowCalcs.map((calc, r) => (
              <div key={r} className="mix-row-calc">
                <span className="row-tag">الناتج r{r}:</span>
                <div className="calc-formula" dir="ltr">
                  <span className="calc-coeffs">
                    ({calc.coeffs[0]}•<Hex>{inputState[0][selectedCol]}</Hex>) ⊕
                    ({calc.coeffs[1]}•<Hex>{inputState[1][selectedCol]}</Hex>) ⊕
                    ({calc.coeffs[2]}•<Hex>{inputState[2][selectedCol]}</Hex>) ⊕
                    ({calc.coeffs[3]}•<Hex>{inputState[3][selectedCol]}</Hex>)
                  </span>
                  <span className="calc-eval">
                    = <Hex>{calc.terms[0].toString(16).padStart(2, '0')}</Hex> ⊕
                      <Hex>{calc.terms[1].toString(16).padStart(2, '0')}</Hex> ⊕
                      <Hex>{calc.terms[2].toString(16).padStart(2, '0')}</Hex> ⊕
                      <Hex>{calc.terms[3].toString(16).padStart(2, '0')}</Hex>
                  </span>
                  <strong className="calc-result">= <Hex>0x{calc.outHex}</Hex></strong>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="matrix-col-preview is-output">
          <span className="col-title">خرج العمود <Hex>c{selectedCol}</Hex> (في MixColumns):</span>
          <div className="vector-cells" dir="ltr">
            {outputState.map((row, r) => (
              <div key={r} className="vector-cell is-result">
                <small>r{r}</small>
                <strong><Hex>0x{row[selectedCol].toUpperCase()}</Hex></strong>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}

export function AddRoundKeyVisualizer({
  inputState,
  roundKey,
  outputState,
  roundNum,
}: {
  inputState: Matrix
  roundKey: Matrix
  outputState: Matrix
  roundNum: number
}) {
  const [selectedCell, setSelectedCell] = useState<{ r: number; c: number }>({ r: 0, c: 0 })
  const inByte = parseInt(inputState[selectedCell.r][selectedCell.c], 16)
  const keyByte = parseInt(roundKey[selectedCell.r][selectedCell.c], 16)
  const outByte = inByte ^ keyByte

  const inBin = inByte.toString(2).padStart(8, '0')
  const keyBin = keyByte.toString(2).padStart(8, '0')
  const outBin = outByte.toString(2).padStart(8, '0')

  return (
    <div className="layer-interactive-card addroundkey-visualizer">
      <div className="layer-card-header">
        <div>
          <h3>محاكاة إضافة مفتاح الجولة (AddRoundKey · XOR)</h3>
          <p>
            تُطبق عملية XOR الحصرية بين كل بايت من مصفوفة الحالة والبايت المقابل له من مفتاح الجولة <Hex>RK{roundNum}</Hex>.
            اضغط على أي خلية في المصفوفات الثلاث أدناه لفحص عملية XOR الثنائية المباشرة.
          </p>
        </div>
      </div>

      <div className="ark-equation-grid">
        <div className="ark-matrix-card">
          <span>الحالة قبل المفتاح</span>
          <StateMatrix
            grid={inputState}
            compact
            onCellClick={(r, c) => setSelectedCell({ r, c })}
            selectedCell={selectedCell}
          />
        </div>

        <div className="ark-operator" aria-hidden="true">⊕</div>

        <div className="ark-matrix-card">
          <span>مفتاح الجولة <Hex>RK{roundNum}</Hex></span>
          <StateMatrix
            grid={roundKey}
            compact
            onCellClick={(r, c) => setSelectedCell({ r, c })}
            selectedCell={selectedCell}
          />
        </div>

        <div className="ark-operator" aria-hidden="true">=</div>

        <div className="ark-matrix-card is-result-card">
          <span>حالة الخرج الناتجة</span>
          <StateMatrix
            grid={outputState}
            compact
            onCellClick={(r, c) => setSelectedCell({ r, c })}
            selectedCell={selectedCell}
          />
        </div>
      </div>

      <div className="ark-cell-inspect">
        <div className="inspect-head">
          <span>فحص الخلية المختارة:</span>
          <strong>الصف <Hex>r{selectedCell.r}</Hex> · العمود <Hex>c{selectedCell.c}</Hex></strong>
        </div>
        <div className="inspect-bits-grid" dir="ltr">
          <div className="bit-row">
            <span>State [r{selectedCell.r}, c{selectedCell.c}]:</span>
            <div className="bits-strip">
              {inBin.split('').map((b, i) => (
                <span key={i} className={b === '1' ? 'bit-one' : 'bit-zero'}>{b}</span>
              ))}
            </div>
            <strong><Hex>0x{inputState[selectedCell.r][selectedCell.c].toUpperCase()}</Hex></strong>
          </div>
          <div className="bit-row">
            <span>RoundKey [r{selectedCell.r}, c{selectedCell.c}]:</span>
            <div className="bits-strip">
              {keyBin.split('').map((b, i) => (
                <span key={i} className={b === '1' ? 'bit-one' : 'bit-zero'}>{b}</span>
              ))}
            </div>
            <strong><Hex>0x{roundKey[selectedCell.r][selectedCell.c].toUpperCase()}</Hex></strong>
          </div>
          <div className="bit-row is-result">
            <span>XOR Result (=):</span>
            <div className="bits-strip">
              {outBin.split('').map((b, i) => (
                <span key={i} className={b === '1' ? 'bit-one' : 'bit-zero'}>{b}</span>
              ))}
            </div>
            <strong className="text-highlight"><Hex>0x{outputState[selectedCell.r][selectedCell.c].toUpperCase()}</Hex></strong>
          </div>
        </div>
      </div>
    </div>
  )
}

export interface ModalMediaData {
  type: 'image' | 'video'
  src: string
  title: string
  subtitle: string
  details?: Array<{ label: string; value: string }>
}

export function MediaLightboxModal({
  media,
  onClose,
}: {
  media: ModalMediaData | null
  onClose: () => void
}) {
  const [zoom, setZoom] = useState(false)
  const dialogRef = useRef<HTMLDivElement>(null)
  const previousFocusRef = useRef<HTMLElement | null>(null)
  const onCloseRef = useRef(onClose)
  onCloseRef.current = onClose

  useEffect(() => {
    if (!media) return
    previousFocusRef.current = document.activeElement instanceof HTMLElement ? document.activeElement : null
    const previousOverflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'

    const handleKeyDown = (e: globalThis.KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault()
        onCloseRef.current()
        return
      }
      if (e.key !== 'Tab' || !dialogRef.current) return
      const focusable = Array.from(dialogRef.current.querySelectorAll<HTMLElement>(
        'button:not([disabled]), video[controls], [href], input:not([disabled]), [tabindex]:not([tabindex="-1"])',
      ))
      if (focusable.length === 0) {
        e.preventDefault()
        dialogRef.current.focus()
        return
      }
      const first = focusable[0]
      const last = focusable[focusable.length - 1]
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault()
        last.focus()
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault()
        first.focus()
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    window.requestAnimationFrame(() => {
      dialogRef.current?.querySelector<HTMLElement>('button, video[controls]')?.focus()
    })
    return () => {
      window.removeEventListener('keydown', handleKeyDown)
      document.body.style.overflow = previousOverflow
      previousFocusRef.current?.focus()
    }
  }, [media])

  useEffect(() => {
    setZoom(false)
  }, [media?.src])

  if (!media) return null

  return (
    <div
      className="media-lightbox-overlay"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-labelledby="media-lightbox-title"
      aria-describedby="media-lightbox-subtitle"
    >
      <div ref={dialogRef} className="media-lightbox-container" tabIndex={-1} onClick={(e) => e.stopPropagation()}>
        <header className="media-lightbox-header">
          <div>
            <h2 id="media-lightbox-title">{media.title}</h2>
            <p id="media-lightbox-subtitle">{media.subtitle}</p>
          </div>
          <div className="media-lightbox-actions">
            {media.type === 'image' && (
              <button
                type="button"
                className={`lightbox-btn${zoom ? ' is-active' : ''}`}
                onClick={() => setZoom(!zoom)}
                aria-pressed={zoom}
                title={zoom ? 'ملاءمة الصورة داخل النافذة' : 'تكبير الصورة'}
              >
                {zoom ? 'ملاءمة' : 'تكبير'}
              </button>
            )}
            <button
              type="button"
              className="lightbox-close-btn"
              onClick={onClose}
              aria-label="إغلاق العرض"
            >
              ✕
            </button>
          </div>
        </header>

        <div className={`media-lightbox-body${zoom ? ' is-zoomed' : ''}`}>
          {media.type === 'video' ? (
            <video
              src={media.src}
              controls
              autoPlay
              className="lightbox-video"
            />
          ) : (
            <img
              src={media.src}
              alt={media.title}
              className={`lightbox-img${media.src.includes('32x32') ? ' pixel-grid-render' : ''}`}
            />
          )}
        </div>

        {media.details && media.details.length > 0 && (
          <footer className="media-lightbox-footer">
            {media.details.map((d, i) => (
              <div key={i} className="lightbox-detail-chip">
                <span>{d.label}:</span>
                <strong>{d.value}</strong>
              </div>
            ))}
          </footer>
        )}
      </div>
    </div>
  )
}

export function AvalancheChart({ compact = false, note }: { compact?: boolean; note?: string }) {
  const values = vfcTrace.measurements.avalanche.countsByInputBit
  return (
    <div className={`avalanche-chart${compact ? ' is-compact' : ''}`}>
      <div className="avalanche-bars" role="img" aria-label={`نتائج 128 تجربة: المتوسط ${vfcTrace.measurements.avalanche.averageChangedPercent.toFixed(2)} بالمئة`}>
        {values.map((value, index) => (
          <i
            key={index}
            style={{ '--bar': `${(value / 128) * 100}%` } as CSSProperties}
            title={`البت ${index}: تغيّر ${value} من 128`}
            className={value >= 60 && value <= 68 ? 'is-near-half' : ''}
          />
        ))}
        <span className="avalanche-half" aria-hidden="true">50%</span>
      </div>
      <div className="avalanche-summary">
        <strong><Hex>{vfcTrace.measurements.avalanche.averageChangedPercent.toFixed(2)}%</Hex></strong>
        <span>متوسط البتات المتغيّرة</span>
        {!compact && <small>{note ?? 'قياس مسجل لهذا المتجه؛ وليس برهاناً أمنياً'}</small>}
      </div>
    </div>
  )
}

export function VerificationSeal({ compact = false }: { compact?: boolean }) {
  return (
    <div className={`verification-seal${compact ? ' is-compact' : ''}`}>
      <span className="verification-ring" aria-hidden="true">
        <Check size={compact ? 20 : 30} strokeWidth={2} />
      </span>
      <div>
        <strong><Hex>{vfcTrace.testSuite.passedCount}/{vfcTrace.testSuite.count}</Hex> اختبارات</strong>
        <span><Hex>{vfcTrace.validation.assertionCount}/{vfcTrace.validation.assertionCount}</Hex> ثوابت أثر</span>
        {!compact && <small>نجحت مجموعة اختبارات المشروع المسجلة</small>}
      </div>
    </div>
  )
}
