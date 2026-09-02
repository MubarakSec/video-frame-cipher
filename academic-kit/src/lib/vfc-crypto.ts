import { vfcTrace } from '../data/vfc-trace'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

export function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16)
  }
  return bytes
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

function stringToBytes(str: string): Uint8Array {
  return new TextEncoder().encode(str)
}

export function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length)
  for (let i = 0; i < a.length; i++) {
    out[i] = a[i] ^ b[i]
  }
  return out
}

function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const totalLen = arrays.reduce((acc, a) => acc + a.length, 0)
  const res = new Uint8Array(totalLen)
  let offset = 0
  for (const arr of arrays) {
    res.set(arr, offset)
    offset += arr.length
  }
  return res
}

// ---------------------------------------------------------------------------
// VFC Key Derivation (PBKDF2)
// ---------------------------------------------------------------------------

export interface DeriveVFCOptions {
  frameNumber?: number
  randomSaltHex?: string
}

export async function deriveVFCKeys(password: string, fingerprintHex: string, options?: DeriveVFCOptions) {
  const enc = new TextEncoder()
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    'PBKDF2',
    false,
    ['deriveBits']
  )

  const fingerprintBytes = hexToBytes(fingerprintHex)
  const frameNo = options?.frameNumber ?? 30
  const frameNoBytes = new Uint8Array([(frameNo >> 24) & 0xff, (frameNo >> 16) & 0xff, (frameNo >> 8) & 0xff, frameNo & 0xff])
  const randomSalt = hexToBytes(options?.randomSaltHex ?? '00112233445566778899aabbccddeeff')

  const embedSalt = concatBytes(enc.encode('VFC-EMBED'), fingerprintBytes, frameNoBytes)
  const encSalt = concatBytes(enc.encode('VFC-ENCRYPT'), fingerprintBytes, frameNoBytes, randomSalt)
  const authSalt = concatBytes(enc.encode('VFC-AUTH'), fingerprintBytes, frameNoBytes, randomSalt)

  const getBits = async (salt: Uint8Array) => {
    const bits = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        hash: 'SHA-256',
        salt: salt as unknown as BufferSource,
        iterations: 200000,
      },
      keyMaterial,
      256
    )
    return new Uint8Array(bits)
  }

  const [kEmbed, kEnc, kAuth] = await Promise.all([
    getBits(embedSalt),
    getBits(encSalt),
    getBits(authSalt),
  ])

  return { kEmbed, kEnc, kAuth }
}

// ---------------------------------------------------------------------------
// VFC SPN-128 Cipher implementation
// ---------------------------------------------------------------------------

function gmul(a: number, b: number): number {
  let p = 0
  for (let i = 0; i < 8; i++) {
    if (b & 1) p ^= a
    const high = a & 0x80
    a = (a << 1) & 0xff
    if (high) a ^= 0x1b
    b >>= 1
  }
  return p
}

const SBOX = vfcTrace.cipher.sbox
const MDS = vfcTrace.cipher.mds
const INV_SBOX = vfcTrace.cipher.inverseSbox
const INV_MDS = vfcTrace.cipher.inverseMds

function toState(block: Uint8Array): number[][] {
  const state = [
    [0, 0, 0, 0],
    [0, 0, 0, 0],
    [0, 0, 0, 0],
    [0, 0, 0, 0],
  ]
  for (let r = 0; r < 4; r++) {
    for (let c = 0; c < 4; c++) {
      state[r][c] = block[c * 4 + r]
    }
  }
  return state
}

function fromState(state: number[][]): Uint8Array {
  const block = new Uint8Array(16)
  for (let r = 0; r < 4; r++) {
    for (let c = 0; c < 4; c++) {
      block[c * 4 + r] = state[r][c]
    }
  }
  return block
}

function subBytes(state: number[][]): number[][] {
  return state.map((row) => row.map((val) => SBOX[val]))
}

function shiftRows(state: number[][]): number[][] {
  return state.map((row, r) => [...row.slice(r), ...row.slice(0, r)])
}

function inverseSubBytes(state: number[][]): number[][] {
  return state.map((row) => row.map((val) => INV_SBOX[val]))
}

function inverseShiftRows(state: number[][]): number[][] {
  return state.map((row, r) => r === 0 ? [...row] : [...row.slice(4 - r), ...row.slice(0, 4 - r)])
}

function mixColumns(state: number[][]): number[][] {
  const out = [
    [0, 0, 0, 0],
    [0, 0, 0, 0],
    [0, 0, 0, 0],
    [0, 0, 0, 0],
  ]
  for (let c = 0; c < 4; c++) {
    const col = [state[0][c], state[1][c], state[2][c], state[3][c]]
    for (let r = 0; r < 4; r++) {
      out[r][c] =
        gmul(MDS[r][0], col[0]) ^
        gmul(MDS[r][1], col[1]) ^
        gmul(MDS[r][2], col[2]) ^
        gmul(MDS[r][3], col[3])
    }
  }
  return out
}

function inverseMixColumns(state: number[][]): number[][] {
  const out = Array.from({ length: 4 }, () => [0, 0, 0, 0])
  for (let c = 0; c < 4; c++) {
    const col = [state[0][c], state[1][c], state[2][c], state[3][c]]
    for (let r = 0; r < 4; r++) {
      out[r][c] =
        gmul(INV_MDS[r][0], col[0]) ^
        gmul(INV_MDS[r][1], col[1]) ^
        gmul(INV_MDS[r][2], col[2]) ^
        gmul(INV_MDS[r][3], col[3])
    }
  }
  return out
}

function addRoundKey(state: number[][], rk: Uint8Array): number[][] {
  const rks = toState(rk)
  return state.map((row, r) => row.map((val, c) => val ^ rks[r][c]))
}

export type VFCBlockState = {
  bytesHex: string
  gridHex: string[][]
}

export type VFCBlockLayerTrace = {
  input: VFCBlockState
  initialWhitening: VFCBlockState
  rounds: Array<{
    subBytes: VFCBlockState
    shiftRows: VFCBlockState
    mixColumns: VFCBlockState
    addRoundKey: VFCBlockState
  }>
}

function describeState(state: number[][]): VFCBlockState {
  return {
    bytesHex: bytesToHex(fromState(state)),
    gridHex: state.map((row) => row.map((value) => value.toString(16).padStart(2, '0'))),
  }
}

/**
 * Returns every state shown by the block-cipher teaching screen. This follows
 * the same six-round path as encryptVFCBlock and does not invent trace data.
 */
export function traceVFCBlockLayers(block: Uint8Array, roundKeys: Uint8Array[]): VFCBlockLayerTrace {
  if (block.length !== 16) throw new Error('VFC block input must contain exactly 16 bytes.')
  if (roundKeys.length < 7 || roundKeys.some((key) => key.length !== 16)) {
    throw new Error('VFC block tracing requires RK0 through RK6, each 16 bytes.')
  }

  let state = toState(block)
  const input = describeState(state)
  state = addRoundKey(state, roundKeys[0])
  const initialWhitening = describeState(state)
  const rounds: VFCBlockLayerTrace['rounds'] = []

  for (let round = 1; round <= 6; round++) {
    state = subBytes(state)
    const subBytesState = describeState(state)
    state = shiftRows(state)
    const shiftRowsState = describeState(state)
    state = mixColumns(state)
    const mixColumnsState = describeState(state)
    state = addRoundKey(state, roundKeys[round])
    const addRoundKeyState = describeState(state)
    rounds.push({
      subBytes: subBytesState,
      shiftRows: shiftRowsState,
      mixColumns: mixColumnsState,
      addRoundKey: addRoundKeyState,
    })
  }

  return { input, initialWhitening, rounds }
}

export async function getRoundKeys(kEnc: Uint8Array): Promise<Uint8Array[]> {
  const rks: Uint8Array[] = []
  for (let i = 0; i <= 6; i++) {
    const msg = concatBytes(kEnc, stringToBytes('VFC-RK'), new Uint8Array([0, i]))
    const hashBuffer = await crypto.subtle.digest('SHA-256', msg as unknown as BufferSource)
    rks.push(new Uint8Array(hashBuffer).slice(0, 16))
  }
  return rks
}

export async function encryptVFCBlock(block: Uint8Array, roundKeys: Uint8Array[]): Promise<Uint8Array> {
  let state = addRoundKey(toState(block), roundKeys[0])
  for (let r = 1; r <= 6; r++) {
    state = subBytes(state)
    state = shiftRows(state)
    state = mixColumns(state)
    state = addRoundKey(state, roundKeys[r])
  }
  return fromState(state)
}

export async function decryptVFCBlock(block: Uint8Array, roundKeys: Uint8Array[]): Promise<Uint8Array> {
  let state = toState(block)
  for (let r = 6; r >= 1; r--) {
    state = addRoundKey(state, roundKeys[r])
    state = inverseMixColumns(state)
    state = inverseShiftRows(state)
    state = inverseSubBytes(state)
  }
  state = addRoundKey(state, roundKeys[0])
  return fromState(state)
}

export function encryptVFCBlockTrace(block: Uint8Array, roundKeys: Uint8Array[]): Uint8Array[] {
  const trace: Uint8Array[] = []
  trace.push(new Uint8Array(block)) // IN
  
  let state = addRoundKey(toState(block), roundKeys[0])
  trace.push(fromState(state)) // RK0
  
  for (let r = 1; r <= 6; r++) {
    state = subBytes(state)
    state = shiftRows(state)
    state = mixColumns(state)
    state = addRoundKey(state, roundKeys[r])
    trace.push(fromState(state)) // R1 to R6
  }
  return trace
}

export function padPKCS7(data: Uint8Array, blockSize: number = 16): Uint8Array {
  const padLen = blockSize - (data.length % blockSize)
  const padding = new Uint8Array(padLen).fill(padLen)
  return concatBytes(data, padding)
}

export function unpadPKCS7(data: Uint8Array, blockSize: number = 16): Uint8Array {
  if (data.length === 0 || data.length % blockSize !== 0) throw new Error('Invalid PKCS#7 padded length.')
  const padLen = data[data.length - 1]
  if (padLen < 1 || padLen > blockSize) throw new Error('Invalid PKCS#7 padding.')
  for (let i = data.length - padLen; i < data.length; i++) {
    if (data[i] !== padLen) throw new Error('Invalid PKCS#7 padding.')
  }
  return data.slice(0, data.length - padLen)
}

export async function encryptVFCCbc(plaintext: Uint8Array, kEnc: Uint8Array, iv: Uint8Array): Promise<Uint8Array> {
  const padded = padPKCS7(plaintext)
  const roundKeys = await getRoundKeys(kEnc)
  const ciphertext = new Uint8Array(padded.length)
  let prev = iv
  for (let i = 0; i < padded.length; i += 16) {
    const block = padded.slice(i, i + 16)
    const xorBlock = xorBytes(block, prev)
    const ctBlock = await encryptVFCBlock(xorBlock, roundKeys)
    ciphertext.set(ctBlock, i)
    prev = ctBlock
  }
  return ciphertext
}

export async function decryptVFCCbc(ciphertext: Uint8Array, kEnc: Uint8Array, iv: Uint8Array): Promise<Uint8Array> {
  if (ciphertext.length === 0 || ciphertext.length % 16 !== 0) throw new Error('Ciphertext must contain complete 16-byte blocks.')
  const roundKeys = await getRoundKeys(kEnc)
  const padded = new Uint8Array(ciphertext.length)
  let prev = iv
  for (let i = 0; i < ciphertext.length; i += 16) {
    const ctBlock = ciphertext.slice(i, i + 16)
    const decrypted = await decryptVFCBlock(ctBlock, roundKeys)
    padded.set(xorBytes(decrypted, prev), i)
    prev = ctBlock
  }
  return unpadPKCS7(padded)
}

export function packVFCPlaintext(filename: string, data: Uint8Array): Uint8Array {
  const name = stringToBytes(filename)
  if (name.length === 0 || name.length > 0xffff) throw new Error('Filename length is outside the supported range.')
  const nameLength = new Uint8Array(2)
  new DataView(nameLength.buffer).setUint16(0, name.length, false)
  const originalSize = new Uint8Array(8)
  new DataView(originalSize.buffer).setBigUint64(0, BigInt(data.length), false)
  return concatBytes(nameLength, name, originalSize, new Uint8Array([0]), data)
}

export function unpackVFCPlaintext(plain: Uint8Array): { filename: string; data: Uint8Array } {
  if (plain.length < 11) throw new Error('Inner plaintext package is truncated.')
  const nameLength = new DataView(plain.buffer, plain.byteOffset, plain.byteLength).getUint16(0, false)
  const metadataEnd = 2 + nameLength + 8 + 1
  if (nameLength === 0 || metadataEnd > plain.length) throw new Error('Inner plaintext metadata is invalid.')
  const filename = new TextDecoder('utf-8', { fatal: true }).decode(plain.slice(2, 2 + nameLength))
  if (!filename || filename.includes('\0') || filename.includes('/') || filename.includes('\\')) throw new Error('Filename in inner package is invalid.')
  const sizeOffset = 2 + nameLength
  const originalSize = new DataView(plain.buffer, plain.byteOffset + sizeOffset, 8).getBigUint64(0, false)
  const flags = plain[sizeOffset + 8]
  if (flags !== 0) throw new Error('This browser lesson does not create compressed inner packages.')
  const data = plain.slice(metadataEnd)
  if (BigInt(data.length) !== originalSize) throw new Error('Recovered file size does not match its encrypted metadata.')
  return { filename, data }
}

// ---------------------------------------------------------------------------
// Payload formatting & HMAC
// ---------------------------------------------------------------------------

export async function generateVFCPayload(ciphertext: Uint8Array, kEmbed: Uint8Array, kAuth: Uint8Array, iv: Uint8Array, options?: DeriveVFCOptions) {
  // 1. Magic
  const magicMsg = concatBytes(kEmbed, stringToBytes('VFC-MAGIC'))
  const magicHash = await crypto.subtle.digest('SHA-256', magicMsg as unknown as BufferSource)
  const magic = new Uint8Array(magicHash).slice(0, 4)
  
  // 2. Header
  const version = new Uint8Array([2])
  const flags = new Uint8Array([0])
  const salt = hexToBytes(options?.randomSaltHex ?? '00112233445566778899aabbccddeeff')
  const frameNumber = options?.frameNumber ?? 30
  const frameNo = new Uint8Array([(frameNumber >> 24) & 0xff, (frameNumber >> 16) & 0xff, (frameNumber >> 8) & 0xff, frameNumber & 0xff])
  
  // CT len (8 bytes)
  const ctLen = new Uint8Array(8)
  const view = new DataView(ctLen.buffer)
  view.setUint32(4, ciphertext.length, false) // Big-endian
  
  const header = concatBytes(magic, version, flags, salt, iv, frameNo, ctLen)
  const authenticatedData = concatBytes(header, ciphertext)
  
  // 3. HMAC
  const hmacKey = await crypto.subtle.importKey(
    'raw',
    kAuth as unknown as BufferSource,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  )
  const signature = await crypto.subtle.sign('HMAC', hmacKey, authenticatedData as unknown as BufferSource)
  const hmacTag = new Uint8Array(signature)
  
  return {
    header,
    ciphertext,
    hmacTag,
    fullPayload: concatBytes(authenticatedData, hmacTag)
  }
}

export type VerifiedVFCPayload = {
  ciphertext: Uint8Array
  salt: Uint8Array
  iv: Uint8Array
  frameNumber: number
}

export type VFCPayloadHeader = {
  version: number
  flags: number
  salt: Uint8Array
  iv: Uint8Array
  frameNumber: number
  ciphertextLength: number
}

export function readVFCPayloadHeader(payload: Uint8Array): VFCPayloadHeader {
  if (payload.length < 50) throw new Error('الحمولة أقصر من الترويسة الثابتة ذات 50 بايتاً.')
  const view = new DataView(payload.buffer, payload.byteOffset, 50)
  const ciphertextLengthBig = view.getBigUint64(42, false)
  if (ciphertextLengthBig > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('طول النص المشفر المعلن أكبر من قدرة المتصفح.')
  return {
    version: payload[4],
    flags: payload[5],
    salt: payload.slice(6, 22),
    iv: payload.slice(22, 38),
    frameNumber: view.getUint32(38, false),
    ciphertextLength: Number(ciphertextLengthBig),
  }
}

export async function verifyVFCPayload(fullPayload: Uint8Array, kEmbed: Uint8Array, kAuth: Uint8Array): Promise<VerifiedVFCPayload> {
  if (fullPayload.length < 82) throw new Error('الحمولة أقصر من ترويسة 50B ووسم HMAC بطول 32B.')
  const expectedMagicHash = await crypto.subtle.digest('SHA-256', concatBytes(kEmbed, stringToBytes('VFC-MAGIC')) as unknown as BufferSource)
  const expectedMagic = new Uint8Array(expectedMagicHash).slice(0, 4)
  if (!expectedMagic.every((value, index) => value === fullPayload[index])) throw new Error('علامة magic لا تطابق سياق كلمة المرور والإطار.')
  if (fullPayload[4] !== 2) throw new Error(`إصدار الحمولة ${fullPayload[4]} غير مدعوم.`)

  const parsedHeader = readVFCPayloadHeader(fullPayload)
  const ciphertextLength = parsedHeader.ciphertextLength
  const authenticatedLength = 50 + ciphertextLength
  if (ciphertextLength === 0 || ciphertextLength % 16 !== 0 || fullPayload.length !== authenticatedLength + 32) {
    throw new Error('طول الحمولة أو محاذاة كتل النص المشفر غير صالحين.')
  }

  const hmacKey = await crypto.subtle.importKey('raw', kAuth as unknown as BufferSource, { name: 'HMAC', hash: 'SHA-256' }, false, ['verify'])
  const valid = await crypto.subtle.verify(
    'HMAC',
    hmacKey,
    fullPayload.slice(authenticatedLength) as unknown as BufferSource,
    fullPayload.slice(0, authenticatedLength) as unknown as BufferSource,
  )
  if (!valid) throw new Error('فشل فحص HMAC: السياق غير مطابق أو الحمولة معدّلة.')

  return {
    ciphertext: fullPayload.slice(50, authenticatedLength),
    salt: parsedHeader.salt,
    iv: parsedHeader.iv,
    frameNumber: parsedHeader.frameNumber,
  }
}

// ---------------------------------------------------------------------------
// Steganography: LSB Audio embedding
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Position generator — exact TypeScript port of vfc/prng.py
//
// Keystream: block_i = SHA256(K_embed || counter_i) with counter as Big-Endian
// uint64. Integers in [0, n) come from rejection sampling so Fisher–Yates
// stays unbiased. Blocks are prefetched in batches purely for performance;
// the byte sequence is identical to the Python implementation.
// ---------------------------------------------------------------------------

class Sha256KeyStream {
  private readonly key: Uint8Array
  private buf = new Uint8Array(0)
  private pos = 0
  private nextCounter = 0

  constructor(key: Uint8Array) {
    this.key = key
  }

  private async fill() {
    const batch = 256
    const merged = new Uint8Array(batch * 32)
    const digests: Promise<ArrayBuffer>[] = []
    for (let k = 0; k < batch; k++) {
      const counterBytes = new Uint8Array(8)
      new DataView(counterBytes.buffer).setBigUint64(0, BigInt(this.nextCounter + k), false)
      digests.push(crypto.subtle.digest('SHA-256', concatBytes(this.key, counterBytes) as unknown as BufferSource))
    }
    const results = await Promise.all(digests)
    for (let k = 0; k < batch; k++) merged.set(new Uint8Array(results[k]), k * 32)
    this.nextCounter += batch
    // Carry over any unconsumed tail so the byte stream stays continuous
    // across refills — exactly like the Python single-block KeyStream.
    const remaining = this.buf.length - this.pos
    if (remaining > 0) {
      const carried = new Uint8Array(remaining + merged.length)
      carried.set(this.buf.subarray(this.pos))
      carried.set(merged, remaining)
      this.buf = carried
    } else {
      this.buf = merged
    }
    this.pos = 0
  }

  private async ensure(byteCount: number) {
    if (this.pos + byteCount > this.buf.length) await this.fill()
  }

  async below(n: number): Promise<number> {
    if (n <= 1) return 0
    let nbytes = 1
    while (2 ** (8 * nbytes) < n) nbytes++
    const span = 2 ** (8 * nbytes)
    const bound = span - (span % n)
    for (;;) {
      await this.ensure(nbytes)
      let val = 0
      for (let i = 0; i < nbytes; i++) val = val * 256 + this.buf[this.pos++]
      if (val < bound) return val % n
    }
  }
}

export async function shuffledPositions(key: Uint8Array, eligibleIndices: number[]): Promise<number[]> {
  const idx = eligibleIndices.slice()
  const stream = new Sha256KeyStream(key)
  const n = idx.length
  for (let i = n - 1; i > 0; i--) {
    const j = await stream.below(i + 1)
    ;[idx[i], idx[j]] = [idx[j], idx[i]]
  }
  return idx
}

export type VFCWavAudio = {
  samples: Int16Array
  sampleRate: number
  channelCount: number
}

export type VFCAudioCapacity = {
  totalSamples: number
  eligibleSamples: number
  rawBytes: number
  maximumPayloadBytes: number
}

export function getAudioCapacity(audio: VFCWavAudio): VFCAudioCapacity {
  let eligibleSamples = 0
  for (const sample of audio.samples) {
    if (Math.abs(sample >> 1) >= 2) eligibleSamples++
  }
  const rawBytes = Math.floor(eligibleSamples / 8)
  return {
    totalSamples: audio.samples.length,
    eligibleSamples,
    rawBytes,
    maximumPayloadBytes: rawBytes,
  }
}

export function createSyntheticCarrier(durationSeconds = 2, sampleRate = 48000): VFCWavAudio {
  const numSamples = Math.round(sampleRate * durationSeconds)
  const samples = new Int16Array(numSamples)
  for (let i = 0; i < numSamples; i++) {
    const t = i / sampleRate
    const env = Math.exp(-3 * t) // exponential decay for a bell-like sound
    const c4 = Math.sin(t * 2 * Math.PI * 211.63)
    const e4 = Math.sin(t * 2 * Math.PI * 329.63)
    const g4 = Math.sin(t * 2 * Math.PI * 392.00)
    const c5 = Math.sin(t * 2 * Math.PI * 523.25)
    
    const mix = (c4 + e4 + g4 + c5) / 4
    samples[i] = Math.floor(24000 * mix * env)
  }
  return { samples, sampleRate, channelCount: 1 }
}

export function parsePcm16Wav(buffer: ArrayBuffer): VFCWavAudio {
  const view = new DataView(buffer)
  const readAscii = (offset: number, length: number) =>
    Array.from({ length }, (_, index) => String.fromCharCode(view.getUint8(offset + index))).join('')
  if (buffer.byteLength < 44 || readAscii(0, 4) !== 'RIFF' || readAscii(8, 4) !== 'WAVE') {
    throw new Error('الملف ليس حاوية WAV صالحة.')
  }

  let offset = 12
  let format: { audioFormat: number; channelCount: number; sampleRate: number; bitsPerSample: number } | null = null
  let dataOffset = -1
  let dataLength = 0
  while (offset + 8 <= buffer.byteLength) {
    const chunkId = readAscii(offset, 4)
    const chunkLength = view.getUint32(offset + 4, true)
    const chunkDataOffset = offset + 8
    if (chunkDataOffset + chunkLength > buffer.byteLength) throw new Error('أحد مقاطع WAV مقطوع أو يعلن حجماً غير صالح.')
    if (chunkId === 'fmt ') {
      if (chunkLength < 16) throw new Error('مقطع fmt في WAV أقصر من المطلوب.')
      format = {
        audioFormat: view.getUint16(chunkDataOffset, true),
        channelCount: view.getUint16(chunkDataOffset + 2, true),
        sampleRate: view.getUint32(chunkDataOffset + 4, true),
        bitsPerSample: view.getUint16(chunkDataOffset + 14, true),
      }
    } else if (chunkId === 'data') {
      dataOffset = chunkDataOffset
      dataLength = chunkLength
    }
    offset = chunkDataOffset + chunkLength + (chunkLength % 2)
  }

  if (!format || dataOffset < 0) throw new Error('ملف WAV لا يحتوي مقطعي fmt وdata المطلوبين.')
  if (format.audioFormat !== 1 || format.bitsPerSample !== 16) throw new Error('يلزم WAV بصوت PCM غير مضغوط وعمق 16-bit.')
  if (format.channelCount < 1 || format.sampleRate < 1 || dataLength % 2 !== 0) throw new Error('خصائص PCM في ملف WAV غير صالحة.')

  const samples = new Int16Array(dataLength / 2)
  for (let i = 0; i < samples.length; i++) samples[i] = view.getInt16(dataOffset + i * 2, true)
  return { samples, sampleRate: format.sampleRate, channelCount: format.channelCount }
}

export function createWavFile(audio: VFCWavAudio): ArrayBuffer {
  const { samples, sampleRate, channelCount } = audio
  const buffer = new ArrayBuffer(44 + samples.length * 2)
  const view = new DataView(buffer)
  const blockAlign = channelCount * 2

  const writeString = (writeOffset: number, value: string) => {
    for (let i = 0; i < value.length; i++) view.setUint8(writeOffset + i, value.charCodeAt(i))
  }

  writeString(0, 'RIFF')
  view.setUint32(4, 36 + samples.length * 2, true)
  writeString(8, 'WAVE')
  writeString(12, 'fmt ')
  view.setUint32(16, 16, true)
  view.setUint16(20, 1, true)
  view.setUint16(22, channelCount, true)
  view.setUint32(24, sampleRate, true)
  view.setUint32(28, sampleRate * blockAlign, true)
  view.setUint16(32, blockAlign, true)
  view.setUint16(34, 16, true)
  writeString(36, 'data')
  view.setUint32(40, samples.length * 2, true)
  for (let i = 0; i < samples.length; i++) view.setInt16(44 + i * 2, samples[i], true)
  return buffer
}

export async function embedPayloadInAudio(payloadBytes: Uint8Array, kEmbed: Uint8Array, carrier = createSyntheticCarrier()) {
  const sampleRate = carrier.sampleRate
  const channelCount = carrier.channelCount
  const samples = new Int16Array(carrier.samples)
  const numSamples = samples.length

  // Collect indices that satisfy the implementation's eligibility rule:
  // abs(sample >> 1) >= 2.
  // then shuffle them with the same SHA-256 keystream Fisher–Yates as the
  // Python pipeline (vfc/prng.py) so positions match byte-for-byte.
  const eligibleIndices: number[] = []
  for (let i = 0; i < numSamples; i++) {
    if (Math.abs(samples[i] >> 1) >= 2) {
      eligibleIndices.push(i)
    }
  }
  const shuffled = await shuffledPositions(kEmbed, eligibleIndices)

  const totalBits = payloadBytes.length * 8
  if (totalBits > shuffled.length) {
    throw new Error(`تحتاج الحمولة إلى ${totalBits.toLocaleString()} عينة مؤهلة، بينما يحتوي هذا الحامل على ${shuffled.length.toLocaleString()} فقط.`)
  }

  // Create original WAV Blob before modifying
  const originalSamples = new Int16Array(samples)
  const originalWavBuffer = createWavFile({ samples: originalSamples, sampleRate, channelCount })
  const originalBlob = new Blob([originalWavBuffer], { type: 'audio/wav' })
  const originalUrl = URL.createObjectURL(originalBlob)

  let payloadBitIdx = 0
  let changedSampleCount = 0

  for (let i = 0; i < shuffled.length && payloadBitIdx < totalBits; i++) {
    const sampleIdx = shuffled[i]
    const val = samples[sampleIdx]
    const byteIdx = Math.floor(payloadBitIdx / 8)
    const bitOffset = 7 - (payloadBitIdx % 8) // MSB first
    const bit = (payloadBytes[byteIdx] >> bitOffset) & 1
    
    const nextValue = (val & ~1) | bit
    samples[sampleIdx] = nextValue
    payloadBitIdx++
    if (nextValue !== val) changedSampleCount++
  }
  
  // Create modified WAV Blob
  const modifiedWavBuffer = createWavFile({ samples, sampleRate, channelCount })
  const modifiedBlob = new Blob([modifiedWavBuffer], { type: 'audio/wav' })
  const modifiedUrl = URL.createObjectURL(modifiedBlob)
  
  return {
    originalAudioUrl: originalUrl,
    modifiedAudioUrl: modifiedUrl,
    embeddedSamples: new Int16Array(samples),
    eligibleSampleCount: shuffled.length,
    usedSampleCount: totalBits,
    changedSampleCount,
  }
}

export async function extractPayloadFromAudio(samples: Int16Array, kEmbed: Uint8Array): Promise<Uint8Array> {
  const eligibleIndices: number[] = []
  for (let i = 0; i < samples.length; i++) {
    if (Math.abs(samples[i] >> 1) >= 2) eligibleIndices.push(i)
  }
  const shuffled = await shuffledPositions(kEmbed, eligibleIndices)
  const headerBits = 50 * 8
  if (shuffled.length < headerBits) throw new Error('لا يحتوي الحامل عينات مؤهلة تكفي لقراءة ترويسة VFC.')

  const readBytes = (byteLength: number) => {
    const bitLength = byteLength * 8
    if (bitLength > shuffled.length) throw new Error('طول الحمولة المعلن في الترويسة يتجاوز سعة الحامل.')
    const output = new Uint8Array(byteLength)
    for (let bitIndex = 0; bitIndex < bitLength; bitIndex++) {
      output[Math.floor(bitIndex / 8)] |= (samples[shuffled[bitIndex]] & 1) << (7 - (bitIndex % 8))
    }
    return output
  }

  const header = readBytes(50)
  const ciphertextLengthBig = new DataView(header.buffer).getBigUint64(42, false)
  if (ciphertextLengthBig > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('طول النص المشفر المعلن أكبر من قدرة المتصفح.')
  const ciphertextLength = Number(ciphertextLengthBig)
  if (ciphertextLength === 0 || ciphertextLength % 16 !== 0) throw new Error('طول النص المشفر المعلن ليس مضاعفاً موجباً لـ16 بايتاً.')
  return readBytes(50 + ciphertextLength + 32)
}
