import assert from 'node:assert/strict'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'
import { createServer } from 'vite'

const scriptDirectory = dirname(fileURLToPath(import.meta.url))
const projectRoot = resolve(scriptDirectory, '..')
const server = await createServer({
  root: projectRoot,
  appType: 'custom',
  logLevel: 'silent',
  server: { middlewareMode: true },
})

try {
  const cryptoModule = await server.ssrLoadModule('/src/lib/vfc-crypto.ts')
  const { vfcTrace } = await server.ssrLoadModule('/src/data/vfc-trace.ts')
  const {
    bytesToHex,
    createWavFile,
    decryptVFCCbc,
    deriveVFCKeys,
    embedPayloadInAudio,
    encryptVFCCbc,
    extractPayloadFromAudio,
    generateVFCPayload,
    hexToBytes,
    packVFCPlaintext,
    parsePcm16Wav,
    shuffledPositions,
    unpackVFCPlaintext,
    verifyVFCPayload,
  } = cryptoModule

  const options = {
    frameNumber: vfcTrace.inputs.frameNumber,
    randomSaltHex: vfcTrace.inputs.saltHex,
  }
  const keys = await deriveVFCKeys(vfcTrace.inputs.passwordAscii, vfcTrace.fingerprint.bytesHex, options)
  assert.equal(bytesToHex(keys.kEmbed), vfcTrace.kdf.embedding.outputHex, 'K_embed differs from the Python vector')
  assert.equal(bytesToHex(keys.kEnc), vfcTrace.kdf.encryption.outputHex, 'K_enc differs from the Python vector')
  assert.equal(bytesToHex(keys.kAuth), vfcTrace.kdf.authentication.outputHex, 'K_auth differs from the Python vector')

  const secret = new TextEncoder().encode(vfcTrace.inputs.secretUtf8)
  const innerPackage = packVFCPlaintext(vfcTrace.inputs.filename, secret)
  assert.equal(bytesToHex(innerPackage), vfcTrace.cbc.filenameMetadataPlaintext.hex, 'Inner package differs from Python')

  const iv = hexToBytes(vfcTrace.inputs.ivHex)
  const ciphertext = await encryptVFCCbc(innerPackage, keys.kEnc, iv)
  assert.equal(bytesToHex(ciphertext), vfcTrace.cbc.ciphertextHex, 'CBC/SPN ciphertext differs from Python')

  const payload = await generateVFCPayload(ciphertext, keys.kEmbed, keys.kAuth, iv, options)
  assert.equal(bytesToHex(payload.fullPayload), vfcTrace.payload.fullHex, 'Authenticated payload differs from Python')

  const carrier = {
    sampleRate: vfcTrace.audioEmbedding.sampleRateHz,
    channelCount: vfcTrace.audioEmbedding.channels,
    samples: Int16Array.from(
      { length: vfcTrace.audioEmbedding.totalSamples },
      (_, index) => ((0x9e37 * index) % 36000) - 18000,
    ),
  }
  const eligible = Array.from(carrier.samples.keys()).filter((index) => Math.abs(carrier.samples[index] >> 1) >= 2)
  const positions = await shuffledPositions(keys.kEmbed, eligible)
  assert.deepEqual(positions.slice(0, 32), [...vfcTrace.audioEmbedding.first32ShuffledPositions], 'Audio positions differ from Python')

  const embedded = await embedPayloadInAudio(payload.fullPayload, keys.kEmbed, carrier)
  const wavBuffer = createWavFile({ ...carrier, samples: embedded.embeddedSamples })
  const reloadedWav = parsePcm16Wav(wavBuffer)
  assert.deepEqual(reloadedWav.samples, embedded.embeddedSamples, 'PCM samples changed during WAV export/re-import')

  const extractedPayload = await extractPayloadFromAudio(reloadedWav.samples, keys.kEmbed)
  assert.equal(bytesToHex(extractedPayload), vfcTrace.payload.fullHex, 'Extracted payload differs after WAV re-import')
  const verified = await verifyVFCPayload(extractedPayload, keys.kEmbed, keys.kAuth)
  const decrypted = await decryptVFCCbc(verified.ciphertext, keys.kEnc, verified.iv)
  const recovered = unpackVFCPlaintext(decrypted)
  assert.equal(recovered.filename, vfcTrace.inputs.filename)
  assert.equal(bytesToHex(recovered.data), vfcTrace.inputs.secretHex)

  console.log('VFC browser compatibility: PASS')
  console.log('  Python vector: keys, inner package, ciphertext, payload, and positions match')
  console.log('  WAV roundtrip: export, re-import, extract, verify, decrypt, and unpack match')
} finally {
  await server.close()
}
