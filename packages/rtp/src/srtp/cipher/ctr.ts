import {
  type Cipher,
  createCipheriv,
  createDecipheriv,
  createHmac,
  timingSafeEqual,
} from "crypto";
import type { RtcpHeader } from "../../rtcp/header";
import type { RtpHeader } from "../../rtp/rtp";
import { SrtpAuthenticationError } from "../error";
import {
  finalizeSrtpRtpHeader,
  parseSrtcpHeader,
  parseSrtpRtpHeader,
} from "../packet";
import { CipherAesBase } from ".";

export class CipherAesCtr extends CipherAesBase {
  readonly authTagLength = 10;

  constructor(
    srtpSessionKey: Buffer,
    srtpSessionSalt: Buffer,
    srtcpSessionKey: Buffer,
    srtcpSessionSalt: Buffer,
    private srtpSessionAuthTag: Buffer,
    private srtcpSessionAuthTag: Buffer,
  ) {
    super(srtpSessionKey, srtpSessionSalt, srtcpSessionKey, srtcpSessionSalt);
    this.srtpKeystreamCipher = createCipheriv(
      "aes-128-ecb",
      srtpSessionKey,
      null,
    );
    this.srtpKeystreamCipher.setAutoPadding(false);
  }

  // Ralai fork: one AES block cipher per session, reused for every RTP packet.
  // AES-CTR is computed here: the counter blocks for a packet are encrypted in
  // one call and XORed with the payload. In SRTP the block index occupies the
  // low 16 bits of the counter (RFC 3711 section 4.1.1), so block i is the
  // packet IV with i in its last two bytes.
  private readonly srtpKeystreamCipher: Cipher;
  private counterBlocks = Buffer.alloc(0);

  private applySrtpKeystream(
    iv: Buffer,
    input: Buffer,
    output: Buffer,
    outputOffset: number,
  ) {
    const blockCount = Math.ceil(input.length / 16);
    const blocksLength = blockCount * 16;
    if (this.counterBlocks.length < blocksLength) {
      this.counterBlocks = Buffer.alloc(blocksLength);
    }
    const counterBlocks = this.counterBlocks;
    for (let block = 0; block < blockCount; block++) {
      const offset = block * 16;
      iv.copy(counterBlocks, offset, 0, 14);
      counterBlocks[offset + 14] = block >> 8;
      counterBlocks[offset + 15] = block & 0xff;
    }
    const keystream = this.srtpKeystreamCipher.update(
      counterBlocks.subarray(0, blocksLength),
    );
    for (let i = 0; i < input.length; i++) {
      output[outputOffset + i] = input[i] ^ keystream[i];
    }
  }

  encryptRtp(header: RtpHeader, payload: Buffer, rolloverCounter: number) {
    const headerSize = header.serializeSize;
    const headerBuffer = header.serialize(headerSize);

    const counter = this.generateCounter(
      header.sequenceNumber,
      rolloverCounter,
      header.ssrc,
      this.srtpSessionSalt,
    );

    // Ralai fork: one output allocation; header, ciphertext and tag are written
    // into it in place.
    const out = Buffer.allocUnsafe(
      headerSize + payload.length + this.authTagLength,
    );
    headerBuffer.copy(out, 0);
    this.applySrtpKeystream(counter, payload, out, headerSize);

    const authTag = this.generateSrtpAuthTag(
      rolloverCounter,
      out.subarray(0, headerSize + payload.length),
    );
    authTag.copy(out, headerSize + payload.length);
    return out;
  }

  decryptRtp(
    cipherText: Buffer,
    rolloverCounter: number,
    header = parseSrtpRtpHeader(cipherText, this.authTagLength),
  ): [Buffer, RtpHeader] {
    const authTagOffset = cipherText.length - this.authTagLength;
    const encryptedPacket = cipherText.subarray(0, authTagOffset);
    const actualAuthTag = cipherText.subarray(authTagOffset);

    const expectedAuthTag = this.generateSrtpAuthTag(
      rolloverCounter,
      encryptedPacket.subarray(0, header.payloadOffset),
      encryptedPacket.subarray(header.payloadOffset),
    );
    assertAuthTag(
      actualAuthTag,
      expectedAuthTag,
      "Failed to authenticate SRTP packet",
    );

    const counter = this.generateCounter(
      header.sequenceNumber,
      rolloverCounter,
      header.ssrc,
      this.srtpSessionSalt,
    );
    // Ralai fork: decrypted with the reused keystream cipher into one buffer.
    const payload = encryptedPacket.subarray(header.payloadOffset);
    const dst = Buffer.allocUnsafe(encryptedPacket.length);
    encryptedPacket.copy(dst, 0, 0, header.payloadOffset);
    this.applySrtpKeystream(counter, payload, dst, header.payloadOffset);

    return [
      dst,
      finalizeSrtpRtpHeader(header, dst, "Failed to authenticate SRTP packet"),
    ];
  }

  encryptRTCP(rtcpPacket: Buffer, srtcpIndex: number): Buffer {
    let out = Buffer.from(rtcpPacket);
    const ssrc = out.readUInt32BE(4);

    const counter = this.generateCounter(
      srtcpIndex & 0xffff,
      srtcpIndex >> 16,
      ssrc,
      this.srtcpSessionSalt,
    );
    const cipher = createCipheriv("aes-128-ctr", this.srtcpSessionKey, counter);
    // Encrypt everything after header
    const buf = cipher.update(out.slice(8));
    buf.copy(out, 8);
    out = Buffer.concat([out, Buffer.alloc(4)]);
    out.writeUInt32BE(srtcpIndex, out.length - 4);
    out[out.length - 4] |= 0x80;
    const authTag = this.generateSrtcpAuthTag(out);
    out = Buffer.concat([out, authTag]);

    return out;
  }

  decryptRTCP(encrypted: Buffer): [Buffer, RtcpHeader] {
    const header = parseSrtcpHeader(
      encrypted,
      this.authTagLength,
      srtcpIndexSize,
    );

    const tailOffset = encrypted.length - (this.authTagLength + srtcpIndexSize);
    const authenticatedPortion = encrypted.subarray(
      0,
      encrypted.length - this.authTagLength,
    );
    const actualTag = encrypted.subarray(encrypted.length - this.authTagLength);
    const expectedTag = this.generateSrtcpAuthTag(authenticatedPortion);
    assertAuthTag(
      actualTag,
      expectedTag,
      "Failed to authenticate SRTCP packet",
    );

    const out = Buffer.from(encrypted).slice(0, tailOffset);

    const isEncrypted = encrypted[tailOffset] >>> 7;
    if (isEncrypted === 0) return [out, header];

    let srtcpIndex = encrypted.readUInt32BE(tailOffset);
    srtcpIndex &= ~(1 << 31);

    const ssrc = encrypted.readUInt32BE(4);

    const counter = this.generateCounter(
      srtcpIndex & 0xffff,
      srtcpIndex >> 16,
      ssrc,
      this.srtcpSessionSalt,
    );
    const cipher = createDecipheriv(
      "aes-128-ctr",
      this.srtcpSessionKey,
      counter,
    );
    const buf = cipher.update(out.subarray(8));
    buf.copy(out, 8);
    return [out, header];
  }

  generateSrtcpAuthTag(buf: Buffer) {
    const srtcpSessionAuth = createHmac("sha1", this.srtcpSessionAuthTag);
    return srtcpSessionAuth.update(buf).digest().slice(0, 10);
  }

  generateCounter(
    sequenceNumber: number,
    rolloverCounter: number,
    ssrc: number,
    sessionSalt: Buffer,
  ) {
    const counter = Buffer.alloc(16);
    counter.writeUInt32BE(ssrc, 4);
    counter.writeUInt32BE(rolloverCounter, 8);
    // Ralai fork: plain arithmetic instead of BigInt.
    counter.writeUInt32BE((sequenceNumber & 0xffff) * 0x10000, 12);

    for (let i = 0; i < sessionSalt.length; i++) {
      counter[i] ^= sessionSalt[i];
    }
    return counter;
  }

  generateSrtpAuthTag(roc: number, ...buffers: Buffer[]) {
    const srtpSessionAuth = createHmac("sha1", this.srtpSessionAuthTag);
    const rocRaw = Buffer.alloc(4);
    rocRaw.writeUInt32BE(roc);

    for (const buf of buffers) {
      srtpSessionAuth.update(buf);
    }
    return srtpSessionAuth.update(rocRaw).digest().subarray(0, 10);
  }
}

const srtcpIndexSize = 4;

function assertAuthTag(actual: Buffer, expected: Buffer, message: string) {
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) {
    throw new SrtpAuthenticationError(message);
  }
}
