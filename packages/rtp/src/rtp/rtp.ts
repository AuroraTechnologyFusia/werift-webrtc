
export type Extension = { id: number; payload: Buffer };

export const ExtensionProfiles = {
  OneByte: 0xbede, // 48862
  TwoByte: 0x1000, // 4096
} as const;
type ExtensionProfile =
  (typeof ExtensionProfiles)[keyof typeof ExtensionProfiles];

const seqNumOffset = 2;
const timestampOffset = 4;
const ssrcOffset = 8;
const csrcOffset = 12;
const csrcSize = 4;

/*
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |V=2|P|X|  CC   |M|     PT      |       sequence number         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                           timestamp                           |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           synchronization source (SSRC) identifier            |
 * +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
 * |            contributing source (CSRC) identifiers             |
 * |                             ....                              |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

export class RtpHeader {
  version = 2;
  padding = false;
  paddingSize = 0;
  extension = false;
  marker = false;
  payloadOffset = 0;
  payloadType = 0;
  /**16bit, 初期値はランダムである必要があります*/
  sequenceNumber = 0;
  /**32bit microsec (milli/1000), 初期値はランダムである必要があります*/
  timestamp = 0;
  ssrc = 0;
  csrcLength = 0;
  csrc: number[] = [];
  extensionProfile: ExtensionProfile = ExtensionProfiles.OneByte;
  /**deserialize only */
  extensionLength?: number;
  extensions: Extension[] = [];
  constructor(props?: Partial<RtpHeader>) {
    // Ralai fork: the RTP hot path builds headers with no props; skip the
    // Object.assign then.
    if (props) {
      Object.assign(this, props);
    }
  }

  // Ralai fork: parsed with direct byte reads (no getBit, no per-field
  // subarray, no array spread): this runs once per received packet.
  static deSerialize(rawPacket: Buffer) {
    const h = new RtpHeader();
    const v_p_x_cc = rawPacket[0];
    h.version = v_p_x_cc >> 6;
    h.padding = (v_p_x_cc & 0x20) !== 0;
    h.extension = (v_p_x_cc & 0x10) !== 0;
    h.csrcLength = v_p_x_cc & 0x0f;

    const m_pt = rawPacket[1];
    h.marker = (m_pt & 0x80) !== 0;
    h.payloadType = m_pt & 0x7f;

    h.sequenceNumber = rawPacket.readUInt16BE(seqNumOffset);
    h.timestamp = rawPacket.readUInt32BE(timestampOffset);
    h.ssrc = rawPacket.readUInt32BE(ssrcOffset);

    let currOffset = csrcOffset;
    if (h.csrcLength > 0) {
      const csrc: number[] = new Array(h.csrcLength);
      for (let i = 0; i < h.csrcLength; i++) {
        csrc[i] = rawPacket.readUInt32BE(currOffset);
        currOffset += csrcSize;
      }
      h.csrc = csrc;
    }
    if (h.extension) {
      h.extensionProfile = rawPacket.readUInt16BE(
        currOffset,
      ) as ExtensionProfile;
      currOffset += 2;
      const extensionLength = rawPacket.readUInt16BE(currOffset) * 4;
      h.extensionLength = extensionLength;
      currOffset += 2;

      switch (h.extensionProfile) {
        // RFC 8285 RTP One Byte Header Extension
        case ExtensionProfiles.OneByte:
          {
            const end = currOffset + extensionLength;
            while (currOffset < end) {
              if (rawPacket[currOffset] === 0x00) {
                currOffset++;
                continue;
              }

              const extId = rawPacket[currOffset] >> 4;
              const len =
                (rawPacket[currOffset] & (rawPacket[currOffset] ^ 0xf0)) + 1; // and not &^
              currOffset++;
              if (extId === 0xf) {
                break;
              }
              const extension: Extension = {
                id: extId,
                payload: rawPacket.subarray(currOffset, currOffset + len),
              };
              h.extensions.push(extension);
              currOffset += len;
            }
          }
          break;
        // RFC 8285 RTP Two Byte Header Extension
        case ExtensionProfiles.TwoByte:
          {
            const end = currOffset + extensionLength;
            while (currOffset < end) {
              if (rawPacket[currOffset] === 0x00) {
                currOffset++;
                continue;
              }
              const extId = rawPacket[currOffset];
              currOffset++;
              const len = rawPacket[currOffset];
              currOffset++;

              const extension: Extension = {
                id: extId,
                payload: rawPacket.subarray(currOffset, currOffset + len),
              };
              h.extensions.push(extension);
              currOffset += len;
            }
          }
          break;
        default:
          {
            const extension: Extension = {
              id: 0,
              payload: rawPacket.subarray(
                currOffset,
                currOffset + extensionLength,
              ),
            };
            h.extensions.push(extension);
            currOffset += h.extensions[0].payload.length;
          }
          break;
      }
    }
    h.payloadOffset = currOffset;
    if (h.padding) {
      h.paddingSize = rawPacket[rawPacket.length - 1];
    }

    return h;
  }

  get serializeSize() {
    const { csrc, extensionProfile, extensions } = this;

    let size = 12 + csrc.length * csrcSize;

    if (extensions.length > 0 || this.extension === true) {
      let extSize = 4;
      switch (extensionProfile) {
        case ExtensionProfiles.OneByte:
          for (const extension of extensions) {
            extSize += 1 + extension.payload.length;
          }
          break;
        case ExtensionProfiles.TwoByte:
          for (const extension of extensions) {
            extSize += 2 + extension.payload.length;
          }
          break;
        default:
          extSize += extensions[0].payload.length;
      }
      size += Math.floor((extSize + 3) / 4) * 4;
    }

    return size;
  }

  serialize(size: number) {
    const buf = Buffer.alloc(size);
    let offset = 0;

    // Ralai fork: direct bit operations instead of BitWriter objects.
    if (this.extensions.length > 0) this.extension = true;
    buf[offset++] =
      ((this.version & 0x03) << 6) |
      (this.padding ? 0x20 : 0) |
      (this.extension ? 0x10 : 0) |
      (this.csrc.length & 0x0f);
    buf[offset++] = (this.marker ? 0x80 : 0) | (this.payloadType & 0x7f);

    buf.writeUInt16BE(this.sequenceNumber, seqNumOffset);
    offset += 2;
    buf.writeUInt32BE(this.timestamp, timestampOffset);
    offset += 4;
    buf.writeUInt32BE(this.ssrc, ssrcOffset);
    offset += 4;

    for (const csrc of this.csrc) {
      buf.writeUInt32BE(csrc, offset);
      offset += 4;
    }

    if (this.extension) {
      const extHeaderPos = offset;
      buf.writeUInt16BE(this.extensionProfile, offset);
      offset += 4;
      const startExtensionsPos = offset;

      switch (this.extensionProfile) {
        case ExtensionProfiles.OneByte:
          for (const extension of this.extensions) {
            buf.writeUInt8(
              (extension.id << 4) | (extension.payload.length - 1),
              offset++,
            );
            extension.payload.copy(buf, offset);
            offset += extension.payload.length;
          }
          break;
        case ExtensionProfiles.TwoByte: // 1バイトで収まらなくなった歴史的経緯
          for (const extension of this.extensions) {
            buf.writeUInt8(extension.id, offset++);
            buf.writeUInt8(extension.payload.length, offset++);
            extension.payload.copy(buf, offset);
            offset += extension.payload.length;
          }
          break;
        default: {
          const extLen = this.extensions[0].payload.length;
          if (extLen % 4 != 0) {
            throw new Error();
          }
          this.extensions[0].payload.copy(buf, offset);
          offset += extLen;
        }
      }

      const extSize = offset - startExtensionsPos;
      const roundedExtSize = Math.trunc((extSize + 3) / 4) * 4;

      buf.writeUInt16BE(Math.trunc(roundedExtSize / 4), extHeaderPos + 2);
      // padding 4 bytes boundaries
      for (let i = 0; i < roundedExtSize - extSize; i++) {
        buf.writeUInt8(0, offset);
        offset++;
      }
    }
    this.payloadOffset = offset;
    return buf;
  }
}

export class RtpPacket {
  constructor(
    public header: RtpHeader,
    public payload: Buffer,
  ) {}

  get serializeSize() {
    return this.header.serializeSize + this.payload.length;
  }

  // Ralai fork: field-by-field copy instead of spread + Object.assign; arrays are
  // copied so the clone's header can be rewritten without touching the source.
  clone() {
    const source = this.header;
    const header = new RtpHeader();
    header.version = source.version;
    header.padding = source.padding;
    header.paddingSize = source.paddingSize;
    header.extension = source.extension;
    header.marker = source.marker;
    header.payloadOffset = source.payloadOffset;
    header.payloadType = source.payloadType;
    header.sequenceNumber = source.sequenceNumber;
    header.timestamp = source.timestamp;
    header.ssrc = source.ssrc;
    header.csrcLength = source.csrcLength;
    header.csrc = source.csrc.slice();
    header.extensionProfile = source.extensionProfile;
    header.extensionLength = source.extensionLength;
    header.extensions = source.extensions.slice();
    return new RtpPacket(header, this.payload);
  }

  serialize() {
    let buf = this.header.serialize(
      this.header.serializeSize + this.payload.length,
    );
    const { payloadOffset } = this.header;
    this.payload.copy(buf, payloadOffset);
    if (this.header.padding) {
      const padding = Buffer.alloc(this.header.paddingSize);
      padding.writeUInt8(this.header.paddingSize, this.header.paddingSize - 1);
      buf = Buffer.concat([buf, padding]);
    }

    return buf;
  }

  static deSerialize(buf: Buffer) {
    const header = RtpHeader.deSerialize(buf);
    const p = new RtpPacket(
      header,
      buf.subarray(header.payloadOffset, buf.length - header.paddingSize),
    );
    return p;
  }

  clear() {
    this.payload = null as any;
  }
}
