import type { Address } from "../imports/common";
import { debug, Event, UdpTransport } from "../imports/common";
import { classes, methods } from "./const";
import { parseMessage } from "./message";
import { StunProtocol } from "./protocol";

const log = debug("werift-ice : packages/ice/src/stun/udpMux.ts");

/**
 * One UDP socket shared by many ICE agents (Ralai fork).
 *
 * A server with a single public UDP port (for example a Fly.io UDP service,
 * which needs the internal and external port to match) cannot give every
 * agent its own socket. The mux routes each datagram to its agent:
 *
 * - a STUN Binding request by its USERNAME (`<local ufrag>:<remote ufrag>`),
 *   confirmed by verifying MESSAGE-INTEGRITY with that agent's password, so a
 *   ufrag shared by two agents (4 hex characters) is still routed correctly;
 *   the sender's address is then bound to that agent;
 * - everything else (DTLS, SRTP, STUN responses) by the sender's address.
 *
 * Agents on a mux should run as ICE lite: they never send checks first, so
 * every remote address is learned from an authenticated request.
 */
export interface UdpMuxOptions {
  /** The address the socket binds to (e.g. the resolved `fly-global-services`). */
  bindAddress: string;
  /** The one port, bound and advertised. */
  port: number;
  /** The address advertised in host candidates (e.g. the public IPv4). */
  advertisedAddress: string;
}

const addressKey = (addr: Address) => `${addr[0]}:${addr[1]}`;

export class UdpMux {
  /** A datagram no registered agent claimed; for observability. */
  readonly onUnroutedDatagram = new Event<[Address]>();
  private readonly protocols = new Set<MuxedStunProtocol>();
  private readonly protocolByAddress = new Map<string, MuxedStunProtocol>();
  private readonly addressesByProtocol = new Map<MuxedStunProtocol, Set<string>>();

  private constructor(
    readonly transport: UdpTransport,
    readonly options: UdpMuxOptions,
  ) {}

  static async init(options: UdpMuxOptions) {
    const transport = await UdpTransport.init("udp4", {
      port: options.port,
      interfaceAddresses: { udp4: options.bindAddress },
    });
    const mux = new UdpMux(transport, options);
    transport.onData = (data, addr) => {
      mux.datagramReceived(data, addr);
    };
    return mux;
  }

  get advertisedAddress(): Address {
    return [this.options.advertisedAddress, this.options.port];
  }

  /** Number of agents registered; for observability. */
  get size() {
    return this.protocols.size;
  }

  register(protocol: MuxedStunProtocol) {
    this.protocols.add(protocol);
    this.addressesByProtocol.set(protocol, new Set());
  }

  unregister(protocol: MuxedStunProtocol) {
    const addresses = this.addressesByProtocol.get(protocol);
    if (addresses) {
      for (const key of addresses) {
        if (this.protocolByAddress.get(key) === protocol) {
          this.protocolByAddress.delete(key);
        }
      }
    }
    this.addressesByProtocol.delete(protocol);
    this.protocols.delete(protocol);
  }

  async close() {
    for (const protocol of [...this.protocols]) {
      await protocol.close();
    }
    await this.transport.close();
  }

  private datagramReceived(data: Buffer, addr: Address) {
    const message = parseMessage(data);
    if (
      message &&
      message.messageClass === classes.REQUEST &&
      message.messageMethod === methods.BINDING
    ) {
      const owner = this.findRequestOwner(data, message.getAttributeValue("USERNAME"));
      if (!owner) {
        log("unrouted binding request", addr);
        this.onUnroutedDatagram.execute(addr);
        return;
      }
      this.bindAddress(owner, addr);
      owner.receiveMuxed(data, addr);
      return;
    }

    const owner = this.protocolByAddress.get(addressKey(addr));
    if (!owner) {
      log("unrouted datagram", addr);
      this.onUnroutedDatagram.execute(addr);
      return;
    }
    owner.receiveMuxed(data, addr);
  }

  private findRequestOwner(data: Buffer, username: unknown) {
    if (typeof username !== "string") {
      return undefined;
    }
    const [localFragment] = username.split(":");
    for (const protocol of this.protocols) {
      const password = protocol.localPasswordFor(localFragment);
      if (password === undefined) {
        continue;
      }
      if (parseMessage(data, Buffer.from(password, "utf8"))) {
        return protocol;
      }
    }
    return undefined;
  }

  private bindAddress(protocol: MuxedStunProtocol, addr: Address) {
    const key = addressKey(addr);
    const previous = this.protocolByAddress.get(key);
    if (previous === protocol) {
      return;
    }
    if (previous) {
      this.addressesByProtocol.get(previous)?.delete(key);
    }
    this.protocolByAddress.set(key, protocol);
    this.addressesByProtocol.get(protocol)?.add(key);
  }
}

/**
 * A StunProtocol on a UdpMux: it shares the mux's socket, advertises the mux's
 * address, and leaves the socket open when it closes.
 */
export class MuxedStunProtocol extends StunProtocol {
  constructor(
    private readonly mux: UdpMux,
    /** The agent's password for one of its local ufrags, or undefined. */
    private readonly passwordFor: (usernameFragment: string) => string | undefined,
  ) {
    super();
  }

  connectionMade = async () => {
    this.transport = this.mux.transport;
    this.mux.register(this);
  };

  localPasswordFor(usernameFragment: string) {
    return this.passwordFor(usernameFragment);
  }

  /** A datagram the mux routed to this agent. */
  receiveMuxed(data: Buffer, addr: Address) {
    this.datagramReceived(data, addr);
  }

  getExtraInfo(): Address {
    return this.mux.advertisedAddress;
  }

  protected async closeTransport() {
    this.mux.unregister(this);
  }
}
