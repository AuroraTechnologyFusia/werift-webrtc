import { setTimeout } from "timers/promises";
import { afterEach, describe, expect, test } from "vitest";

import { randomPort } from "../../../common/src";
import type { Connection } from "../../src/ice";
import { UdpMux } from "../../src/stun/udpMux";
import { createTestConnection, inviteAccept } from "../utils";

// Ralai fork: several ICE-lite agents share one UDP socket (UdpMux).

const LOOPBACK = "127.0.0.1";

const createMux = async () => {
  const port = await randomPort("udp4", { udp4: LOOPBACK });
  return UdpMux.init({ bindAddress: LOOPBACK, port, advertisedAddress: LOOPBACK });
};

const createClient = () =>
  createTestConnection(true, {
    interfaceAddresses: { udp4: LOOPBACK },
    useIpv6: false,
  });

const createMuxedLite = (mux: UdpMux) =>
  createTestConnection(false, { iceLite: true, udpMux: mux, useIpv6: false });

const connect = async (client: Connection, lite: Connection) => {
  await inviteAccept(client, lite);
  client.remoteIsLite = true;
  await Promise.all([client.connect(), lite.connect()]);
};

const nextData = (connection: Connection) =>
  new Promise<Buffer>((resolve) => {
    const { unSubscribe } = connection.onData.subscribe((data) => {
      unSubscribe();
      resolve(data);
    });
  });

describe("UdpMux", () => {
  const cleanup: (() => Promise<void>)[] = [];
  afterEach(async () => {
    for (const close of cleanup.splice(0).reverse()) {
      await close();
    }
  });

  test("two agents share one port and each receives only its own data", async () => {
    // Arrange: one mux, two lite agents on it, each with its own client
    const mux = await createMux();
    cleanup.push(() => mux.close());
    const liteA = createMuxedLite(mux);
    const liteB = createMuxedLite(mux);
    const clientA = createClient();
    const clientB = createClient();
    cleanup.push(
      () => clientA.close(),
      () => clientB.close(),
      () => liteA.close(),
      () => liteB.close(),
    );

    // Act
    await connect(clientA, liteA);
    await connect(clientB, liteB);

    // Assert: both advertise the mux's single address
    for (const lite of [liteA, liteB]) {
      const udpHosts = lite.localCandidates.filter(
        (candidate) => candidate.transport === "udp",
      );
      expect(udpHosts.map((c) => [c.host, c.port])).toEqual([
        mux.advertisedAddress,
      ]);
    }
    expect(mux.size).toBe(2);

    // Assert: data is routed per agent in both directions
    const toLiteA = nextData(liteA);
    const toLiteB = nextData(liteB);
    await clientA.send(Buffer.from("for A"));
    await clientB.send(Buffer.from("for B"));
    expect((await toLiteA).toString()).toBe("for A");
    expect((await toLiteB).toString()).toBe("for B");

    const toClientA = nextData(clientA);
    const toClientB = nextData(clientB);
    await liteA.send(Buffer.from("from A"));
    await liteB.send(Buffer.from("from B"));
    expect((await toClientA).toString()).toBe("from A");
    expect((await toClientB).toString()).toBe("from B");
  });

  test("agents with the same ufrag are told apart by MESSAGE-INTEGRITY", async () => {
    // Arrange: force a ufrag collision; the passwords differ
    const mux = await createMux();
    cleanup.push(() => mux.close());
    const liteA = createMuxedLite(mux);
    const liteB = createMuxedLite(mux);
    liteB.localUsername = liteA.localUsername;
    const clientA = createClient();
    const clientB = createClient();
    cleanup.push(
      () => clientA.close(),
      () => clientB.close(),
      () => liteA.close(),
      () => liteB.close(),
    );

    // Act
    await connect(clientA, liteA);
    await connect(clientB, liteB);

    // Assert
    const toLiteA = nextData(liteA);
    const toLiteB = nextData(liteB);
    await clientA.send(Buffer.from("for A"));
    await clientB.send(Buffer.from("for B"));
    expect((await toLiteA).toString()).toBe("for A");
    expect((await toLiteB).toString()).toBe("for B");
  });

  test("a datagram from an unknown address is dropped and reported", async () => {
    // Arrange
    const mux = await createMux();
    cleanup.push(() => mux.close());
    const unrouted: string[] = [];
    mux.onUnroutedDatagram.subscribe((addr) => {
      unrouted.push(`${addr[0]}:${addr[1]}`);
    });
    // Act: send raw data to the mux from a socket no agent knows
    const { createSocket } = await import("dgram");
    const socket = createSocket("udp4");
    cleanup.push(
      () => new Promise<void>((resolve) => socket.close(() => resolve())),
    );
    socket.send(Buffer.from("hello"), mux.advertisedAddress[1], LOOPBACK);
    await setTimeout(100);

    // Assert
    expect(unrouted).toHaveLength(1);
  });

  test("closing an agent unregisters it and leaves the socket open for others", async () => {
    // Arrange
    const mux = await createMux();
    cleanup.push(() => mux.close());
    const liteA = createMuxedLite(mux);
    const liteB = createMuxedLite(mux);
    const clientA = createClient();
    const clientB = createClient();
    cleanup.push(
      () => clientA.close(),
      () => clientB.close(),
      () => liteB.close(),
    );
    await connect(clientA, liteA);
    await connect(clientB, liteB);

    // Act
    await liteA.close();

    // Assert
    expect(mux.size).toBe(1);
    expect(mux.transport.closed).toBe(false);
    const toLiteB = nextData(liteB);
    await clientB.send(Buffer.from("still here"));
    expect((await toLiteB).toString()).toBe("still here");
  });
});
