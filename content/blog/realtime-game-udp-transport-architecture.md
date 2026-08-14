+++
title = "Designing a Bounded UDP Transport Architecture for Real-Time Games"
date = 2026-08-14
description = "An implementation-oriented architecture for a portable UDP transport layer that survives loss, reordering, jitter, congestion, and short outages without sacrificing real-time freshness."
draft = false

[taxonomies]
tags = ["networking", "game-development", "udp", "systems-architecture", "pseudocode"]
+++

Real-time games do not have one network requirement. They have several traffic classes that must coexist on the same path:

- input must arrive quickly and remain fresh;
- snapshots can become obsolete before a retransmission arrives;
- inventory, room, and match-state transitions must not be lost;
- independent events should not wait behind an unrelated missing event;
- a congested or temporarily silent path must not create an unbounded queue;
- a server must not allocate expensive per-client state for an unauthenticated source;
- the network loop must remain portable across operating systems and game engines.

The right architecture is not "UDP plus one reliability switch." It is a bounded transport with explicit message policies, packet acknowledgements, loss recovery, congestion control, memory accounting, and a clean boundary between protocol state and socket I/O.

This article develops that architecture from first principles and includes portable examples that can be used as a starting point. Production code should add complete validation, diagnostics, fuzzing, platform-specific error handling, and a reviewed cryptographic boundary.

## 1. The architectural boundary

The transport should sit between the game simulation and the operating-system socket layer:

~~~mermaid
flowchart TD
    Game["Game simulation<br/>prediction, snapshots, RPCs"]
    Connection["Connection state machine<br/>queues, ACKs, timers, loss<br/>fragmentation, reassembly"]
    Codec["Packet codec<br/>wire format"]
    Control["RTT / loss / CC<br/>pacing, cwnd, PTO"]
    Socket["Socket adapter<br/>non-blocking I/O, addresses"]

    Game -->|"typed messages and channel policy"| Connection
    Connection --> Codec
    Connection --> Control
    Codec -->|"complete UDP datagrams"| Socket
    Control -->|"complete UDP datagrams"| Socket
~~~

The connection object should not own a socket. It exposes a transmit callback and accepts complete datagrams from the caller. The same state machine can then run with a normal UDP socket, an IO completion port, an engine network thread, a packet-batching API, or a deterministic simulator.

~~~text
TYPE Result =
    OK
    ARGUMENT_ERROR
    WOULD_BLOCK
    CLOSED
    MALFORMED
    LIMIT_REACHED
    IO_ERROR

TYPE Callbacks =
    transmit(user_context, datagram_bytes) -> Result
    on_message(user_context, channel, message_sequence, payload_bytes)
    user_context

FUNCTION receive(connection, datagram_bytes, now_ms) -> Result
FUNCTION tick(connection, now_ms) -> Result
~~~

The caller owns the input datagram buffer. A message callback borrows its payload only for the callback duration. If the game needs to process it later, it copies the data into an application-owned queue.

## 2. Model traffic as explicit channel policies

Every message should declare what success means:

| Mode | Delivery | Ordering | Appropriate data |
| --- | --- | --- | --- |
| Reliable ordered | Retransmitted until acknowledged | Earlier messages block later messages | Room state, inventory, authoritative transitions |
| Reliable unordered | Retransmitted until acknowledged | No cross-message ordering | Independent events, hit confirmations, effects |
| Unreliable sequenced | No retransmission of stale state | Only newer updates are delivered | Input, transforms, snapshots |
| Unreliable | Best effort | None | Regenerable hints, telemetry, disposable effects |

Do not put all game messages onto one reliable ordered stream. One missing old packet would hold unrelated newer messages behind it. Conversely, do not mark an inventory mutation as unreliable merely because the game also has snapshots.

~~~text
TYPE ChannelMode =
    UNRELIABLE
    UNRELIABLE_SEQUENCED
    RELIABLE_UNORDERED
    RELIABLE_ORDERED

TYPE Channel =
    id
    mode: ChannelMode
    priority
~~~

Reliable ordered maintains a receive frontier and a bounded gap buffer. Reliable unordered deduplicates without waiting for unrelated sequences. Unreliable sequenced accepts only newer updates under wrapping comparison. Bare unreliable has no delivery or ordering promise.

## 3. A strict fixed wire header

A fixed header makes validation and instrumentation easier. A practical header can contain:

| Field | Size | Reason |
| --- | ---: | --- |
| magic | 2 bytes | Reject unrelated UDP traffic early |
| version | 1 byte | Permit explicit protocol evolution |
| packet type | 1 byte | Data, ACK, ping, close, or handshake |
| flags | 1 byte | Reliability and ACK behavior |
| channel | 1 byte | Logical message stream |
| payload length | 2 bytes | Exact datagram bounds |
| session ID | 8 bytes | Connection namespace |
| packet sequence | 4 bytes | Packet ACK and loss detection |
| largest ACK | 4 bytes | Highest packet received |
| ACK bitmap | 16 bytes | Previous 128 packet positions |
| message sequence | 4 bytes | Message ordering and freshness |
| send timestamp | 4 bytes | RTT and latency measurement |
| fragment index/count | 4 bytes | Application-level fragmentation |

Use explicit big-endian reads and writes. Never cast a byte buffer to a in-memory record: padding, alignment, enum width, and host endianness are not wire contracts.

~~~text
TYPE Header =
    type
    flags
    channel
    payload_length
    session_id
    packet_sequence
    largest_acknowledged
    ack_bits[4]
    message_sequence
    send_time
    fragment_index
    fragment_count

FUNCTION encode_header(header, output_capacity):
    REQUIRE output_capacity >= FIXED_HEADER_SIZE
    REQUIRE header.payload_length <= MAX_UINT16
    REQUIRE header.fragment_count > 0
    REQUIRE header.fragment_index < header.fragment_count

    WRITE magic in big-endian order
    WRITE version
    WRITE type, flags, and channel
    WRITE payload_length in big-endian order
    WRITE every integer field explicitly
    RETURN encoded_header_bytes
~~~

The decoder should reject a version mismatch, invalid type or flag combination, illegal fragment metadata, a payload length mismatch, truncated input, and trailing bytes:

~~~text
FUNCTION decode_packet(datagram):
    REQUIRE datagram.length >= FIXED_HEADER_SIZE
    REQUIRE read_u16(datagram[0..1]) == MAGIC
    REQUIRE datagram[2] == SUPPORTED_VERSION

    header = parse_all_fields_in_big_endian_order()
    REQUIRE datagram.length ==
            FIXED_HEADER_SIZE + header.payload_length
    REQUIRE header.fragment_count > 0
    REQUIRE header.fragment_index < header.fragment_count
    REQUIRE flags_are_legal_for_type(header)

    RETURN PacketView(header,
                      payload = datagram.after_header,
                      payload_length = header.payload_length)
~~~

Production code should add checked arithmetic, reserved-bit validation, packet-type validation, and tests for every boundary.

## 4. Wrapping sequence arithmetic

Packet and message sequences eventually wrap. Ordinary candidate-greater-than-reference comparisons fail at the wrap boundary:

~~~text
FUNCTION sequence_is_newer(candidate, reference):
    distance = candidate - reference using unsigned wraparound
    RETURN distance != 0 AND distance < HALF_SEQUENCE_SPACE

FUNCTION sequence_distance(newer, older):
    RETURN newer - older using unsigned wraparound
~~~

Use this helper for ACK windows, loss detection, ordered receive frontiers, and sequenced freshness. Do not mix modular comparisons with ordinary integer comparisons.

## 5. The 128-packet ACK window

The ACK window stores the largest received packet and the previous 128 positions. Bit zero of the first word represents largest minus one, bit one represents largest minus two, and so on.

~~~text
TYPE AckWindow =
    initialized
    largest
    bits[4]

FUNCTION record_ack(window, packet_sequence):
    IF NOT window.initialized:
        window.initialized = true
        window.largest = packet_sequence
        CLEAR window.bits
        RETURN NEW_PACKET

    IF sequence_is_newer(packet_sequence, window.largest):
        distance = packet_sequence - window.largest

        IF distance >= 128:
            CLEAR window.bits
        ELSE:
            SHIFT window.bits toward older positions by distance
            bit = distance - 1
            SET window.bits[bit / 32, bit MOD 32]

        window.largest = packet_sequence
        RETURN NEW_PACKET

    distance = window.largest - packet_sequence
    IF distance == 0 OR distance > 128:
        RETURN DUPLICATE_OR_TOO_OLD

    bit = distance - 1
    IF bit_is_set(window.bits, bit):
        RETURN DUPLICATE_OR_TOO_OLD

    SET window.bits[bit]
    RETURN NEW_PACKET
~~~

The ACK window answers three separate questions: whether a packet is new, whether a packet is acknowledged by the peer, and whether a new packet introduced a gap that should influence loss detection. Keep those answers separate in the implementation and tests.

## 6. Packet identity and message identity

A packet sequence identifies one datagram for ACK, loss, and congestion accounting. A message sequence identifies one application message within a channel.

One large message can produce several packet sequences but only one message sequence. A retransmission keeps the message identity while creating a new packet transmission.

~~~text
TYPE SendRecord =
    channel
    message_sequence
    fragment_count
    acknowledged_fragments
    owned_payload_copy
    payload_size
    deadline
    reliable
~~~

The record owns a copy only when the message must survive the caller's send call. A reliable record cannot be discarded until all required fragments are acknowledged or the application explicitly cancels it.

On receive, process the identities in this order:

~~~mermaid
flowchart TD
    Packet["Packet arrives"] --> Ack["Packet ACK window<br/>new / duplicate / too old"]
    Ack --> Fragments["Fragment map<br/>new / duplicate fragment"]
    Fragments --> Complete{"Complete message?"}
    Complete -->|"Reliable ordered"| Ordered["Wait for receive frontier"]
    Complete -->|"Reliable unordered"| Unordered["Deliver once"]
    Complete -->|"Sequenced"| Sequenced["Deliver only if newer"]
~~~

Do not increment reassembly bytes for a duplicate fragment. Do not invoke the game callback until all fragments are present and the message passes size and integrity checks.

## 7. Fragment above the application MTU

IP fragmentation is difficult to observe and recover from. Choose a conservative UDP datagram size and fragment application messages above that size.

~~~text
FUNCTION fragment_count(message_size, fragment_capacity):
    IF message_size == 0:
        RETURN 1
    RETURN 1 + ((message_size - 1) DIV fragment_capacity)

FUNCTION checked_add(a, b):
    IF a > MAX_SIZE - b:
        RETURN OVERFLOW
    RETURN a + b

FUNCTION checked_multiply(a, b):
    IF b != 0 AND a > MAX_SIZE DIV b:
        RETURN OVERFLOW
    RETURN a * b
~~~

Before allocating, enforce:

- message length is below the configured maximum;
- fragment count is non-zero and below the configured maximum;
- fragment index is less than fragment count;
- a non-final fragment has the expected capacity;
- a final fragment fits the remaining message size;
- aggregate reassembly bytes and message count remain below budget.

These checks protect both accidental oversized messages and hostile datagrams.

## 8. RTT, loss detection, and PTO

A useful RTT estimator tracks latest RTT, smoothed RTT, variation, minimum RTT, and the maximum delayed-ACK allowance:

~~~text
TYPE RttEstimator =
    latest_ms
    smoothed_ms
    variation_ms
    minimum_ms
    max_ack_delay_ms
    initialized

FUNCTION update_rtt(estimator, sample_ms, ack_delay_ms):
    adjusted = MAX(sample_ms - ack_delay_ms, sample_ms)

    IF NOT estimator.initialized:
        estimator.latest_ms = adjusted
        estimator.smoothed_ms = adjusted
        estimator.variation_ms = adjusted / 2
        estimator.minimum_ms = adjusted
        estimator.initialized = true
        RETURN

    estimator.minimum_ms = MIN(estimator.minimum_ms, adjusted)
    estimator.variation_ms =
        0.75 * estimator.variation_ms +
        0.25 * ABS(estimator.smoothed_ms - adjusted)
    estimator.smoothed_ms =
        0.875 * estimator.smoothed_ms + 0.125 * adjusted

FUNCTION probe_timeout(estimator, backoff_count):
    base = estimator.smoothed_ms +
           4 * estimator.variation_ms +
           estimator.max_ack_delay_ms
    base = MAX(base, MINIMUM_TIMER_MS)
    RETURN saturating_multiply(base, 2 ^ backoff_count)
~~~

A production implementation should clamp values, handle non-finite input, and keep one consistent time unit. Probe timeout should back off after repeated silence:

~~~text
FUNCTION pto_with_backoff(pto_ms, backoff_count):
    IF backoff_count >= 63:
        RETURN MAX_UINT64
    multiplier = 2 ^ backoff_count
    IF pto_ms > MAX_UINT64 / multiplier:
        RETURN MAX_UINT64
    RETURN pto_ms * multiplier
~~~

Loss can be declared by packet threshold or time threshold. Packet-threshold loss reacts quickly to reordering; time-threshold loss handles a quiet path where there are not enough later packets to create a gap signal.

## 9. Byte-based congestion control

Counting packets is misleading when one message is 40 bytes and another is 1200 bytes. Maintain bytes in flight and a byte-based congestion window:

~~~text
TYPE CongestionController =
    mss
    congestion_window
    slow_start_threshold
    bytes_in_flight
    minimum_window
    pacing_gain
    in_recovery
    recovery_start_ms

FUNCTION can_send(controller, packet_bytes):
    IF controller.bytes_in_flight > controller.congestion_window:
        RETURN false
    RETURN packet_bytes <=
           controller.congestion_window -
           controller.bytes_in_flight

FUNCTION on_packet_sent(controller, packet_bytes):
    controller.bytes_in_flight =
        saturating_add(controller.bytes_in_flight, packet_bytes)

FUNCTION on_ack(controller, acknowledged_bytes):
    controller.bytes_in_flight =
        MAX(0, controller.bytes_in_flight - acknowledged_bytes)

    IF controller.congestion_window <
       controller.slow_start_threshold:
        controller.congestion_window += acknowledged_bytes
    ELSE:
        increase = MAX(1,
            controller.mss * acknowledged_bytes /
            controller.congestion_window)
        controller.congestion_window += increase

FUNCTION on_loss(controller, lost_bytes, now_ms):
    controller.bytes_in_flight =
        MAX(0, controller.bytes_in_flight - lost_bytes)

    IF NOT controller.in_recovery OR
       now_ms >= controller.recovery_start_ms:
        controller.congestion_window =
            MAX(controller.minimum_window,
                controller.congestion_window / 2)
        controller.slow_start_threshold =
            controller.congestion_window
        controller.recovery_start_ms = now_ms
        controller.in_recovery = true
~~~

Check the congestion window before handing an ACK-eliciting packet to the socket adapter. A pacing timer should also limit how quickly the application consumes the available window.

When a queue is full, return backpressure. Do not turn it into a busy loop:

~~~text
result = send(connection, channel, payload, now_ms)

IF result == WOULD_BLOCK:
    DROP an obsolete snapshot
    OR reduce snapshot update rate
    OR enqueue a retry for an important event
ELSE IF result != OK:
    record a transport error
~~~

## 10. The event loop

The transport should be driven by a monotonic clock and a bounded loop:

~~~text
LOOP forever:
    now_ms = monotonic_milliseconds()

    REPEAT:
        datagram, source = receive_nonblocking(socket)
        IF no_datagram_is_available:
            BREAK

        IF source_is_not_bound_to_session(source, datagram):
            record_invalid_source()
            CONTINUE

        receive(connection, datagram, now_ms)

    produce_game_messages(connection, now_ms)
    tick(connection, now_ms)

    deadline = next_transport_deadline(connection)
    wait_for_socket_or_timer(socket, deadline)
~~~

Drain readable datagrams, but cap work per iteration if one peer can monopolize the loop. Call net_tick even when no datagram arrived, because retransmission and PTO timers are independent of receive activity. Use one monotonic time base for send timestamps, RTT samples, deadlines, and idle timeouts.

For a multi-peer server, parse and validate the session ID before looking up the connection. Use an O(1) table keyed by a bounded session ID or a hash table, then verify the source address associated with that session. A packet with a valid session ID from an unexpected address must not reach the connection state machine.

## 11. Stateless handshake and admission control

Do not allocate full per-peer transport state for an unauthenticated first packet. A stateless handshake can use:

1. CONNECT: nonce, requested MTU, protocol version;
2. CHALLENGE: nonce echo, time bucket, negotiated MTU, address cookie;
3. RESPONSE: challenge material returned by the client;
4. ACCEPT: non-zero session ID and negotiated timers.

The cookie can be derived from a server secret and source identity:

~~~text
cookie = HMAC(secret,
              address_family || source_ip || source_port ||
              client_nonce || time_bucket || negotiated_mtu)
~~~

Use a rotating time bucket so that a cookie expires without server-side state. Accept the current bucket and, if desired, one adjacent bucket for clock skew. Compare cookies in constant time.

The cookie proves that the response came from a host that received traffic at the claimed source address. It does not provide confidentiality, integrity for data packets, or protection from a compromised client. Steady-state datagrams need an independently reviewed authenticated-encryption boundary on an untrusted network.

Handshake processing should enforce an amplification budget. Limit challenge size, rate-limit repeated requests, and avoid allocating queues until the response is verified.

## 12. Memory ownership and reentrancy

Transport bugs often come from a correct packet algorithm combined with an incorrect lifetime assumption.

Borrowed memory:

- receive buffers belong to the caller;
- decoded payload views are valid only while that buffer is unchanged;
- callback payloads are borrowed for the callback duration;
- socket address objects returned by a receive operation may be overwritten by the next receive.

Owned memory:

- reliable queued messages own a payload copy until acknowledged or cancelled;
- incomplete fragmented messages own reassembly storage;
- retransmission records own the metadata required to rebuild a packet;
- the application owns any message copied out of a callback.

Callbacks run synchronously. Mutating the same connection recursively should be rejected or deferred:

~~~text
FUNCTION on_message(peer, channel, sequence, payload):
    copied_payload = copy(payload)
    IF copied_payload failed:
        record_backpressure(peer)
        RETURN

    enqueue(peer.deferred_work,
            channel,
            sequence,
            copied_payload)

FUNCTION flush_deferred(peer, now_ms):
    WHILE deferred_work is not empty:
        work = dequeue(peer.deferred_work)
        send(peer.connection,
             work.channel,
             work.payload,
             now_ms)
        release(work.payload)
~~~

If destruction is requested by a callback, mark the connection as closing and free it only after the outer protocol call returns.

## 13. Weak-network behavior by traffic class

Input should be sent at a bounded rate on an unreliable sequenced channel. Include an input sequence and optionally repeat recent commands in one payload.

Snapshots should carry a snapshot ID and, for deltas, a baseline ID. Use an unreliable sequenced channel and periodically send a self-contained key snapshot.

State transitions belong on reliable ordered. Give the stream a bounded gap buffer and a deadline policy. If the connection is too far behind, resynchronize from a fresh authoritative state.

Independent events belong on reliable unordered. Deduplicate at the transport layer and expose an event ID to the game layer for idempotency.

During a short outage, stop flooding the path with retransmissions. PTO backoff and congestion-window reduction limit probe traffic. When the path returns, deliver fresh state first and let the game decide whether old optional events are still relevant.

## 14. A deterministic network simulator

Before using real sockets, test the state machine against a deterministic network. Model each direction independently and own every scheduled datagram:

~~~text
TYPE Link =
    base_delay_ms
    jitter_ms
    loss_probability
    duplicate_probability
    reorder_probability
    bandwidth_bytes_per_second
    queue_limit_bytes

TYPE ScheduledEvent =
    deliver_at_ms
    destination
    owned_datagram_copy

TYPE Simulator =
    virtual_now_ms
    deterministic_seed
    forward_link
    reverse_link
    min_heap_of_events

FUNCTION send_through_link(simulator, link, source, destination, datagram):
    IF random_probability(link.loss_probability):
        record_injected_loss()
        RETURN

    delay = link.base_delay_ms +
            random_jitter(link.jitter_ms)

    enqueue_heap(simulator,
                 deliver_at = simulator.virtual_now_ms + delay,
                 destination,
                 copy(datagram))

    IF random_probability(link.duplicate_probability):
        enqueue_a_delayed_copy()

FUNCTION advance(simulator, elapsed_ms):
    simulator.virtual_now_ms += elapsed_ms
    WHILE heap_top.deliver_at <= simulator.virtual_now_ms:
        event = pop_heap()
        deliver_owned_copy(event)
~~~

Use a seeded PRNG and a stable min-heap of delivery events. Test no loss, random loss, burst loss, duplication, severe reordering, bandwidth queue overflow, maximum-size messages, sequence wraparound, complete outage and recovery, allocator failures, callback reentrancy, and deferred destruction.

A virtual clock makes failures reproducible. A real UDP loopback test is still needed for kernel buffers, socket errors, scheduling, and system-call overhead.

## 15. Complete game-peer wrapper example

This wrapper keeps protocol state, socket state, and game queues separate:

~~~text
TYPE GamePeer =
    connection
    socket
    remote_address
    receive_buffer
    deferred_work_queue

FUNCTION transmit(peer, datagram):
    result = udp_send(peer.socket,
                      peer.remote_address,
                      datagram)
    IF result indicates socket backpressure:
        RETURN WOULD_BLOCK
    IF result is an error:
        RETURN IO_ERROR
    RETURN OK

FUNCTION on_message(peer, channel, sequence, payload):
    IF NOT decode_and_queue_game_message(peer,
                                         channel,
                                         sequence,
                                         payload):
        record_bad_payload(peer)

FUNCTION poll(peer):
    now_ms = monotonic_milliseconds()

    REPEAT:
        datagram, source = udp_receive_nonblocking(peer.socket)
        IF no_datagram_is_available:
            BREAK
        IF source != peer.remote_address:
            record_invalid_source(peer)
            CONTINUE
        receive(peer.connection, datagram, now_ms)

    flush_deferred(peer, now_ms)
    tick(peer.connection, now_ms)
~~~

The wrapper does not call net_send from inside message. It copies or decodes the callback payload, returns to the transport, and flushes deferred game work afterward.

## 16. Observability and acceptance criteria

Expose counters and gauges by connection and by channel:

- packets sent, received, acknowledged, duplicated, and marked lost;
- bytes sent, received, pending, and in flight;
- retransmitted packets and ACK-only packets;
- reliable messages accepted, delivered, acknowledged, missing, and duplicated;
- sequenced updates delivered, superseded, and freshness gaps;
- incomplete reassembly messages and bytes;
- queue drops, transport backpressure, and socket would-block events;
- smoothed RTT, RTT variation, PTO, congestion window, and pacing rate;
- allocator current and peak bytes and blocks;
- time from outage recovery to the first fresh state.

Do not report one aggregate packet-loss number as the only health signal. A snapshot stream may intentionally discard old state while reliable state remains lossless.

A useful correctness gate after a bounded drain period is:

~~~text
reliable accepted == reliable delivered
reliable delivered IDs are unique and exactly match accepted IDs
ordered delivery has no regression
sequenced delivery has no regression
pending bytes == 0
tracked packets == 0
bytes in flight == 0
payload validation errors == 0
unexpected closes == 0
current transport allocations == 0 after destruction
~~~

Report p50, p95, p99, and p99.9 latency with sample counts. A p99.9 value from 40 samples is not a stable production threshold.

## 17. Design decisions and trade-offs

An architecture is easier to maintain when its choices are explicit. The following decisions are deliberate constraints, not accidental details.

### UDP instead of a byte-stream transport

The transport uses UDP because a game needs message boundaries, independent channel policies, and the ability to discard obsolete state. A byte stream has no natural concept of a snapshot that can be replaced by a newer snapshot. Reconstructing message boundaries and freshness above a stream is possible, but it moves more policy into the application and makes loss and head-of-line behavior less visible.

The cost is that the transport must implement packet sequencing, acknowledgements, loss detection, congestion control, pacing, and path validation itself. This is justified only when the game actually needs these semantics. A bulk download, patch transfer, or long-lived ordered document stream should normally use a separately managed bulk protocol.

### Packet acknowledgements instead of message acknowledgements

Acknowledging packets gives the congestion controller a precise byte-level view of what crossed the path. It also allows one reliable message to be fragmented across several packets without inventing a second acknowledgement format for every fragment.

The cost is that the transport must map packet state back to message state. A message is complete only when all required fragments are acknowledged, and a retransmitted message fragment must keep its message identity while receiving a new packet sequence. This extra bookkeeping is worthwhile because packet loss and application delivery are different events.

### A 128-bit ACK history

A fixed 128-packet history is a compromise between wire cost, reordering tolerance, and implementation complexity. It is large enough for normal bursts and moderate reordering, while four 32-bit words are cheap to serialize and inspect.

A smaller history reduces overhead but makes reordering look like loss more often. A much larger history consumes header bytes on every packet and increases shifting and validation work. The right size depends on the maximum bandwidth-delay product and the packet scheduler; it should be tested against the expected path rather than chosen from a round number.

### Separate packet and message sequences

This is one of the most important decisions. Packet sequences are for transport accounting; message sequences are for game semantics. Combining them creates ambiguity when one message is fragmented or retransmitted. Keeping them separate makes it possible to retransmit a packet without delivering the message twice, and to discard an obsolete sequenced message without corrupting packet loss accounting.

### Explicit channel modes instead of one global reliability policy

A global policy is simple to configure but usually wrong for a mixed game workload. Reliable ordered protects state transitions but can create head-of-line blocking. Unreliable sequenced protects freshness but intentionally accepts gaps. Reliable unordered costs more memory but avoids unrelated ordering stalls.

The trade-off is configuration complexity. The game team must classify messages and document what happens when each class is delayed, duplicated, or dropped. That complexity is valuable because it exposes a decision that would otherwise be hidden inside an overloaded "reliable" flag.

### Selective retransmission instead of replaying a whole window

Retransmitting only missing packets reduces bandwidth during random loss and prevents a single loss from multiplying the entire send window. It requires a tracked-packet table, packet-level ACK history, and a retransmission scheduler.

The scheduler must also avoid a retransmission storm. Loss marks should feed congestion control, PTO should back off after repeated silence, and retransmissions should compete with new data through the same pacing and congestion-window rules.

### Freshness over completeness for real-time state

Input and snapshots are modeled as replaceable state, not as a log that must be replayed. The receiver keeps the newest valid sequence and counts freshness gaps for observability. It does not attempt to repair every old snapshot.

This decision improves latency and bounds memory, but it changes application design. Snapshot payloads should contain enough state to be useful when an earlier snapshot was lost. Delta compression therefore needs periodic self-contained key snapshots and explicit baseline validation.

### Application-level fragmentation instead of IP fragmentation

The transport chooses a conservative datagram size and fragments messages above that size. IP fragmentation is avoided because the application cannot reliably observe every fragment, assign useful retransmission policy, or enforce a message memory budget at the IP layer.

The cost is a reassembly table and additional fragment metadata. Those costs are predictable and can be bounded. The design intentionally rejects a message when its fragment count or total size exceeds a configured limit instead of allocating indefinitely.

### Bounded memory and visible backpressure

An unbounded queue hides failure until the process runs out of memory. A bounded queue makes overload visible as WOULD_BLOCK, queue-drop counters, and application callbacks. The game can then reduce snapshot rate, reduce precision, drop an obsolete state, or retry an important event.

This means a send operation is not a promise that the datagram has already reached the network. It is a promise that the transport accepted the message within its current budget. The application must distinguish accepted, transmitted, acknowledged, and delivered states.

### A socket-free connection object

Separating the connection state machine from socket I/O avoids locking the transport to one operating-system API or one thread model. It also makes deterministic testing possible: the same connection can exchange datagrams through a virtual clock without opening a socket.

The cost is a stricter integration contract. The caller must supply complete datagrams, call tick regularly, handle WOULD_BLOCK, and provide a monotonic clock. A socket-free design is only useful if those responsibilities are documented and tested.

### Single-owner connection state instead of internal locks

Each connection is owned by one event-loop context, and callers serialize access. This keeps queue traversal, callbacks, timers, and deferred destruction easy to reason about. It also avoids hidden lock contention in the hot path.

The cost is that a multi-threaded engine needs an explicit handoff queue. Network threads should enqueue datagrams or events to the connection owner rather than calling the connection concurrently. This is usually easier to profile than a transport with internal locks and callback-induced lock ordering.

### Synchronous callbacks with deferred mutation

Synchronous callbacks make delivery order deterministic and avoid an extra event allocation for every message. They also make payload lifetime obvious: the payload is borrowed until the callback returns.

The danger is reentrancy. A callback that recursively sends, receives, ticks, or destroys the same connection can invalidate the outer operation. The architecture therefore rejects recursive mutation or defers it until the outer call returns. This is a small API restriction that prevents a large class of use-after-free and iterator invalidation bugs.

### Stateless cookie admission before expensive allocation

The server verifies an address-bound cookie before creating per-peer queues and reassembly state. This prevents spoofed-source packets from consuming the same resources as an authenticated session.

The trade-off is an additional handshake round trip and a server secret rotation policy. Cookies also do not authenticate or encrypt steady-state data. Admission control and data security are intentionally separate responsibilities.

### Monotonic time supplied by the caller

All send timestamps, RTT samples, deadlines, idle timers, and PTO calculations use one monotonic time base. Wall-clock adjustments must not make a packet appear to have a negative age or make a timeout fire immediately.

The caller must provide a correct clock and consistent units. A transport should reject or clamp impossible time values rather than silently mixing seconds, milliseconds, and wall-clock timestamps.

### Strict decoding before dispatch

The decoder rejects unknown versions, invalid flags, impossible fragment metadata, truncated datagrams, and trailing bytes before the packet reaches connection logic. Early rejection keeps malformed input out of allocation, ACK, and reassembly paths.

The cost is less tolerance for accidental format variation. That is intentional: protocol evolution should use an explicit version or extension mechanism, not silently accept ambiguous bytes.

### Security boundary outside the transport core

The transport can provide address-bound admission cookies and session validation, but authenticated encryption requires key exchange, nonce management, replay protection, and cryptographic review. Keeping that boundary explicit avoids creating a custom cryptographic protocol by accident.

The result is a layered deployment: the transport handles packet mechanics and game delivery policy, while a mature security layer provides confidentiality and authenticated integrity.

### Deterministic simulation plus real socket testing

A deterministic simulator makes loss, jitter, duplicate, reordering, and outage cases reproducible. Real UDP tests expose kernel buffers, socket errors, scheduler behavior, and file-descriptor limits. Neither replaces the other.

The decision to maintain both test paths increases test code, but it prevents two common mistakes: trusting an idealized simulator as a performance benchmark, or trusting a loopback benchmark as evidence about a weak real network.

## 18. Bandwidth arbitration: who sends first?

When the congestion window, pacing budget, or socket queue is full, the answer should come from an explicit scheduler rather than from whichever queue happens to be traversed first.

There is no universal order for every game, but a safe default is:

1. control traffic: handshake responses, ACKs, loss probes, and close signals;
2. recovery traffic: retransmissions that are still within their delivery policy;
3. deadline-sensitive input and commands;
4. reliable ordered state transitions;
5. reliable unordered events;
6. the newest snapshot for each entity or interest group;
7. bulk, telemetry, and optional cosmetic data.

This order is not a strict global priority queue. It has reservations and fairness rules:

- reserve a small portion of every pacing interval for control traffic;
- cap the fraction consumed by retransmissions so a loss burst cannot starve fresh input forever;
- let deadlines increase urgency for input and state transitions;
- coalesce replaceable snapshots so only the newest pending snapshot remains;
- use weighted round-robin or deficit round-robin between channels of the same urgency;
- rotate ties by channel and peer so one connection cannot monopolize the scheduler.

### Why reliable traffic is not always first

Reliable messages need eventual delivery, but sending every retransmission before fresh input can make a game feel unresponsive during an outage. The recovery lane should receive enough budget to make progress, while the deadline lane must continue to receive a bounded share.

If a reliable message has a hard deadline, it can temporarily receive a higher score. That should be an explicit application decision, not an accidental consequence of putting all reliable queues at the front of a list.

### Why snapshots are not simply last

Snapshots are replaceable, but they are still needed to keep remote state visually fresh. A scheduler should discard an older pending snapshot before delaying the newest one. The queue should store one latest snapshot per replacement key rather than an unbounded history.

### A practical scheduler score

Each eligible packet gets a score based on class priority, deadline urgency, retransmission age, and fairness debt:

~~~text
FUNCTION score(candidate, now_ms):
    score = class_weight(candidate.class)

    IF candidate.has_deadline:
        remaining = candidate.deadline_ms - now_ms
        IF remaining <= 0:
            score += EXPIRED_DEADLINE_BONUS
        ELSE:
            score += DEADLINE_SCALE / remaining

    IF candidate.is_retransmission:
        score += MIN(candidate.retry_age_ms / RETRY_AGE_SCALE,
                     RETRY_BONUS_CAP)

    score += candidate.fairness_credit
    RETURN score
~~~

The score must not be the only protection. A packet is eligible only when the congestion controller, pacing timer, and per-class quota all permit it:

~~~text
FUNCTION choose_next_packet(now_ms):
    candidates = all_nonempty_queues()
    candidates = FILTER candidates WHERE
        congestion_window_allows(candidate) AND
        pacing_budget_allows(candidate) AND
        class_quota_allows(candidate)

    IF candidates is empty:
        RETURN NONE

    selected = candidate_with_highest_score(candidates)
    BREAK_TIES_USING_ROUND_ROBIN(selected.class, selected.peer)
    RETURN selected
~~~

After sending, subtract the packet bytes from the congestion and pacing budgets, reduce the selected class credit, and increase the credit of eligible classes that were skipped. This is what prevents a high-priority stream from permanently starving a lower-priority stream.

### Suggested quota model

The following is a starting point, not a universal constant:

| Lane | Role | Budget rule |
| --- | --- | --- |
| Control | ACK, PTO probe, handshake, close | Reserved first; never wait behind game data |
| Recovery | Reliable retransmission | High priority, but capped per pacing interval |
| Deadline | Input and urgent commands | Minimum service share; deadline can raise priority |
| State | Reliable ordered transitions | Weighted service, deadline-aware |
| Freshness | Latest snapshots | Coalescing queue; old state is dropped |
| Optional | Telemetry and bulk | Uses only remaining capacity |

For example, a pacing interval can reserve 8% for control, allow recovery to consume at most 40%, guarantee a minimum 20% to deadline-sensitive traffic, and distribute the remainder by configured channel weights. The exact values should be tuned from measured RTT, packet size, loss rate, and game deadlines.

### What happens when the queue is already full?

Queue admission and wire scheduling are separate decisions:

~~~text
ON application_send(message):
    IF message is replaceable snapshot:
        replace older pending snapshot with message
        RETURN ACCEPTED_OR_COALESCED

    IF pending_bytes + message.size > pending_limit:
        IF message is optional:
            RETURN WOULD_BLOCK_OR_DROPPED
        IF message is reliable:
            RETURN WOULD_BLOCK

    enqueue message according to channel policy
    RETURN ACCEPTED
~~~

An accepted reliable message must remain owned until its delivery policy completes. An accepted snapshot may be replaced by a newer snapshot if the channel explicitly allows coalescing. Input can also be coalesced, but only if the game payload contains enough information to recover from skipped commands.

The key rule is that bandwidth arbitration must preserve three guarantees simultaneously: control traffic keeps the connection alive, reliable traffic makes bounded progress, and fresh real-time state continues to move. A single static priority list cannot provide all three under every loss pattern; reservations, deadlines, coalescing, and fairness are the complete policy.

## 19. Tuning and production checklist

A useful starting profile is input at roughly 60 Hz on unreliable sequenced, snapshots at 20-30 Hz on a separate unreliable sequenced channel, room and inventory transitions on reliable ordered, and independent events on reliable unordered. Keep bulk downloads on a separate service rather than competing with the real-time congestion window.

If pending queue delay exceeds one game tick, reduce snapshot rate, precision, or entity count instead of accumulating obsolete state. Tune ACK delay, keepalive, idle timeout, initial RTT, pending limits, and reassembly limits from measured traffic.

Before shipping:

1. Define message classes and choose a channel policy for each one.
2. Set MTU and maximum message size from the real deployment path.
3. Enforce checked arithmetic for allocation sizes and counters.
4. Bound pending bytes, pending messages, tracked packets, fragments, and reassembly.
5. Use explicit endian conversion; never serialize a in-memory record by casting.
6. Test ACK boundaries, packet duplication, reordering, and sequence wraparound.
7. Use a monotonic clock for every transport timestamp and deadline.
8. Make reliable message IDs exact and idempotent at the application boundary.
9. Validate session ID and source address before dispatching a datagram.
10. Authenticate the handshake and rate-limit unauthenticated responses.
11. Add authenticated encryption at the deployment boundary.
12. Treat callback data as borrowed and defer recursive mutation.
13. Run deterministic weak-network tests in CI.
14. Run real multi-socket loopback and cross-host tests separately.
15. Record latency distributions, freshness, retransmissions, congestion, queues, and memory peaks.
16. Establish hardware-specific thresholds instead of copying numbers from another machine.

The central idea is to separate packet mechanics from message semantics, make every resource finite, and let the game choose what is worth preserving. Once those decisions are explicit, loss recovery, congestion control, weak-network testing, and production diagnostics become composable parts of one understandable state machine.

## Acknowledgements

This article builds on decades of work in computer networking, transport-protocol design, congestion-control research, and real-time game networking. The ideas around packet acknowledgement windows, RTT estimation, loss thresholds, probe backoff, pacing, stateless admission cookies, and deterministic network simulation are the result of many engineers and researchers sharing measurements, standards, and implementation lessons.

Thanks to the open-source networking community and to the game engineers who have documented the practical consequences of packet loss, reordering, bufferbloat, mobile-network handovers, and overloaded queues. Their experience is what turns abstract transport mechanisms into useful design rules: preserve freshness where possible, guarantee delivery where necessary, and make every resource limit visible.
