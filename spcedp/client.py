"""Asyncio TCP server that an SPC panel dials in to.

The panel is the TCP client; we are the receiver.  Once a connection is
up, traffic looks like:

  panel  ->  HELLO            (major=1 min=2,  8 random bytes)
  us     ->  HELLO_ACK        (echo same bytes back)
  panel  ->  POLL  every 10s  (major=1 min=0,  8 random bytes)
  us     ->  POLL_ACK         (echo)
  panel  ->  SIA_EVENT        (major=2 min=0, ASCII payload)
  us     ->  SIA_EVENT_ACK    (echo)
  us     ->  CMD_REQ          (major=10 XML or major=4 binary)
  panel  ->  CMD_REPLY
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import ssl
from collections.abc import AsyncIterator, Callable, Coroutine
from dataclasses import dataclass, field
from types import TracebackType
from typing import Any

from .commands import BinaryCommand, BinaryOp, PanelOp
from .errors import (
    PanelRejected,
    ReplyCode,
    SpcConnectionLost,
    SpcProtocolError,
    SpcTimeout,
)
from .events import SiaEvent
from .wire import (
    FLAG_FROM_RECEIVER,
    EncryptionRequired,
    Frame,
    FrameDecodeError,
    FrameDecoder,
    MajorCode,
    MinorCode,
)
from .xmlcmd import AttrValue, ReplyAssembler, XmlReply, build_request, parse_reply

log = logging.getLogger("spcedp")

# Bound on the buffered SIA event stream; the oldest event is dropped if a
# consumer falls this far behind (see Session.emit_event).
EVENT_QUEUE_MAXSIZE = 1024
# Backstop on a single fragmented XML reply, so a panel that never closes
# </COMMAND_REPLY> can't spin xml_command forever.
MAX_XML_FRAGMENTS = 64
# Disconnect a peer that sends nothing for this long; the panel polls ~10s.
DEFAULT_IDLE_TIMEOUT = 120.0
# Warn (rising edge) if the outbound queue backs up this far - a peer not
# draining its socket. The queue is bounded by WRITE_QUEUE_MAXSIZE so a stuck
# writer can't grow it without limit; once it hits the cap the session is torn
# down rather than silently dropping an outbound ACK or alarm frame.
WRITE_QUEUE_WARN = 256
# Hard cap on the outbound queue. _send uses put_nowait, so on QueueFull we tear
# the session down (set _closed) rather than block the read loop or drop a frame.
WRITE_QUEUE_MAXSIZE = 2048


@dataclass(slots=True)
class Session:
    """One panel-side TCP connection.

    Created by PanelServer for each inbound connection and handed to the
    user's on_session / on_event callbacks.  Holds the request/reply
    correlation state, the outbound write queue, and the SIA event feed.

    NOTE: the constructor (field set and order) is NOT part of the public
    API - only PanelServer constructs Session, and the field layout may
    change between 0.x releases.  The contractual surface for callbacks is
    the public method set: xml_command, binary_command, panel_command,
    events, and wait_ready.
    """

    panel_id: int
    receiver_id: int
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    next_seq: int = 0
    # repr=False: keep the EDP key out of repr(Session) so it can't leak via a
    # third-party reporter that renders locals/objects.
    key: bytes | None = field(default=None, repr=False)
    _pending_xml: dict[int, asyncio.Future[bytes]] = field(default_factory=dict)
    _pending_bin: dict[int, asyncio.Future[bytes]] = field(default_factory=dict)
    _ready: asyncio.Event = field(default_factory=asyncio.Event)
    _events: asyncio.Queue[SiaEvent] = field(
        default_factory=lambda: asyncio.Queue(maxsize=EVENT_QUEUE_MAXSIZE)
    )
    _write_queue: asyncio.Queue[bytes] = field(
        default_factory=lambda: asyncio.Queue(maxsize=WRITE_QUEUE_MAXSIZE)
    )
    _tasks: set[asyncio.Task] = field(default_factory=set)
    _closed: asyncio.Event = field(default_factory=asyncio.Event)
    _poll_count: int = 0
    # True once a WRITE_QUEUE_WARN rising-edge has been logged; reset when the
    # queue drains back below the threshold so the warning re-arms.
    _write_warned: bool = field(default=False, repr=False)
    # Set when the writer/session done-callbacks tear the session down. The read
    # loop in PanelServer._handle awaits this and stops, so an unexpected writer
    # death or a crashed on_session does not leave a mute-but-alive receiver.
    _teardown_requested: asyncio.Event = field(default_factory=asyncio.Event, repr=False)

    async def wait_ready(self, min_polls: int = 1) -> None:
        """Wait until the panel has completed at least N polls post-HELLO."""
        while self._poll_count < min_polls:
            self._ready.clear()
            await self._ready.wait()

    def _alloc_seq(self) -> int:
        self.next_seq = (self.next_seq + 1) & 0xFFFFFFFF
        return self.next_seq

    def _frame(self, *, major: int, minor: int, payload: bytes, sequence: int) -> Frame:
        """Build an outbound frame addressed from this receiver to the panel."""
        return Frame(
            src_id=self.receiver_id,
            dst_id=self.panel_id,
            sequence=sequence,
            major=major,
            minor=minor,
            payload=payload,
            src_flag=FLAG_FROM_RECEIVER,
        )

    def _send(self, frame: Frame) -> None:
        """Queue a frame for the writer task; never blocks the caller.

        The queue is bounded (WRITE_QUEUE_MAXSIZE). If it is full the writer is
        not draining (slow/dead peer), so we tear the session down rather than
        block the read loop or silently drop an outbound ACK/alarm frame.
        """
        data = frame.encode(key=self.key)
        try:
            self._write_queue.put_nowait(data)
        except asyncio.QueueFull:
            log.error(
                "outbound queue full at %d frames; peer not draining - tearing session down",
                WRITE_QUEUE_MAXSIZE,
            )
            self.request_teardown()
            return
        qsize = self._write_queue.qsize()
        # Rising-edge warning: fire once when the queue first crosses the warn
        # threshold, re-arm only after it drains back below it. An exact `== N`
        # check fires at most once and is missed if the queue steps over N.
        if qsize >= WRITE_QUEUE_WARN:
            if not self._write_warned:
                self._write_warned = True
                log.warning(
                    "outbound queue at %d frames (warn=%d); is the panel draining its socket?",
                    qsize,
                    WRITE_QUEUE_WARN,
                )
        elif self._write_warned:
            self._write_warned = False

    def request_teardown(self) -> None:
        """Signal that this session must be torn down.

        Sets _closed (waking events() consumers and failing in-flight requests
        is handled by _teardown) and _teardown_requested, which the read loop
        awaits so it stops and runs the normal teardown path. Idempotent.
        """
        self._closed.set()
        self._teardown_requested.set()

    async def _writer_loop(self) -> None:
        """Drain queued outbound frames to the socket on a dedicated task.

        Keeping writes - and writer.drain() backpressure - off the read
        loop means a slow or backpressured send can't stall inbound POLL
        handling and trip the panel's link-dead timer.
        """
        try:
            while True:
                data = await self._write_queue.get()
                self.writer.write(data)
                await self.writer.drain()
        except (OSError, ssl.SSLError) as exc:
            # Any socket-level write/drain failure (ConnectionResetError and
            # BrokenPipeError are OSError subclasses), plus TLS errors. Log and
            # return; the done-callback treats a non-cancelled exit as
            # unexpected and tears the session down so we don't go mute-alive.
            # CancelledError (the normal teardown-driven shutdown) is not an
            # OSError, so it propagates past this handler untouched.
            log.warning("writer loop exiting on socket error: %s", exc)
            return

    def fail_pending(self, exc: BaseException) -> None:
        """Resolve every in-flight request future with `exc`.

        Called on disconnect so awaiting callers fail fast with a clear
        error instead of blocking until their own timeout fires.
        """
        for pending in (self._pending_xml, self._pending_bin):
            for fut in pending.values():
                if not fut.done():
                    fut.set_exception(exc)
            pending.clear()

    def reply_echo(self, req: Frame, minor: int) -> None:
        """Queue a reply frame echoing the request's sequence and payload.

        Used for POLL_ACK / HELLO_ACK / SIA_EVENT_ACK - the receiver
        replays the request payload verbatim.  The checksum is
        recomputed by Frame.encode (Frame.checksum is RX-only metadata), so
        it is not echoed.
        """
        self._send(
            self._frame(
                major=req.major,
                minor=minor,
                payload=req.payload,
                sequence=req.sequence,
            )
        )

    async def xml_command(
        self,
        command_id: str,
        timeout: float = 5.0,
        **attrs: AttrValue,
    ) -> XmlReply:
        """Issue an XML COMMAND and return the parsed reply.

        Handles reply fragmentation transparently: re-sends the request
        with the FRAG_CONT marker until </COMMAND_REPLY> is observed, up to
        MAX_XML_FRAGMENTS frames (then raises rather than looping forever).

        Raises only SpcError subclasses: SpcTimeout if the panel does not
        reply in `timeout`, SpcConnectionLost if the link drops mid-command,
        SpcProtocolError if the reply never closes / parses.
        """
        assembler = ReplyAssembler()
        first = True
        for _ in range(MAX_XML_FRAGMENTS):
            seq = self._alloc_seq()
            payload = build_request(command_id, continuation=not first, **attrs)
            fut: asyncio.Future[bytes] = asyncio.get_running_loop().create_future()
            self._pending_xml[seq] = fut
            self._send(
                self._frame(
                    major=int(MajorCode.XML_CMD),
                    minor=int(MinorCode.REQUEST),
                    payload=payload,
                    sequence=seq,
                )
            )
            try:
                reply_payload = await asyncio.wait_for(fut, timeout)
            except TimeoutError as exc:
                raise SpcTimeout(f"no XML reply for {command_id!r} within {timeout}s") from exc
            finally:
                self._pending_xml.pop(seq, None)
            try:
                assembled = assembler.feed(reply_payload)
            except ValueError as exc:
                raise SpcProtocolError(
                    f"malformed XML reply fragment for {command_id!r}: {exc}"
                ) from exc
            if assembled is not None:
                try:
                    return parse_reply(assembled)
                except ValueError as exc:
                    raise SpcProtocolError(
                        f"could not parse XML reply for {command_id!r}: {exc}"
                    ) from exc
            first = False
        raise SpcProtocolError(
            f"XML reply for {command_id!r} did not close </COMMAND_REPLY> "
            f"after {MAX_XML_FRAGMENTS} fragments"
        )

    async def binary_command(
        self,
        op: BinaryOp | int,
        target_id: int = 0,
        param: int = 0,
        timeout: float = 5.0,
    ) -> None:
        """Issue a binary command; raise PanelRejected unless the panel replies OK.

        Also raises SpcTimeout / SpcConnectionLost / SpcProtocolError (all
        SpcError subclasses) on timeout, disconnect, or a malformed reply.
        """
        body = BinaryCommand(op, target_id, param).encode()
        await self._major_command(
            major=int(MajorCode.BINARY_CMD),
            body=body,
            label=f"op={op} target={target_id} param={param}",
            timeout=timeout,
        )

    async def panel_command(
        self,
        op: PanelOp | int,
        timeout: float = 5.0,
    ) -> None:
        """Issue a panel-wide command (`major=5`); raise PanelRejected unless OK.

        Used for the panel reset and self-test actions.  The request is a
        1-byte opcode payload and the reply a 1-byte status code, like the
        binary channel.  Also raises SpcTimeout / SpcConnectionLost /
        SpcProtocolError on timeout, disconnect, or a malformed reply.
        """
        await self._major_command(
            major=int(MajorCode.PANEL_CMD),
            body=bytes([int(op) & 0xFF]),
            label=f"panel_op={op}",
            timeout=timeout,
        )

    async def _major_command(
        self,
        *,
        major: int,
        body: bytes,
        label: str,
        timeout: float,
    ) -> None:
        seq = self._alloc_seq()
        fut: asyncio.Future[bytes] = asyncio.get_running_loop().create_future()
        self._pending_bin[seq] = fut
        self._send(
            self._frame(
                major=major,
                minor=int(MinorCode.REQUEST),
                payload=body,
                sequence=seq,
            )
        )
        try:
            reply = await asyncio.wait_for(fut, timeout)
        except TimeoutError as exc:
            raise SpcTimeout(f"no reply within {timeout}s for {label!r}") from exc
        finally:
            self._pending_bin.pop(seq, None)
        if not reply:
            raise SpcProtocolError(f"empty command reply for {label!r}")
        code = reply[0]
        if code != ReplyCode.OK:
            raise PanelRejected(code, command=label)

    def emit_event(self, event: SiaEvent) -> None:
        """Push a SIA event onto the events() stream.

        If the stream's consumer has fallen EVENT_QUEUE_MAXSIZE events
        behind, the oldest event is dropped to make room (and logged).
        """
        try:
            self._events.put_nowait(event)
        except asyncio.QueueFull:
            with contextlib.suppress(asyncio.QueueEmpty):
                self._events.get_nowait()  # drop oldest
            self._events.put_nowait(event)
            log.warning(
                "SIA event queue full (maxsize=%d); dropped oldest event",
                EVENT_QUEUE_MAXSIZE,
            )

    async def events(self) -> AsyncIterator[SiaEvent]:
        """Stream SIA events as they arrive; ends when the session disconnects.

        Once the connection is torn down, any buffered events are drained and
        the iterator stops (rather than blocking forever on an empty queue).

        Cancel-safe: if the consumer's __anext__ is cancelled in the window
        after an event has been dequeued but before it is yielded, the event
        is re-queued (to the front) so it is delivered on the next iteration
        rather than silently lost.
        """
        # A result dequeued from a previous iteration that was not yet yielded
        # (e.g. the yield was cancelled). Delivered first on the next pass.
        pending_event: SiaEvent | None = None
        while True:
            if pending_event is not None:
                event, pending_event = pending_event, None
            else:
                get_task = asyncio.ensure_future(self._events.get())
                closed_task = asyncio.ensure_future(self._closed.wait())
                try:
                    await asyncio.wait({get_task, closed_task}, return_when=asyncio.FIRST_COMPLETED)
                except asyncio.CancelledError:
                    # Cancelled while waiting. If get_task already completed it
                    # has consumed an event; re-queue it so it is not lost.
                    self._requeue_completed_get(get_task)
                    closed_task.cancel()
                    raise
                closed_task.cancel()
                if not get_task.done():
                    # Session closed before an event arrived: cancel the get,
                    # drain anything still queued, then stop.
                    get_task.cancel()
                    while not self._events.empty():
                        yield self._events.get_nowait()
                    return
                event = get_task.result()
            try:
                yield event
            except GeneratorExit:
                # The async generator is being closed (consumer cancelled its
                # __anext__ or stopped iterating). Re-queue the dequeued-but-
                # unyielded event so a subsequent consumer still sees it.
                self._requeue_event(event)
                raise

    def _requeue_completed_get(self, get_task: asyncio.Future[SiaEvent]) -> None:
        """If a cancelled get task already pulled an event, put it back."""
        if get_task.cancel():
            # Successfully cancelled before it produced a result: nothing pulled.
            return
        if get_task.cancelled():
            return
        if get_task.exception() is None:
            self._requeue_event(get_task.result())

    def _requeue_event(self, event: SiaEvent) -> None:
        """Re-insert an event at the front of the queue, dropping the oldest if
        full, so a completed-but-unyielded event is delivered next instead of
        being lost. Best-effort: keeps the safety-critical event in the feed."""
        items: list[SiaEvent] = [event]
        with contextlib.suppress(asyncio.QueueEmpty):
            while True:
                items.append(self._events.get_nowait())
        for item in items:
            try:
                self._events.put_nowait(item)
            except asyncio.QueueFull:
                log.warning(
                    "SIA event queue full re-queuing event (maxsize=%d); dropped oldest",
                    EVENT_QUEUE_MAXSIZE,
                )
                break


class PanelServer:
    """Listen for inbound EDP connections from one or more panels."""

    def __init__(
        self,
        *,
        receiver_id: int,
        bind: str = "0.0.0.0",
        port: int = 50000,
        key: bytes | str | None = None,
        idle_timeout: float | None = DEFAULT_IDLE_TIMEOUT,
        on_event: Callable[[Session, SiaEvent], Coroutine[Any, Any, None]] | None = None,
        on_session: Callable[[Session], Coroutine[Any, Any, None]] | None = None,
    ) -> None:
        """If `key` is provided, the receiver speaks EDP encryption.  Pass
        either 16 raw bytes, or the panel's 32-hex-digit EDP key; it is
        validated now, not mid-session.

        `idle_timeout` (seconds) disconnects a peer that sends nothing for
        that long; pass None to disable.  The panel polls roughly every 10s.
        """
        self.receiver_id = receiver_id
        self.bind = bind
        self.port = port
        self.key = self._normalise_key(key)
        self.idle_timeout = idle_timeout
        self._on_event = on_event
        self._on_session = on_session
        self._server: asyncio.base_events.Server | None = None

    @staticmethod
    def _normalise_key(key: bytes | str | None) -> bytes | None:
        """Validate and normalise the EDP key to 16 raw bytes (or None).

        Distinguishes 'no encryption' (`key is None`) from a provided but
        invalid key (e.g. an empty or wrong-length value), and fails fast at
        construction so a config mistake doesn't surface deep in the loop.
        """
        if key is None:
            return None
        if isinstance(key, str):
            try:
                key = bytes.fromhex(key)
            except ValueError as exc:
                raise ValueError("EDP key string must be 32 hex digits (16 bytes)") from exc
        else:
            key = bytes(key)
        if len(key) != 16:
            raise ValueError(f"EDP key must be 16 bytes, got {len(key)}")
        return key

    async def __aenter__(self) -> PanelServer:
        self._server = await asyncio.start_server(self._handle, self.bind, self.port)
        log.info("listening on %s:%d", self.bind, self.port)
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()

    async def serve_forever(self) -> None:
        assert self._server is not None
        async with self._server:
            await self._server.serve_forever()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        log.info("connection from %s", peer)
        decoder = FrameDecoder(key=self.key)
        session = Session(
            panel_id=0, receiver_id=self.receiver_id, reader=reader, writer=writer, key=self.key
        )
        writer_task = asyncio.create_task(session._writer_loop())
        # If the writer task exits for any reason other than cancellation (the
        # normal teardown path), it is dead and the receiver would go
        # mute-but-alive: tear the session down so the read loop stops too.
        writer_task.add_done_callback(lambda t: self._on_writer_done(t, session, peer))
        session_task: asyncio.Task | None = None
        handshake_started = False
        try:
            while True:
                if session._teardown_requested.is_set():
                    break
                try:
                    chunk = await self._read_chunk(reader, session)
                except TimeoutError:
                    self._log_idle_timeout(peer, handshake_started)
                    break
                if chunk is None:
                    # Teardown was requested (writer died / on_session crashed)
                    # while we were blocked on the socket read.
                    break
                if not chunk:
                    break
                try:
                    frames = decoder.feed(chunk)
                except EncryptionRequired:
                    log.error(
                        "%s is sending encrypted frames but no key is configured; disconnecting",
                        peer,
                    )
                    break
                except FrameDecodeError as exc:
                    # The decoder gave up resyncing (corrupt stream / wrong key).
                    log.error("%s: %s; disconnecting", peer, exc)
                    break
                for frame in frames:
                    if not handshake_started:
                        handshake_started = True
                        session.panel_id = frame.src_id
                    # Keep our seq ahead of the panel's (shared space): reusing
                    # its last seq makes the panel drop the link.
                    session.next_seq = max(session.next_seq, frame.sequence)
                    # ACK before starting on_session, so the panel sees its
                    # HELLO_ACK before any of our commands. One malformed frame
                    # must not kill the read loop (and silence all ACKs), so
                    # dispatch is guarded per-frame.
                    try:
                        self._dispatch(session, frame)
                    except Exception:
                        log.exception("error dispatching %s frame; continuing", frame.kind)
                    if session_task is None and self._on_session is not None:
                        session_task = asyncio.create_task(self._on_session(session))
                        # A crashed on_session is invisible (POLLs keep being
                        # ACKed) until teardown; log it immediately and tear the
                        # session down, mirroring on_event's failure logging.
                        session_task.add_done_callback(
                            lambda t: self._on_session_done(t, session, peer)
                        )
        except ConnectionResetError, BrokenPipeError:
            pass
        finally:
            await self._teardown(session, decoder, writer, (writer_task, session_task), peer)

    async def _read_chunk(self, reader: asyncio.StreamReader, session: Session) -> bytes | None:
        """Read one chunk, racing the idle timeout and a teardown request.

        Returns the bytes read (possibly empty on EOF), or None if a teardown
        was requested (writer died / on_session crashed) while we were blocked
        on the socket so the read loop stops promptly rather than waiting out
        the idle timeout. Raises asyncio.TimeoutError on idle timeout.
        """
        read_task = asyncio.ensure_future(reader.read(4096))
        teardown_task = asyncio.ensure_future(session._teardown_requested.wait())
        try:
            done, _ = await asyncio.wait(
                {read_task, teardown_task},
                timeout=self.idle_timeout,
                return_when=asyncio.FIRST_COMPLETED,
            )
        finally:
            teardown_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await teardown_task
        if read_task in done:
            return read_task.result()
        # The socket read did not complete: either teardown was requested or
        # the idle timeout elapsed. Cancel the in-flight read either way.
        read_task.cancel()
        with contextlib.suppress(asyncio.CancelledError, ConnectionResetError, BrokenPipeError):
            await read_task
        if session._teardown_requested.is_set():
            return None
        raise TimeoutError

    def _on_writer_done(self, task: asyncio.Task, session: Session, peer: object) -> None:
        """Done-callback for the writer task: tear down on unexpected exit."""
        if task.cancelled():
            return  # normal teardown cancelled it
        exc = task.exception()
        if exc is not None:
            log.error("writer task for %s died; tearing session down", peer, exc_info=exc)
        else:
            # The writer loop should only ever exit via cancellation; a clean
            # return means it stopped writing while the session is still up.
            log.error("writer task for %s exited unexpectedly; tearing session down", peer)
        session.request_teardown()

    def _on_session_done(self, task: asyncio.Task, session: Session, peer: object) -> None:
        """Done-callback for on_session: log a crash immediately and tear down."""
        if task.cancelled():
            return  # normal teardown cancelled it
        exc = task.exception()
        if exc is not None:
            log.error("on_session callback for %s raised; tearing session down", peer, exc_info=exc)
            session.request_teardown()

    def _log_idle_timeout(self, peer: object, handshake_started: bool) -> None:
        if self.key is not None and not handshake_started:
            log.warning("idle timeout on %s with no decodable frames; wrong encryption key?", peer)
        else:
            log.warning("idle timeout (%ss) on %s; disconnecting", self.idle_timeout, peer)

    async def _teardown(
        self,
        session: Session,
        decoder: FrameDecoder,
        writer: asyncio.StreamWriter,
        tasks: tuple[asyncio.Task | None, ...],
        peer: object,
    ) -> None:
        log.info("connection closed: %s", peer)
        if decoder._buf:
            log.debug("discarding %d residual buffered bytes at EOF", len(decoder._buf))
        # Fail in-flight futures and wake events() consumers, so callers don't
        # block until their own timeout. Use SpcConnectionLost so awaiting
        # callers see a typed SDK error rather than a raw socket exception.
        session.fail_pending(SpcConnectionLost("panel disconnected"))
        session._closed.set()
        session._teardown_requested.set()
        # Cancel and await background tasks before closing the socket.
        pending = [t for t in (*tasks, *session._tasks) if t is not None]
        for t in pending:
            t.cancel()
        for t in pending:
            try:
                await t
            except asyncio.CancelledError:
                pass
            except Exception:
                log.exception("background task failed during teardown")
        # Flush frames queued but not yet written (the writer task is stopped now).
        with contextlib.suppress(Exception):
            while not session._write_queue.empty():
                writer.write(session._write_queue.get_nowait())
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()

    def _dispatch(self, sess: Session, frame: Frame) -> None:
        # Replies to our outstanding requests first.
        if frame.major == MajorCode.XML_CMD and frame.minor == MinorCode.REPLY:
            fut = sess._pending_xml.pop(frame.sequence, None)
            if fut is not None and not fut.done():
                fut.set_result(frame.payload)
            return
        if (frame.major == MajorCode.BINARY_CMD and frame.minor == MinorCode.BINARY_REPLY) or (
            frame.major == MajorCode.PANEL_CMD and frame.minor == MinorCode.PANEL_REPLY
        ):
            fut = sess._pending_bin.pop(frame.sequence, None)
            if fut is not None and not fut.done():
                fut.set_result(frame.payload)
            return

        # Panel-initiated frames - acknowledge and surface events.
        if frame.major == MajorCode.SESSION:
            if frame.minor == MinorCode.POLL:
                sess.reply_echo(frame, int(MinorCode.POLL_ACK))
                sess._poll_count += 1
                sess._ready.set()
            elif frame.minor == MinorCode.HELLO:
                sess.reply_echo(frame, int(MinorCode.HELLO_ACK))
            return
        if frame.major == MajorCode.EVENT and frame.minor == MinorCode.EVENT_PUSH:
            sess.reply_echo(frame, int(MinorCode.EVENT_ACK))
            try:
                event = SiaEvent.parse(frame.payload)
            except ValueError:
                log.warning("unparseable SIA payload: %r", frame.payload)
                return
            sess.emit_event(event)
            if self._on_event is not None:
                # Retain the task (the loop only weakly refs running tasks);
                # _run_event_callback logs any failure.
                task = asyncio.create_task(self._run_event_callback(sess, event))
                sess._tasks.add(task)
                task.add_done_callback(sess._tasks.discard)
            return

        log.debug("unhandled %s payload=%r", frame.kind, frame.payload[:40])

    async def _run_event_callback(self, sess: Session, event: SiaEvent) -> None:
        assert self._on_event is not None
        try:
            await self._on_event(sess, event)
        except Exception:
            log.exception("on_event callback raised")
