"""EDP v2 wire format.

Reverse-engineered (black-box) from live captures against an SPC4300
panel. All multi-byte integers are little-endian.

Frame layout (23-byte header + variable payload):

    offset  size  field
     0-1    2     remaining-length      total bytes = 2 + this
     2      1     protocol byte         constant 0x45 ('E')
     3      1     version               0x02
     4      1     source flag           0x00 if src is panel, 0x08 if receiver
     5-8    4     sequence number       request and reply share the same seq
     9-12   4     source ID
    13-16   4     destination ID
    17      1     major code
    18      1     minor code
    19-20   2     checksum              not validated by the panel
    21-22   2     payload length
    23..   var    payload

Two command families seen on the wire:

  major=10 ("XML")    request payload `\\x01<COMMAND ID="..." />`
                      reply payload   `\\x01<COMMAND_REPLY>...</COMMAND_REPLY>`
                      large replies are fragmented; the first chunk is tagged
                      with 0x01 ("first") and subsequent chunks 0x02
                      ("continuation"). To pull continuations the requester
                      re-sends the same XML command prefixed with 0x02.

  major=4 ("binary")  request payload `<opcode> <target_id> <param>`
                      reply payload   1 byte status code (0xF0 = OK, 0xFC = nyi)
"""

from __future__ import annotations

import enum
import logging
import struct
from dataclasses import dataclass

log = logging.getLogger("spcedp")

PROTOCOL_BYTE = 0x45  # 'E'
PROTOCOL_VERSION = 0x02
HEADER_LEN = 23
MAX_FRAME_LEN = 0xFFFF  # length prefix and dlen are both 16-bit
# Largest frame we will wait to complete. Real EDP frames are small: session
# POLLs are tiny, binary commands a few bytes, and large XML replies fragment
# on the wire at ~1.4KB chunks. 16384 is far above any genuine frame yet well
# below MAX_FRAME_LEN, so a valid-magic header claiming more than this is
# treated as not-looks-valid and resynced immediately rather than waited on.
MAX_PLAUSIBLE_FRAME = 16384
# Bound the byte-by-byte resync so a wrong key or corrupt stream fails fast
# rather than dropping bytes forever; set well above any real frame size.
RESYNC_LIMIT = 8192

# Bits in the flags byte (wire offset 4).
FLAG_ENCRYPTED = 0x01
FLAG_FROM_RECEIVER = 0x08

ENCRYPT_OFFSET_IN_WIRE = 17  # encrypted region begins here (struct offset 15)
AES_BLOCK_SIZE = 16


class FrameDecodeError(ValueError):
    """A frame could not be decoded.

    Recoverable: the stream decoder logs and resyncs past the offending
    bytes rather than tearing the connection down.  Subclasses ValueError
    so callers expecting the historical ValueError contract still catch it.
    """


class EncryptionRequired(FrameDecodeError):
    """The frame is encrypted but the decoder has no key configured.

    Unlike other decode failures this is *not* recoverable by resyncing:
    every subsequent frame on the stream will also be encrypted, so the
    decoder re-raises this to let the session tear down instead of
    spinning byte-by-byte through the whole buffer.
    """


# EDP frame checksum parameters (reverse-engineered; see PROTOCOL.md §2.5
# for the algorithm).
_CSUM_INIT = 0xFFFF
_CSUM_POLY = 0xA097
_CSUM_OFFSET_LOW = 0x11
_CSUM_OFFSET_HIGH = 0x12


def edp_checksum(struct_bytes: bytes, dlen: int) -> int:
    """Compute the EDP v2 frame checksum.

    `struct_bytes` is the in-memory frame struct (== wire bytes after
    stripping the 2-byte length prefix); `dlen` is the payload length
    field.  Returns the 16-bit value that goes at struct offsets
    0x11-0x12 (little-endian on the wire).

    The algorithm is a 16-bit linear-shift register where each input
    byte is *added* (not XORed) into the low half of the state, with a
    conditional XOR by poly 0xA097 when the high bit of the previous
    state shifts out.  The two bytes of the checksum slot itself are
    skipped during iteration.
    """
    end = dlen + 0x15
    if len(struct_bytes) < end:
        raise ValueError(f"struct_bytes too short: have {len(struct_bytes)}, need {end}")
    low = _CSUM_INIT & 0xFF
    high = (_CSUM_INIT >> 8) & 0xFF
    poly_low = _CSUM_POLY & 0xFF
    poly_high = (_CSUM_POLY >> 8) & 0xFF
    for i in range(end):
        if i in (_CSUM_OFFSET_LOW, _CSUM_OFFSET_HIGH):
            continue
        carry = high & 0x80
        state = (((high << 8) | low) << 1) & 0xFFFF
        # Parens are load-bearing: the byte-add is masked to 8 bits and must
        # not carry into the high half.
        low = ((state & 0xFF) + struct_bytes[i]) & 0xFF
        high = (state >> 8) & 0xFF
        if carry:
            low ^= poly_low
            high ^= poly_high
    return (high << 8) | low


class MajorCode(enum.IntEnum):
    SESSION = 1  # POLL / HELLO
    EVENT = 2  # SIA event push from panel
    BINARY_CMD = 4  # 3-byte (op,target,param) or 1-byte (op) writes
    PANEL_CMD = 5  # panel-wide commands (reset, test); 1-byte payload
    XML_CMD = 10  # <COMMAND ID="..." /> XML


class MinorCode(enum.IntEnum):
    # session (major=1)
    POLL = 0
    POLL_ACK = 1
    HELLO = 2
    HELLO_ACK = 3
    # event (major=2)
    EVENT_PUSH = 0
    EVENT_ACK = 1
    # commands (major=4 or 10)
    REQUEST = 0
    REPLY = 1
    BINARY_REPLY = 2  # major=4 replies
    PANEL_REPLY = 1  # major=5 replies; alias of REPLY, named for the dispatch site


@dataclass(slots=True)
class Frame:
    """One EDP frame, decoded."""

    src_id: int
    dst_id: int
    sequence: int
    major: int
    minor: int
    payload: bytes = b""
    checksum: int = 0
    src_flag: int = 0  # 0x00 from panel, 0x08 from the receiver (us)

    def encode(self, key: bytes | None = None) -> bytes:
        """Serialize to wire bytes; computes and inserts the checksum.

        If `key` is supplied (16 bytes), AES-128-ECB encrypts struct
        offsets 15+ (maj/min/csum/dlen/payload) and sets the encrypted
        flag bit.  Otherwise the frame is sent in cleartext.
        """
        src_flag = self.src_flag
        if key is not None:
            src_flag |= FLAG_ENCRYPTED
        # The payload length goes into a 16-bit ('H') field; bounds-check it
        # here so an oversized payload raises a typed ValueError with a clear
        # message instead of a raw struct.error from struct.pack below.
        if len(self.payload) > MAX_FRAME_LEN:
            raise ValueError(
                f"EDP payload too large: {len(self.payload)} bytes; "
                f"max payload length is {MAX_FRAME_LEN} (16-bit dlen field)"
            )
        body = struct.pack(
            "<BBBIIIBBHH",
            PROTOCOL_BYTE,
            PROTOCOL_VERSION,
            src_flag,
            self.sequence & 0xFFFFFFFF,
            self.src_id & 0xFFFFFFFF,
            self.dst_id & 0xFFFFFFFF,
            self.major & 0xFF,
            self.minor & 0xFF,
            0,  # checksum placeholder
            len(self.payload),
        )
        struct_bytes = body + self.payload
        self.checksum = edp_checksum(struct_bytes, len(self.payload))
        struct_bytes = (
            struct_bytes[:_CSUM_OFFSET_LOW]
            + struct.pack("<H", self.checksum)
            + struct_bytes[_CSUM_OFFSET_HIGH + 1 :]
        )
        if key is not None:
            struct_bytes = _encrypt_payload(struct_bytes, key)
        rem = len(struct_bytes)
        # Validate the final rem (covers payload + any encryption padding) for a
        # typed error rather than a struct.error. rem is the remaining-length
        # field; total wire bytes = rem + 2 (the length prefix itself).
        if rem > MAX_FRAME_LEN:
            raise ValueError(
                f"EDP frame too large: {rem} bytes (payload {len(self.payload)}B); "
                f"max frame body is {MAX_FRAME_LEN}"
            )
        return struct.pack("<H", rem) + struct_bytes

    @classmethod
    def decode(cls, buf: bytes, key: bytes | None = None) -> Frame:
        if len(buf) < HEADER_LEN:
            raise FrameDecodeError(f"buffer too short for EDP header: {len(buf)}B")
        rem = struct.unpack_from("<H", buf, 0)[0]
        total = rem + 2
        if len(buf) < total:
            raise FrameDecodeError(f"buffer truncated: have {len(buf)}B, frame says {total}B")
        if buf[2] != PROTOCOL_BYTE or buf[3] != PROTOCOL_VERSION:
            raise FrameDecodeError(f"bad EDP magic: proto={buf[2]:#x} ver={buf[3]:#x}")
        src_flag = buf[4]
        encrypted = bool(src_flag & FLAG_ENCRYPTED)
        if encrypted:
            if key is None:
                raise EncryptionRequired("frame is encrypted but no key was supplied")
            buf = _decrypt_in_buf(bytes(buf[:total]), key)
            # total is unchanged (the length prefix is cleartext); dlen below
            # excludes the zero padding, so the payload slice stays correct.
        seq, src, dst = struct.unpack_from("<III", buf, 5)
        maj = buf[17]
        mn = buf[18]
        csum, dlen = struct.unpack_from("<HH", buf, 19)
        # Reject a dlen past the frame bounds instead of silently truncating;
        # on the encrypted path a wrong key produces a garbage dlen here.
        if HEADER_LEN + dlen > total:
            raise FrameDecodeError(f"payload length {dlen} overflows frame ({total}B total)")
        if encrypted:
            # ECB has no MAC, but the checksum sits inside the encrypted region,
            # so a wrong key or corruption is caught here. encode() computes it
            # with FLAG_ENCRYPTED set and _decrypt_in_buf clears the bit, so
            # restore it before recomputing.
            struct_for_csum = bytearray(buf[2:total])
            struct_for_csum[2] |= FLAG_ENCRYPTED
            if edp_checksum(bytes(struct_for_csum), dlen) != csum:
                raise FrameDecodeError(
                    "checksum mismatch after decrypt - wrong key or corrupt frame"
                )
        else:
            # Cleartext path: validate the checksum too, so garbage that merely
            # carries valid magic does not decode into a phantom frame. The
            # struct bytes are the wire bytes minus the 2-byte length prefix; no
            # FLAG_ENCRYPTED restore is needed since the bit is already clear.
            if edp_checksum(bytes(buf[2:total]), dlen) != csum:
                raise FrameDecodeError("checksum mismatch - corrupt frame")
        payload = buf[HEADER_LEN : HEADER_LEN + dlen]
        return cls(
            src_id=src,
            dst_id=dst,
            sequence=seq,
            major=maj,
            minor=mn,
            payload=payload,
            checksum=csum,
            src_flag=src_flag & ~FLAG_ENCRYPTED,
        )

    @property
    def kind(self) -> str:
        try:
            return f"{MajorCode(self.major).name}.{self.minor}"
        except ValueError:
            return f"maj={self.major} min={self.minor}"

    def __repr__(self) -> str:  # pragma: no cover - convenience
        return (
            f"Frame(seq=0x{self.sequence:08x} {self.src_id}->{self.dst_id} "
            f"{self.kind} dlen={len(self.payload)})"
        )


def _encrypt_payload(struct_bytes: bytes, key: bytes) -> bytes:
    """Encrypt struct offsets 15+ in place per the EDP wire format (§2.7).

    Cleartext bytes 0-14 (pid/ver/flags/seq/src/dst) are preserved.
    Bytes 15+ are zero-padded to the next 16-byte multiple and replaced
    with AES-128-ECB ciphertext.  The returned buffer is the new struct
    (no length prefix); the caller must update the prefix.
    """
    if len(key) != 16:
        raise ValueError(f"EDP key must be 16 bytes, got {len(key)}")
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    head = struct_bytes[:15]
    tail = struct_bytes[15:]
    pad_len = (-len(tail)) % AES_BLOCK_SIZE
    tail_padded = tail + b"\x00" * pad_len
    cipher = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    ct = cipher.update(tail_padded) + cipher.finalize()
    return head + ct


def _decrypt_in_buf(buf: bytes, key: bytes) -> bytes:
    """Decrypt the encrypted tail (struct offsets 15+) of an EDP frame.

    Input is the full wire frame (with the 2-byte length prefix).
    Output is the same buffer with the tail replaced by plaintext.
    """
    if len(key) != 16:
        raise ValueError(f"EDP key must be 16 bytes, got {len(key)}")
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    head = buf[:ENCRYPT_OFFSET_IN_WIRE]
    tail = buf[ENCRYPT_OFFSET_IN_WIRE:]
    if len(tail) % AES_BLOCK_SIZE != 0:
        raise FrameDecodeError(
            f"encrypted tail length {len(tail)} is not a multiple of {AES_BLOCK_SIZE}"
        )
    cipher = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    pt = cipher.update(tail) + cipher.finalize()
    # Clear the encrypt bit so the rest of the decoder sees a cleartext frame.
    out = bytearray(head + pt)
    out[4] &= ~FLAG_ENCRYPTED
    return bytes(out)


class FrameDecoder:
    """Stateful TCP byte stream splitter.

    EDP doesn't map 1:1 onto TCP segments; frames can be split across
    reads, multiple frames can arrive in one read, and the panel
    sometimes sends the 2-byte length prefix on its own.  Feed bytes
    in, get whole frames out.
    """

    def __init__(self, key: bytes | None = None) -> None:
        self._buf = bytearray()
        self._key = key
        self._dropped = 0  # bytes dropped since the last good frame (resync budget)
        # Bound the wait for a valid-looking header to complete. A genuine
        # header that claims `total` bytes but never receives them would
        # otherwise wedge feed() forever with _dropped stuck at 0 (so
        # RESYNC_LIMIT never fires). We anchor on the claimed total when we
        # first start waiting and count bytes accumulated since; if the wait
        # exceeds RESYNC_LIMIT without completing, we resync past the prefix.
        self._wait_total: int | None = None  # claimed total we are waiting on
        self._wait_start_len = 0  # len(self._buf) when the wait began

    def feed(self, data: bytes) -> list[Frame]:
        self._buf.extend(data)
        out: list[Frame] = []
        while True:
            if len(self._buf) < HEADER_LEN:
                return out
            rem = struct.unpack_from("<H", self._buf, 0)[0]
            total = rem + 2
            looks_valid = (
                # Compare rem (not total) against MAX_FRAME_LEN to match
                # encode()'s bound; total = rem + 2. Reject any header whose
                # claimed frame is larger than the largest plausible real EDP
                # frame so a phantom large length-prefix resyncs immediately
                # instead of wedging the decoder while it waits for bytes that
                # will never arrive (MAX_PLAUSIBLE_FRAME <= MAX_FRAME_LEN).
                HEADER_LEN <= total <= MAX_PLAUSIBLE_FRAME
                and rem <= MAX_FRAME_LEN
                and self._buf[2] == PROTOCOL_BYTE
                and self._buf[3] == PROTOCOL_VERSION
            )
            if not looks_valid:
                self._reset_wait()
                self._resync()
                continue
            if len(self._buf) < total:
                # A plausible header that has not yet completed. Bound the wait
                # so a stalled or phantom prefix cannot wedge us forever: anchor
                # on the claimed total and count bytes accumulated since the
                # wait began. Reset the anchor if the claimed total changes
                # (e.g. resync exposed a different header).
                if self._wait_total != total:
                    self._wait_total = total
                    self._wait_start_len = len(self._buf)
                if len(self._buf) - self._wait_start_len > RESYNC_LIMIT:
                    log.warning(
                        "incomplete frame after %d bytes (claimed %d, have %d); "
                        "resyncing past suspect prefix",
                        len(self._buf) - self._wait_start_len,
                        total,
                        len(self._buf),
                    )
                    self._reset_wait()
                    self._resync()
                    continue
                return out
            # The frame is fully buffered; we are no longer waiting on it.
            self._reset_wait()
            try:
                frame = Frame.decode(bytes(self._buf[:total]), key=self._key)
            except EncryptionRequired:
                # Every following frame is encrypted too; let the session tear
                # down rather than resync byte-by-byte forever.
                raise
            except FrameDecodeError as exc:
                # Looked like a frame but didn't decode; resync, don't disconnect.
                log.warning("dropping undecodable frame, resyncing: %s", exc)
                self._resync()
                continue
            del self._buf[:total]
            self._dropped = 0  # whole frame decoded: reset the resync budget
            out.append(frame)

    def _reset_wait(self) -> None:
        """Clear the incomplete-frame wait anchor (the header we were waiting to
        complete is gone: decoded, dropped, or about to be resynced past)."""
        self._wait_total = None
        self._wait_start_len = 0

    def _resync(self) -> None:
        """Drop one byte to hunt for the next frame boundary, bounded so a
        corrupt stream or wrong encryption key fails fast with a clear error
        instead of silently spinning to an idle timeout.

        Resync drops a single byte (not a whole header) on purpose: a phantom
        length-prefix is often immediately followed by a real frame, so byte-by-
        byte re-alignment finds that frame instead of swallowing it."""
        del self._buf[:1]
        self._dropped += 1
        if self._dropped > RESYNC_LIMIT:
            raise FrameDecodeError(
                f"gave up resyncing after dropping {self._dropped} bytes "
                "(corrupt stream or wrong encryption key?)"
            )
