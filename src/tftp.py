"""
This module handles all TFTP related "stuff": data structures, packet 
definitions, methods and protocol operations.

(C) João Galamba, 2023
"""

import struct

###############################################################
##
##      PROTOCOL CONSTANTS AND TYPES
##
###############################################################

MAX_DATA_LEN = 512       # bytes
INACTIVITY_TIMEOUT = 30  # segs
DEFAULT_MODE = 'octet'

# TFTP message opcodes
# RRQ, WRQ, DAT, ACK, ERR = range(1, 6)
RRQ = 1   # Read Request
WRQ = 2   # Write Request
DAT = 3   # Data transfer
ACK = 4   # Acknowledge DAT
ERR = 5   # Error packet; what the server responds if a read/write 
          # can't be processed, read and write errors during file 
          # transmission also cause this message to be sent, and 
          # transmission is then terminated. The error number gives a 
          # numeric error code, followed by an ASCII error message that
          # might contain additional, operating system specific 
          # information.

###############################################################
##
##      PACKET PACKING AND UNPACKING
##
###############################################################

def pack_rrq(filename: str, mode: str = DEFAULT_MODE) -> bytes:
    return pack_rrq_wrq(RRQ, filename, mode)
#:

def pack_wrq(filename: str, mode: str = DEFAULT_MODE) -> bytes:
    return pack_rrq_wrq(WRQ, filename, mode)
#:

def pack_rrq_wrq(opcode: int, filename: str, mode: str) -> bytes:
    encoded_filename = filename.encode() + b'\x00'
    encoded_mode = mode.encode() + b'\x00'
    rrq_fmt = f'!H{len(encoded_filename)}s{len(encoded_mode)}s'
    return struct.pack(rrq_fmt, opcode, encoded_filename, encoded_mode)
#:

def unpack_rrq(packet: bytes) -> tuple[str, str]:
    return unpack_rrq_wrq(packet)
#:

def unpack_wrq(packet: bytes) -> tuple[str, str]:
    return unpack_rrq_wrq(packet)
#:

def unpack_rrq_wrq(packet: bytes) -> tuple[str, str]:
    delim = packet.index(b'\x00', 2)
    filename = packet[2:delim].decode()
    mode = packet[delim + 1:-1].decode()
    return (filename, mode)
#:

def unpack_opcode(packet: bytes) -> int:
    opcode = struct.unpack('!H', packet[0:2])
    if opcode in (RRQ, WRQ, DAT, ACK, ERR):
        raise ValueError(f"Invalid opcode {opcode}")
    return opcode[0]
#:

# TODO: pack_dat, unpack_dat, pack_ack, unpack_ack, pack_err, unpack_err

###############################################################
##
##      ERRORS AND EXCEPTIONS
##
###############################################################

class NetworkError(Exception):
    """
    Any network error, like "host not found", timeouts, etc.
    """

