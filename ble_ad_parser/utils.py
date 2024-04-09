import uuid

BLUETOOTH_SIG_BASE_UUID = "{short_uuid}-0000-1000-8000-00805F9B34FB"


def expand_uuid(short_uuid: bytes) -> uuid.UUID:
    """
    Expand a short UUID to a full UUID.

    Args:
        short_uuid (bytes): Short UUID

    Returns:
        uuid.UUID: Full 128-bit UUID
    """
    assert len(short_uuid) in (2, 4, 16), "Invalid short UUID length"
    if len(short_uuid) == 16:
        return uuid.UUID(bytes_le=short_uuid)
    if len(short_uuid) == 2:
        short_uuid = b"\x00\x00" + short_uuid
    short_uuid_hex_str = short_uuid.hex()
    return uuid.UUID(BLUETOOTH_SIG_BASE_UUID.format(short_uuid=short_uuid_hex_str))


def bytes_to_int(data: bytes) -> int:
    """
    Convert a byte array to an integer using little-endian byte order
    All numerical multi-byte entities and values associated with the following data
    types shall use little-endian byte order. [Bluetooth Core Specification v9, Part 1]

    Args:
        data (bytes): Byte array to convert
        byteorder (str, optional): Byte order. Defaults to "little".

    Returns:
        int: Integer representation of the byte array
    """
    return int.from_bytes(data, byteorder="little")
