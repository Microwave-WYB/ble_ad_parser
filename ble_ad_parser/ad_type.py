"""
This module contains classes for parsing AD types
"""

from dataclasses import dataclass
from typing import Dict, List, Literal, Type
from uuid import UUID


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


@dataclass
class ADTypeData:
    """Base class for AD types"""

    @classmethod
    def from_bytes(cls, data: bytes) -> "ADTypeData":
        """
        Create an ADType object from a byte array

        Args:
            data (bytes): Byte array containing the AD type data

        Returns:
            ADType: AD type object
        """
        raise NotImplementedError("This method must be implemented in the derived class")


@dataclass
class Flags(ADTypeData):
    """AD type 0x01 (Flags)"""

    le_limited_discoverable: bool
    le_general_discoverable: bool
    br_edr_not_supported: bool
    le_br_edr_controller: bool
    le_br_edr_host: bool

    @classmethod
    def from_bytes(cls, data: bytes) -> "Flags":
        assert len(data) == 1, "Flags data must be 1 byte long"
        data_int = bytes_to_int(data)
        return cls(
            le_limited_discoverable=bool(data_int & 0b00000001),
            le_general_discoverable=bool(data_int & 0b00000010),
            br_edr_not_supported=bool(data_int & 0b00000100),
            le_br_edr_controller=bool(data_int & 0b00001000),
            le_br_edr_host=bool(data_int & 0b00010000),
        )


@dataclass
class ServiceUUIDs(ADTypeData):
    """
    Class for AD types 0x02-0x07, 0x14, 0x15 (Service UUIDs)
    """

    uuids: List[int] | List[UUID]
    complete: bool
    solicitation: bool
    bit_length: Literal[16, 32, 128]

    @staticmethod
    def validate(data, bit_length):
        """
        Validate the length of the service UUID data
        """
        assert (
            len(data) % (bit_length // 8) == 0
        ), f"Service UUID data must be a multiple of {bit_length // 8} bytes long"

    @classmethod
    def from_bytes(cls, data: bytes) -> ADTypeData:
        raise NotImplementedError("This method must be implemented in the derived class")


@dataclass
class IncompleteUUID16(ServiceUUIDs):
    """AD type 0x02 (Incomplete List of 16-bit Service Class UUIDs)"""

    @classmethod
    def from_bytes(cls, data: bytes) -> "IncompleteUUID16":
        cls.validate(data, 16)
        uuids = [bytes_to_int(data[i : i + 2]) for i in range(0, len(data), 2)]
        return cls(uuids=uuids, complete=False, solicitation=False, bit_length=16)


@dataclass
class CompleteUUID16(ServiceUUIDs):
    """AD type 0x03 (Complete List of 16-bit Service Class UUIDs)"""

    @classmethod
    def from_bytes(cls, data: bytes) -> "CompleteUUID16":
        cls.validate(data, 16)
        uuids = [bytes_to_int(data[i : i + 2]) for i in range(0, len(data), 2)]
        return cls(uuids=uuids, complete=True, solicitation=False, bit_length=16)


@dataclass
class IncompleteUUID32(ServiceUUIDs):
    """AD type 0x04 (Incomplete List of 32-bit Service Class UUIDs)"""

    @classmethod
    def from_bytes(cls, data: bytes) -> "IncompleteUUID32":
        cls.validate(data, 32)
        uuids = [bytes_to_int(data[i : i + 4]) for i in range(0, len(data), 4)]
        return cls(uuids=uuids, complete=False, solicitation=False, bit_length=32)


@dataclass
class CompleteUUID32(ServiceUUIDs):
    """AD type 0x05 (Complete List of 32-bit Service Class UUIDs)"""

    @classmethod
    def from_bytes(cls, data: bytes) -> "CompleteUUID32":
        cls.validate(data, 32)
        uuids = [bytes_to_int(data[i : i + 4]) for i in range(0, len(data), 4)]
        return cls(uuids=uuids, complete=True, solicitation=False, bit_length=32)


@dataclass
class IncompleteUUID128(ServiceUUIDs):
    """AD type 0x06 (Incomplete List of 128-bit Service Class UUIDs)"""

    @classmethod
    def from_bytes(cls, data: bytes) -> "IncompleteUUID128":
        cls.validate(data, 128)
        uuids = [UUID(bytes_le=data[i : i + 16]) for i in range(0, len(data), 16)]
        return cls(uuids=uuids, complete=False, solicitation=False, bit_length=128)


@dataclass
class CompleteUUID128(ServiceUUIDs):
    """AD type 0x07 (Complete List of 128-bit Service Class UUIDs)"""

    @classmethod
    def from_bytes(cls, data: bytes) -> "CompleteUUID128":
        cls.validate(data, 128)
        uuids = [UUID(bytes_le=data[i : i + 16]) for i in range(0, len(data), 16)]
        return cls(uuids=uuids, complete=True, solicitation=False, bit_length=128)


@dataclass
class ShortenedLocalName(ADTypeData):
    """AD type 0x08 (Shortened Local Name)"""

    name: str

    @classmethod
    def from_bytes(cls, data: bytes) -> "ShortenedLocalName":
        return cls(name=data.decode("utf-8"))


@dataclass
class CompleteLocalName(ADTypeData):
    """AD type 0x09 (Complete Local Name)"""

    name: str

    @classmethod
    def from_bytes(cls, data: bytes) -> "CompleteLocalName":
        return cls(name=data.decode("utf-8"))


@dataclass
class TxPowerLevel(ADTypeData):
    """AD type 0x0A (Tx Power Level)"""

    power_level: int

    @classmethod
    def from_bytes(cls, data: bytes) -> "TxPowerLevel":
        assert len(data) == 1, "Tx Power Level data must be 1 byte long"
        return cls(power_level=bytes_to_int(data))


@dataclass
class ClassOfDevice(ADTypeData):
    """AD type 0x0D (Class of Device)"""

    class_of_device: int

    @classmethod
    def from_bytes(cls, data: bytes) -> "ClassOfDevice":
        assert len(data) == 3, "Class of Device data must be 3 bytes long"
        return cls(class_of_device=bytes_to_int(data))


@dataclass
class SimplePairingHashC(ADTypeData):
    """AD type 0x0E (Simple Pairing Hash C)"""

    hash_c: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> "SimplePairingHashC":
        return cls(hash_c=data)


@dataclass
class SimplePairingRandomizerR(ADTypeData):
    """AD type 0x0F (Simple Pairing Randomizer R)"""

    randomizer_r: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> "SimplePairingRandomizerR":
        return cls(randomizer_r=data)


@dataclass
class DeviceID(ADTypeData):
    """AD type 0x10 (Device ID)"""

    device_id: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> "DeviceID":
        return cls(device_id=data)


@dataclass
class SecurityManagerTKValue(ADTypeData):
    """AD type 0x10 (Security Manager TK Value)"""

    tk_value: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> "SecurityManagerTKValue":
        return cls(tk_value=data)


@dataclass
class SecurityManagerOOBFlags(ADTypeData):
    """AD type 0x11 (Security Manager OOB Flags)"""

    oob_flags: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> "SecurityManagerOOBFlags":
        return cls(oob_flags=data)


@dataclass
class PeripheralConnectionIntervalRange(ADTypeData):
    """AD type 0x12 (Peripheral Connection Interval Range)"""

    min_interval: int
    max_interval: int

    @classmethod
    def from_bytes(cls, data: bytes) -> "PeripheralConnectionIntervalRange":
        assert len(data) == 4, "Peripheral Connection Interval Range data must be 4 bytes long"
        min_interval = bytes_to_int(data[:2])
        max_interval = bytes_to_int(data[2:])
        return cls(min_interval=min_interval, max_interval=max_interval)


@dataclass
class SolicitationUUID16(ServiceUUIDs):
    """AD type 0x14 (List of 16-bit Service Solicitation UUIDs)"""

    @classmethod
    def from_bytes(cls, data: bytes) -> "SolicitationUUID16":
        cls.validate(data, 16)
        uuids = [bytes_to_int(data[i : i + 2]) for i in range(0, len(data), 2)]
        return cls(uuids=uuids, complete=False, solicitation=True, bit_length=16)


@dataclass
class SolicitationUUID128(ServiceUUIDs):
    """AD type 0x15 (List of 128-bit Service Solicitation UUIDs)"""

    @classmethod
    def from_bytes(cls, data: bytes) -> "SolicitationUUID128":
        cls.validate(data, 128)
        uuids = [UUID(bytes_le=data[i : i + 16]) for i in range(0, len(data), 16)]
        return cls(uuids=uuids, complete=False, solicitation=True, bit_length=128)


@dataclass
class ServiceDataUUID16(ADTypeData):
    """AD type 0x16 (Service Data - 16-bit UUID)"""

    uuid: int
    data: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> "ServiceDataUUID16":
        assert len(data) >= 2, "Service Data - 16-bit UUID data must be at least 2 bytes long"
        uuid = bytes_to_int(data[:2])
        data = data[2:]
        return cls(uuid=uuid, data=data)


@dataclass
class PublicTargetAddress(ADTypeData):
    """AD type 0x17 (Public Target Address)"""

    target_address: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> "PublicTargetAddress":
        return cls(target_address=data)


@dataclass
class RandomTargetAddress(ADTypeData):
    """AD type 0x18 (Random Target Address)"""

    target_address: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> "RandomTargetAddress":
        return cls(target_address=data)


@dataclass
class Appearance(ADTypeData):
    """AD type 0x19 (Appearance)"""

    appearance: int

    @classmethod
    def from_bytes(cls, data: bytes) -> "Appearance":
        assert len(data) == 2, "Appearance data must be 2 bytes long"
        return cls(appearance=bytes_to_int(data))


@dataclass
class AdvertisingInterval(ADTypeData):
    """AD type 0x1A (Advertising Interval)"""

    interval: int

    @classmethod
    def from_bytes(cls, data: bytes) -> "AdvertisingInterval":
        assert len(data) == 2, "Advertising Interval data must be 2 bytes long"
        return cls(interval=bytes_to_int(data))


@dataclass
class LEBluetoothDeviceAddress(ADTypeData):
    """AD type 0x1B (LE Bluetooth Device Address)"""

    address: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> "LEBluetoothDeviceAddress":
        return cls(address=data)


@dataclass
class LERole(ADTypeData):
    """AD type 0x1C (LE Role)"""

    role: int

    @classmethod
    def from_bytes(cls, data: bytes) -> "LERole":
        assert len(data) == 1, "LE Role data must be 1 byte long"
        return cls(role=bytes_to_int(data))


@dataclass
class SimplePairingHashC256(ADTypeData):
    """AD type 0x1D (Simple Pairing Hash C-256)"""

    hash_c: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> "SimplePairingHashC256":
        return cls(hash_c=data)


@dataclass
class SimplePairingRandomizerR256(ADTypeData):
    """AD type 0x1E (Simple Pairing Randomizer R-256)"""

    randomizer_r: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> "SimplePairingRandomizerR256":
        return cls(randomizer_r=data)


@dataclass
class ServiceDataUUID32(ADTypeData):
    """AD type 0x20 (Service Data - 32-bit UUID)"""

    uuid: int
    data: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> "ServiceDataUUID32":
        assert len(data) >= 4, "Service Data - 32-bit UUID data must be at least 4 bytes long"
        uuid = bytes_to_int(data[:4])
        data = data[4:]
        return cls(uuid=uuid, data=data)


@dataclass
class ServiceDataUUID128(ADTypeData):
    """AD type 0x21 (Service Data - 128-bit UUID)"""

    uuid: UUID
    data: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> "ServiceDataUUID128":
        assert len(data) >= 16, "Service Data - 128-bit UUID data must be at least 16 bytes long"
        uuid = UUID(bytes_le=data[:16])
        data = data[16:]
        return cls(uuid=uuid, data=data)


@dataclass
class LESecureConnectionsConfirmationValue(ADTypeData):
    """AD type 0x22 (LE Secure Connections Confirmation Value)"""

    confirmation_value: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> "LESecureConnectionsConfirmationValue":
        return cls(confirmation_value=data)


@dataclass
class LESecureConnectionsRandomValue(ADTypeData):
    """AD type 0x23 (LE Secure Connections Random Value)"""

    random_value: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> "LESecureConnectionsRandomValue":
        return cls(random_value=data)


@dataclass
class URI(ADTypeData):
    """AD type 0x24 (URI)"""

    uri: str

    @classmethod
    def from_bytes(cls, data: bytes) -> "URI":
        return cls(uri=data.decode("utf-8"))


@dataclass
class IndoorPositioning(ADTypeData):
    """AD type 0x25 (Indoor Positioning)"""

    data: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> "IndoorPositioning":
        raise NotImplementedError("TODO")


@dataclass
class TransportDiscoveryData(ADTypeData):
    """AD type 0x26 (Transport Discovery Data)"""

    data: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> "TransportDiscoveryData":
        raise NotImplementedError("TODO")


@dataclass
class LESupportedFeatures(ADTypeData):
    """AD type 0x27 (LE Supported Features)"""

    features: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> "LESupportedFeatures":
        raise NotImplementedError("TODO")


@dataclass
class ChannelMapUpdateIndication(ADTypeData):
    """AD type 0x28 (Channel Map Update Indication)"""

    data: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> "ChannelMapUpdateIndication":
        raise NotImplementedError("TODO")


@dataclass
class PBADV(ADTypeData):
    """AD type 0x29 (PB-ADV)"""

    data: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> "PBADV":
        raise NotImplementedError("TODO")


@dataclass
class MeshMessage(ADTypeData):
    """AD type 0x2A (Mesh Message)"""

    data: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> "MeshMessage":
        raise NotImplementedError("TODO")


@dataclass
class MeshBeacon(ADTypeData):
    """AD type 0x2B (Mesh Beacon)"""

    data: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> "MeshBeacon":
        raise NotImplementedError("TODO")


@dataclass
class BIGInfo(ADTypeData):
    """AD type 0x2C (BIGInfo)"""

    data: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> "BIGInfo":
        raise NotImplementedError("TODO")


@dataclass
class BroadcastCode(ADTypeData):
    """AD type 0x2D (Broadcast Code)"""

    data: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> "BroadcastCode":
        raise NotImplementedError("TODO")


@dataclass
class ResolvableSetIdentifier(ADTypeData):
    """AD type 0x2E (Resolvable Set Identifier)"""

    data: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> "ResolvableSetIdentifier":
        raise NotImplementedError("TODO")


@dataclass
class AdvertisingIntervalLong(ADTypeData):
    """AD type 0x2F (Advertising Interval - long)"""

    data: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> "AdvertisingIntervalLong":
        raise NotImplementedError("TODO")


@dataclass
class BroadcastName(ADTypeData):
    """AD type 0x30 (Broadcast Name)"""

    data: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> "BroadcastName":
        raise NotImplementedError("TODO")


@dataclass
class EncryptedAdvertisingData(ADTypeData):
    """AD type 0x31 (Encrypted Advertising Data)"""

    data: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> "EncryptedAdvertisingData":
        raise NotImplementedError("TODO")


@dataclass
class PeriodicAdvertisingResponseTimingInformation(ADTypeData):
    """AD type 0x32 (Periodic Advertising Response Timing Information)"""

    data: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> "PeriodicAdvertisingResponseTimingInformation":
        raise NotImplementedError("TODO")


@dataclass
class ElectronicShelfLabel(ADTypeData):
    """AD type 0x34 (Electronic Shelf Label)"""

    data: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> "ElectronicShelfLabel":
        raise NotImplementedError("TODO")


@dataclass
class _3DInformationData(ADTypeData):
    """AD type 0x3D (3D Information Data)"""

    data: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> "_3DInformationData":
        raise NotImplementedError("TODO")


@dataclass
class ManufacturerSpecificData(ADTypeData):
    """AD type 0xFF (Manufacturer Specific Data)"""

    company_id: int
    data: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> "ManufacturerSpecificData":
        company_id = bytes_to_int(data[:2])
        data = data[2:]
        return cls(company_id=company_id, data=data)


type_to_class: Dict[int, Type[ADTypeData]] = {
    0x01: Flags,
    0x02: IncompleteUUID16,
    0x03: CompleteUUID16,
    0x04: IncompleteUUID32,
    0x05: CompleteUUID32,
    0x06: IncompleteUUID128,
    0x07: CompleteUUID128,
    0x08: ShortenedLocalName,
    0x09: CompleteLocalName,
    0x0A: TxPowerLevel,
    0x0D: ClassOfDevice,
    0x0E: SimplePairingHashC,
    0x0F: SimplePairingRandomizerR,
    0x11: SecurityManagerOOBFlags,
    0x12: PeripheralConnectionIntervalRange,
    0x14: SolicitationUUID16,
    0x15: SolicitationUUID128,
    0x16: ServiceDataUUID16,
    0x17: PublicTargetAddress,
    0x18: RandomTargetAddress,
    0x19: Appearance,
    0x1A: AdvertisingInterval,
    0x1B: LEBluetoothDeviceAddress,
    0x1C: LERole,
    0x1D: SimplePairingHashC256,
    0x1E: SimplePairingRandomizerR256,
    0x20: ServiceDataUUID32,
    0x21: ServiceDataUUID128,
    0x22: LESecureConnectionsConfirmationValue,
    0x23: LESecureConnectionsRandomValue,
    0x24: URI,
    0x25: IndoorPositioning,
    0x26: TransportDiscoveryData,
    0x27: LESupportedFeatures,
    0x28: ChannelMapUpdateIndication,
    0x29: PBADV,
    0x2A: MeshMessage,
    0x2B: MeshBeacon,
    0x2C: BIGInfo,
    0x2D: BroadcastCode,
    0x2E: ResolvableSetIdentifier,
    0x2F: AdvertisingIntervalLong,
    0x30: BroadcastName,
    0x31: EncryptedAdvertisingData,
    0x32: PeriodicAdvertisingResponseTimingInformation,
    0x34: ElectronicShelfLabel,
    0x3D: _3DInformationData,
    0xFF: ManufacturerSpecificData,
}

type_of_class_OOB: Dict[int, Type[ADTypeData]]  = {
    **type_to_class,
    0x10: SecurityManagerTKValue,
}

type_of_class_EIR: Dict[int, Type[ADTypeData]]  = {
    **type_to_class,
    0x10: DeviceID,
}
