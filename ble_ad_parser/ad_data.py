"""
This module contains functions to parse AD data from a byte array
The module does not read the parsed data, it only parses the data and returns it in
a structured format
"""

from dataclasses import dataclass
from typing import List, Tuple


@dataclass
class ADField:
    """Class to represent an AD field"""

    type: int
    length: int
    data: bytes


@dataclass
class ADData:
    """Class to represent AD data"""

    fields: List[ADField]

    @classmethod
    def from_bytes(cls, data: bytes):
        """
        Create an ADData object from a byte array

        Args:
            data (bytes): Byte array containing the AD data

        Returns:
            ADData: AD data object
        """
        fields = []
        while data:
            field, data = extract_ad_field(data)
            fields.append(field)
        return cls(fields)


def extract_ad_field(data: bytes) -> Tuple[ADField, bytes]:
    """
    Parse an AD field from the given data

    Args:
        data (bytes): Byte array starting with the target AD field

    Returns:
        Tuple[ADField, bytes]: Tuple containing the parsed AD field and the remaining data
    """
    data_type = data[0]
    length = data[1]
    ad_data = data[2 : 2 + length]
    ad_field = ADField(data_type, length, ad_data)
    remaining_data = data[2 + length :]
    return ad_field, remaining_data
