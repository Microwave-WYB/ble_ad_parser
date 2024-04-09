"""
This module contains functions to parse AD data from a byte array
The module does not read the parsed data, it only parses the data and returns it in
a structured format
"""

from dataclasses import dataclass
from typing import List

from ble_ad_parser.ad_types import ADField


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
            ad_field, data = ADField.from_bytes(data)
            fields.append(ad_field)
        return cls(fields)
