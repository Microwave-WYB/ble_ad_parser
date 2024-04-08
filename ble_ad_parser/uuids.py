"""
This module syncs the assigned UUIDs from the Bluetooth SIG repository
"""

from dataclasses import dataclass
from typing import Dict

from ble_ad_parser.assigned_numbers import AssignedNumbers


@dataclass
class AssignedUUIDs:
    """Class to represent the assigned UUIDs"""

    table: Dict[int, str]

    @classmethod
    def from_assigned_numbers(cls, assigned_numbers: AssignedNumbers):
        """
        Create an AssignedUUIDs object from the assigned numbers dictionary

        Args:
            assigned_numbers (AssignedNumbers): Assigned numbers dictionary

        Returns:
            AssignedUUIDs: Assigned UUIDs object
        """
        table = {}
        for _, values in assigned_numbers["uuids"].items():
            for value in values["uuids"]:
                uuid, name = value["uuid"], value["name"]
                table[uuid] = name
        return cls(table)
