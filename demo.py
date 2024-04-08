from pathlib import Path

from ble_ad_parser.assigned_numbers import AssignedNumbersDownloader
from ble_ad_parser.uuids import AssignedUUIDs

assigned_numbers = AssignedNumbersDownloader(target_dir=Path("./assigned_numbers_repo")).read()

uuids = AssignedUUIDs.from_assigned_numbers(assigned_numbers)

print(uuids.table)
