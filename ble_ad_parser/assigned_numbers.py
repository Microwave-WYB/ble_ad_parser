"""
This module syncs the assigned numbers from the Bluetooth SIG repository
"""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict

import git
import git.exc
import yaml

type AssignedNumbers = dict


def read_subtree(directory: Path) -> AssignedNumbers:
    """
    Recursively read a sub-tree of the assigned numbers repository

    Args:
        directory (Path): The directory to start reading from

    Returns:
        AssignedNumbers: Dictionary containing the assigned numbers
    """
    subtree: AssignedNumbers = {}

    for item in directory.iterdir():
        if item.is_file() and item.suffix == ".yaml":
            # Parse the YAML content
            yaml_content = yaml.safe_load(item.read_text())
            subtree[item.stem] = yaml_content
        elif item.is_dir():
            # Recursively read subdirectories
            subtree[item.name] = read_subtree(item)

    return subtree


@dataclass
class AssignedNumbersDownloader:
    """Class to represent the assigned numbers"""

    git_clone_url: str = "https://bitbucket.org/bluetooth-SIG/public.git"
    target_dir: Path = Path("assigned_numbers_repo")
    cache_file: Path = Path("assigned_numbers.json")

    def __post_init__(self):
        self.sync()

    def sync(self):
        """
        Sync the assigned numbers from the Bluetooth SIG repository
        if the repository is not cloned, it will clone the repository
        otherwise, it will pull the latest changes
        """
        try:
            repo = git.Repo(self.target_dir)
            repo.remotes.origin.pull()
        except (git.exc.InvalidGitRepositoryError, git.exc.NoSuchPathError):
            git.Repo.clone_from(self.git_clone_url, self.target_dir)

    def read(self) -> AssignedNumbers:
        """
        Read the assigned numbers from the cloned repository

        Returns:
            AssignedNumbers: Dictionary containing the assigned numbers
        """
        if self.cache_file.exists():
            return json.loads(self.cache_file.read_text(encoding="utf-8"))

        assigned_numbers = read_subtree(self.target_dir / "assigned_numbers")

        # Cache the assigned numbers
        self.cache_file.write_text(json.dumps(assigned_numbers, indent=2), encoding="utf-8")

        return assigned_numbers


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
