#!/usr/bin/env python3
# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "internetarchive",
#     "requests",
# ]
# ///
"""Lint Internet Archive entries from README.md."""

import json
import math
import re
import sys
from pathlib import Path

import requests
from internetarchive import get_item


def extract_ia_entries(readme_path: str) -> list[tuple[str, str]]:
    """Extract Internet Archive entries from README.md.

    Returns list of (log_origin, item_identifier) tuples.
    """
    content = Path(readme_path).read_text()
    entries = []

    # Match table rows with archive.org URLs
    # Format: | log_origin | https://archive.org/details/item_id ... |
    pattern = r'\|\s*([^\|]+?)\s*\|\s*https://archive\.org/details/(\S+?)\s'

    for match in re.finditer(pattern, content):
        log_origin = match.group(1).strip()
        item_id = match.group(2).strip()
        entries.append((log_origin, item_id))

    return entries


def lint_item(log_origin: str, item_id: str) -> list[str]:
    """Lint a single Internet Archive item.

    Returns a list of error messages (empty if all checks pass).
    """
    errors = []

    item = get_item(item_id)
    metadata = item.metadata

    if not metadata:
        errors.append(f"Item {item_id} not found or has no metadata")
        return errors

    # Check 1: Has "certificate transparency log" topic
    subjects = metadata.get("subject", [])
    if isinstance(subjects, str):
        subjects = [subjects]
    if "certificate transparency log" not in subjects:
        errors.append(
            f"Missing 'certificate transparency log' topic (has: {subjects})"
        )

    # Check 2: Has ctlogid and cturl metadata
    ctlogid = metadata.get("ctlogid")
    cturl = metadata.get("cturl")
    if not ctlogid:
        errors.append("Missing 'ctlogid' metadata")
    if not cturl:
        errors.append("Missing 'cturl' metadata")

    # Check 3: Collection is one of the allowed collections
    allowed_collections = {"opensource_media", "datasets", "datasets_unsorted"}
    collection = metadata.get("collection", [])
    if isinstance(collection, str):
        collection = [collection]
    if not any(c in allowed_collections for c in collection):
        errors.append(
            f"Collection should be one of {allowed_collections} (has: {collection})"
        )

    # Check 4: Number of zip files matches ceil(ctlogsize / 256^3)
    ctlogsize = metadata.get("ctlogsize")
    if ctlogsize:
        try:
            ctlogsize = int(ctlogsize)
            expected_zips = math.ceil(ctlogsize / (256**3))

            # Count zip files in item
            zip_count = sum(
                1 for f in item.files if f.get("name", "").endswith(".zip")
            )

            if zip_count != expected_zips:
                errors.append(
                    f"Expected {expected_zips} zip files based on ctlogsize "
                    f"{ctlogsize}, found {zip_count}"
                )
        except ValueError:
            errors.append(f"Invalid ctlogsize value: {ctlogsize}")
    else:
        errors.append("Missing 'ctlogsize' metadata")

    # Check 5: Verify checkpoint and log.v3.json files exist and match metadata
    if ctlogid or cturl:
        # Find first zip file to fetch from
        zip_files = sorted(
            f.get("name") for f in item.files if f.get("name", "").endswith(".zip")
        )
        if zip_files:
            first_zip = zip_files[0]
            base_url = f"https://archive.org/download/{item_id}/{first_zip}"

            # Fetch and verify log.v3.json
            log_json_url = f"{base_url}/log.v3.json"
            try:
                resp = requests.get(log_json_url, timeout=30)
                if resp.status_code == 200:
                    log_json = resp.json()

                    # Verify log_id matches ctlogid
                    if ctlogid and log_json.get("log_id") != ctlogid:
                        errors.append(
                            f"log.v3.json log_id '{log_json.get('log_id')}' "
                            f"does not match metadata ctlogid '{ctlogid}'"
                        )

                    # Verify url matches cturl
                    log_url = log_json.get("url", "").rstrip("/")
                    metadata_url = (cturl or "").rstrip("/")
                    if cturl and log_url != metadata_url:
                        errors.append(
                            f"log.v3.json url '{log_url}' "
                            f"does not match metadata cturl '{metadata_url}'"
                        )
                else:
                    errors.append(
                        f"Failed to fetch log.v3.json: HTTP {resp.status_code}"
                    )
            except requests.RequestException as e:
                errors.append(f"Failed to fetch log.v3.json: {e}")
            except json.JSONDecodeError as e:
                errors.append(f"Invalid JSON in log.v3.json: {e}")

            # Fetch and verify checkpoint
            checkpoint_url = f"{base_url}/checkpoint"
            try:
                resp = requests.get(checkpoint_url, timeout=30)
                if resp.status_code == 200:
                    checkpoint = resp.text
                    lines = checkpoint.strip().split("\n")

                    if len(lines) >= 2:
                        checkpoint_origin = lines[0]
                        checkpoint_size = lines[1]

                        # Verify origin matches cturl
                        if cturl:
                            expected_origin = cturl.replace("https://", "").rstrip("/")
                            if checkpoint_origin != expected_origin:
                                errors.append(
                                    f"checkpoint origin '{checkpoint_origin}' "
                                    f"does not match cturl '{expected_origin}'"
                                )

                        # Verify size matches ctlogsize
                        if ctlogsize:
                            try:
                                if int(checkpoint_size) != ctlogsize:
                                    errors.append(
                                        f"checkpoint size {checkpoint_size} "
                                        f"does not match ctlogsize {ctlogsize}"
                                    )
                            except ValueError:
                                errors.append(
                                    f"Invalid checkpoint size: {checkpoint_size}"
                                )
                    else:
                        errors.append(
                            f"Invalid checkpoint format (expected at least 2 lines)"
                        )
                else:
                    errors.append(
                        f"Failed to fetch checkpoint: HTTP {resp.status_code}"
                    )
            except requests.RequestException as e:
                errors.append(f"Failed to fetch checkpoint: {e}")
        else:
            errors.append("No zip files found in item")

    return errors


def main():
    readme_path = Path(__file__).parent.parent.parent / "README.md"

    entries = extract_ia_entries(str(readme_path))
    print(f"Found {len(entries)} Internet Archive entries")

    all_passed = True
    for log_origin, item_id in entries:
        print(f"\nLinting {item_id} ({log_origin})...")
        errors = lint_item(log_origin, item_id)

        if errors:
            all_passed = False
            for error in errors:
                print(f"  ERROR: {error}")
        else:
            print("  OK")

    if not all_passed:
        print("\nLinting failed!")
        sys.exit(1)
    else:
        print("\nAll checks passed!")
        sys.exit(0)


if __name__ == "__main__":
    main()
