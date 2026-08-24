#!/usr/bin/env python3
# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "bencodepy",
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

import bencodepy
import requests
from internetarchive import get_item


def extract_ia_entries(readme_path: str) -> list[tuple[str, list[str], bool]]:
    """Extract Internet Archive entries from README.md.

    Returns (log_origin, item_identifiers, has_torrent) tuples. A log may span
    multiple IA items, with extension items named ``<identifier>_extN``.
    """
    content = Path(readme_path).read_text()
    entries = []

    for line in content.splitlines():
        if not line.startswith("|"):
            continue

        cells = line.split("|")
        if len(cells) < 4:
            continue

        log_origin = cells[1].strip()
        item_ids = re.findall(
            r"https://archive\.org/details/([^\s|]+)", cells[2]
        )
        if not item_ids:
            continue

        has_torrent = ".torrent" in cells[3]
        entries.append((log_origin, item_ids, has_torrent))

    return entries


def lint_item(
    log_origin: str, item_ids: list[str], has_torrent: bool
) -> list[str]:
    """Lint all Internet Archive items for a single log.

    Returns a list of error messages (empty if all checks pass).
    """
    errors = []
    items = [(item_id, get_item(item_id)) for item_id in item_ids]

    expected_extension_ids = [
        f"{item_ids[0]}_ext{index}" for index in range(1, len(item_ids))
    ]
    if item_ids[1:] != expected_extension_ids:
        errors.append(
            "Extension items must be named consecutively: expected "
            f"{expected_extension_ids}, found {item_ids[1:]}"
        )

    total_zip_count = sum(
        1
        for _, item in items
        for f in item.files
        if f.get("name", "").endswith(".zip")
    )

    for item_id, item in items:
        item_errors = lint_item_part(
            log_origin, item_id, item, total_zip_count,
            has_torrent and item_id == item_ids[0],
        )
        errors.extend(f"{item_id}: {error}" for error in item_errors)

    return errors


def lint_item_part(
    log_origin: str, item_id: str, item, total_zip_count: int, has_torrent: bool
) -> list[str]:
    """Lint one IA item that is part of a possibly split log archive."""
    errors = []
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

    # Check 2: Has ctlogid and URL metadata.
    # RFC 6962 logs have a single cturl/log.v3.json "url" field, while
    # Static CT logs have separate submission and monitoring URLs.
    ctlogid = metadata.get("ctlogid")
    cturl = metadata.get("cturl")
    ctsubmissionurl = metadata.get("ctsubmissionurl")
    ctmonitoringurl = metadata.get("ctmonitoringurl")
    if not ctlogid:
        errors.append("Missing 'ctlogid' metadata")
    if not cturl and not (ctsubmissionurl and ctmonitoringurl):
        errors.append(
            "Missing URL metadata: expected either 'cturl' or both "
            "'ctsubmissionurl' and 'ctmonitoringurl'"
        )

    # Check 3: Collection is one of the allowed collections
    allowed_collections = {"opensource_media", "datasets", "datasets_unsorted"}
    collection = metadata.get("collection", [])
    if isinstance(collection, str):
        collection = [collection]
    if not any(c in allowed_collections for c in collection):
        errors.append(
            f"Collection should be one of {allowed_collections} (has: {collection})"
        )

    # Check 4: Number of zip files across all extension items matches
    # ceil(ctlogsize / 256^3).
    ctlogsize = metadata.get("ctlogsize")
    if ctlogsize:
        try:
            ctlogsize = int(ctlogsize)
            expected_zips = math.ceil(ctlogsize / (256**3))

            if total_zip_count != expected_zips:
                errors.append(
                    f"Expected {expected_zips} zip files across all items based on "
                    f"ctlogsize {ctlogsize}, found {total_zip_count}"
                )
        except ValueError:
            errors.append(f"Invalid ctlogsize value: {ctlogsize}")
    else:
        errors.append("Missing 'ctlogsize' metadata")

    # Check 5: Verify checkpoint and log.v3.json files exist and match metadata
    if ctlogid or cturl or ctsubmissionurl or ctmonitoringurl:
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

                    # Verify URL metadata matches log.v3.json.
                    if cturl:
                        log_url = log_json.get("url", "").rstrip("/")
                        metadata_url = cturl.rstrip("/")
                        if log_url != metadata_url:
                            errors.append(
                                f"log.v3.json url '{log_url}' "
                                f"does not match metadata cturl '{metadata_url}'"
                            )
                    else:
                        log_submission_url = log_json.get(
                            "submission_url", ""
                        ).rstrip("/")
                        metadata_submission_url = (
                            ctsubmissionurl or ""
                        ).rstrip("/")
                        if (
                            ctsubmissionurl
                            and log_submission_url != metadata_submission_url
                        ):
                            errors.append(
                                f"log.v3.json submission_url "
                                f"'{log_submission_url}' does not match "
                                f"metadata ctsubmissionurl "
                                f"'{metadata_submission_url}'"
                            )

                        log_monitoring_url = log_json.get(
                            "monitoring_url", ""
                        ).rstrip("/")
                        metadata_monitoring_url = (
                            ctmonitoringurl or ""
                        ).rstrip("/")
                        if (
                            ctmonitoringurl
                            and log_monitoring_url != metadata_monitoring_url
                        ):
                            errors.append(
                                f"log.v3.json monitoring_url "
                                f"'{log_monitoring_url}' does not match "
                                f"metadata ctmonitoringurl "
                                f"'{metadata_monitoring_url}'"
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

                        # Verify origin matches the submission URL (or cturl for
                        # older RFC 6962 logs).
                        origin_url = ctsubmissionurl or cturl
                        if origin_url:
                            expected_origin = origin_url.replace(
                                "https://", ""
                            ).rstrip("/")
                            if checkpoint_origin != expected_origin:
                                errors.append(
                                    f"checkpoint origin '{checkpoint_origin}' "
                                    f"does not match URL metadata '{expected_origin}'"
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

    # Check 6: Verify torrent file is not partial (only if torrent link exists in README)
    if not has_torrent:
        return errors

    torrent_url = f"https://archive.org/download/{item_id}/{item_id}_archive.torrent"
    try:
        resp = requests.get(torrent_url, timeout=30)
        if resp.status_code == 200:
            torrent_data = bencodepy.decode(resp.content)
            info = torrent_data.get(b"info", {})

            # Extract files from torrent
            torrent_files = set()
            if b"files" in info:
                # Multi-file torrent
                for f in info[b"files"]:
                    path_parts = [p.decode() for p in f[b"path"]]
                    torrent_files.add("/".join(path_parts))
            elif b"name" in info:
                # Single-file torrent
                torrent_files.add(info[b"name"].decode())

            # Get original files from IA item (exclude derived files and _files.xml)
            ia_files = set()
            for f in item.files:
                source = f.get("source", "")
                name = f.get("name", "")
                # Only check original files, not derived ones or _files.xml metadata
                if source == "original" and name and not name.endswith("_files.xml"):
                    ia_files.add(name)

            # Check for missing files
            missing = ia_files - torrent_files
            if missing:
                errors.append(
                    f"Torrent is missing {len(missing)} files: "
                    f"{', '.join(sorted(missing)[:5])}"
                    f"{' ...' if len(missing) > 5 else ''}"
                )
        else:
            errors.append(f"Failed to fetch torrent: HTTP {resp.status_code}")
    except requests.RequestException as e:
        errors.append(f"Failed to fetch torrent: {e}")
    except Exception as e:
        errors.append(f"Failed to parse torrent: {e}")

    return errors


def main():
    readme_path = Path(__file__).parent.parent.parent / "README.md"

    entries = extract_ia_entries(str(readme_path))
    print(f"Found {len(entries)} Internet Archive entries")

    all_passed = True
    for log_origin, item_ids, has_torrent in entries:
        print(f"\nLinting {', '.join(item_ids)} ({log_origin})...")
        errors = lint_item(log_origin, item_ids, has_torrent)

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
