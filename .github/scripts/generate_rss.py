#!/usr/bin/env python3
"""Generate an RSS feed of .torrent links from README.md."""

import re
import xml.etree.ElementTree as ET
from pathlib import Path


def extract_torrent_entries(readme_path: str) -> list[tuple[str, str | None, str]]:
    """Extract torrent entries from README.md.

    Returns list of (log_origin, archive_url, torrent_url) tuples.
    archive_url may be None if the second column is empty or not a https:// link.
    """
    content = Path(readme_path).read_text()
    entries = []

    # Match table rows with torrent links
    # Format: | log_origin | archive_url | [.torrent](torrent_url) |
    # The second column is optional and may contain any content or be empty
    pattern = r'\|\s*([^\|]+?)\s*\|\s*([^\|]*?)\s*[†]?\s*\|\s*\[\.torrent\]\(([^)]+)\)\s*\|'

    for match in re.finditer(pattern, content):
        log_origin = match.group(1).strip()
        archive_url_raw = match.group(2).strip()
        torrent_url = match.group(3).strip()

        # Only use archive_url if it's a valid https:// link
        archive_url = archive_url_raw if archive_url_raw.startswith('https://') else None

        entries.append((log_origin, archive_url, torrent_url))

    return entries


def generate_rss(entries: list[tuple[str, str | None, str]], output_path: str) -> None:
    """Generate RSS feed from torrent entries."""
    # Register namespace to avoid ns0 prefix
    ET.register_namespace('atom', 'http://www.w3.org/2005/Atom')

    rss = ET.Element('rss', version='2.0')

    channel = ET.SubElement(rss, 'channel')

    # Channel metadata
    title = ET.SubElement(channel, 'title')
    title.text = 'CT Log Archive Torrents'

    link = ET.SubElement(channel, 'link')
    link.text = 'https://github.com/geomys/ct-archive'

    description = ET.SubElement(channel, 'description')
    description.text = 'Torrent files for archived Certificate Transparency logs'

    language = ET.SubElement(channel, 'language')
    language.text = 'en-us'

    # Self-referencing atom:link
    atom_link = ET.SubElement(channel, '{http://www.w3.org/2005/Atom}link')
    atom_link.set('href', 'https://raw.githubusercontent.com/geomys/ct-archive/main/torrents.rss')
    atom_link.set('rel', 'self')
    atom_link.set('type', 'application/rss+xml')

    # Add items for each torrent
    for log_origin, archive_url, torrent_url in entries:
        item = ET.SubElement(channel, 'item')

        item_title = ET.SubElement(item, 'title')
        item_title.text = f'{log_origin}'

        # Only add item_link if archive_url is a valid https:// link
        if archive_url is not None:
            item_link = ET.SubElement(item, 'link')
            item_link.text = archive_url

        item_description = ET.SubElement(item, 'description')
        item_description.text = f'Torrent archive for CT log: {log_origin}'

        # Use torrent URL as enclosure
        enclosure = ET.SubElement(item, 'enclosure')
        enclosure.set('url', torrent_url)
        enclosure.set('type', 'application/x-bittorrent')

        # Use torrent URL as guid
        guid = ET.SubElement(item, 'guid')
        guid.set('isPermaLink', 'false')
        guid.text = torrent_url

    # Write with XML declaration
    tree = ET.ElementTree(rss)
    ET.indent(tree, space='  ')
    tree.write(output_path, encoding='unicode', xml_declaration=True)

    # Add newline at end of file
    with open(output_path, 'a') as f:
        f.write('\n')


def main():
    readme_path = Path(__file__).parent.parent.parent / 'README.md'
    output_path = Path(__file__).parent.parent.parent / 'torrents.rss'

    entries = extract_torrent_entries(str(readme_path))
    print(f'Found {len(entries)} torrent entries')

    generate_rss(entries, str(output_path))
    print(f'Generated RSS feed at {output_path}')


if __name__ == '__main__':
    main()
