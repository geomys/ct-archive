# Certificate Transparency Log Archive

This repository contains a directory of archived Certificate Transparency (CT)
logs, as well as tools to archive RFC 6962 and Static CT logs.

## Archived Logs

| Log Origin | Archive Location |
|------------|------------------|
| ct.cloudflare.com/logs/nimbus2022 | https://archive.org/details/ct_cloudflare_nimbus2022 [^noissuer] |
| ct.cloudflare.com/logs/nimbus2023 | https://archive.org/details/ct_cloudflare_nimbus2023 [^noissuer] |
| ct.cloudflare.com/logs/nimbus2024 | https://archive.org/details/ct_cloudflare_nimbus2024 [^noissuer] |
| ct1.digicert-ct.com/log | https://archive.org/details/ct_digicert_ct1 [^noissuer] |
| ct2.digicert-ct.com/log | https://archive.org/details/ct_digicert_ct2 [^noissuer] |
| yeti2018.ct.digicert.com/log | https://archive.org/details/ct_digicert_yeti2018 [^noissuer] |
| yeti2019.ct.digicert.com/log | https://archive.org/details/ct_digicert_yeti2019 [^noissuer] |
| yeti2020.ct.digicert.com/log | https://archive.org/details/ct_digicert_yeti2020 [^noissuer] |
| yeti2021.ct.digicert.com/log | https://archive.org/details/ct_digicert_yeti2021 [^noissuer] |
| yeti2022.ct.digicert.com/log | https://archive.org/details/ct_digicert_yeti2022 [^noissuer] |
| yeti2022-2.ct.digicert.com/log | https://archive.org/details/ct_digicert_yeti2022_2 [^noissuer] |
| yeti2023.ct.digicert.com/log | https://archive.org/details/ct_digicert_yeti2023 [^noissuer] |
| nessie2018.ct.digicert.com/log | https://archive.org/details/ct_digicert_nessie2018 [^noissuer] |
| nessie2019.ct.digicert.com/log | https://archive.org/details/ct_digicert_nessie2019 [^noissuer] |
| nessie2020.ct.digicert.com/log | https://archive.org/details/ct_digicert_nessie2020 [^noissuer] |
| nessie2021.ct.digicert.com/log | https://archive.org/details/ct_digicert_nessie2021 [^noissuer] |
| nessie2022.ct.digicert.com/log | https://archive.org/details/ct_digicert_nessie2022 [^noissuer] |
| nessie2023.ct.digicert.com/log | https://archive.org/details/ct_digicert_nessie2023 [^noissuer] |
| sphinx.ct.digicert.com/2024h1 | https://archive.org/details/ct_digicert_sphinx2024h1 |
| sphinx.ct.digicert.com/2024h2 | https://archive.org/details/ct_digicert_sphinx2024h2 |
| wyvern.ct.digicert.com/2024h1 | https://archive.org/details/ct_digicert_wyvern2024h1 [WIP] |
| wyvern.ct.digicert.com/2024h2 | https://archive.org/details/ct_digicert_wyvern2024h2 [WIP] |
| ct.ws.symantec.com | https://archive.org/details/ct_symantec_ct [^noissuer] |
| vega.ws.symantec.com | https://archive.org/details/ct_symantec_vega [^noissuer] |
| sirius.ws.symantec.com | https://archive.org/details/ct_symantec_sirius [^noissuer] |
| ctlog-gen2.api.venafi.com | https://archive.org/details/ct_venafi_ctlog_gen2 [^noissuer] |
| oak.ct.letsencrypt.org/2019 | https://archive.org/details/ct_letsencrypt_oak2019 [^noissuer] |
| oak.ct.letsencrypt.org/2020 | https://archive.org/details/ct_letsencrypt_oak2020 [^noissuer] |
| oak.ct.letsencrypt.org/2021 | https://archive.org/details/ct_letsencrypt_oak2021 [^noissuer] |
| oak.ct.letsencrypt.org/2022 | https://archive.org/details/ct_letsencrypt_oak2022 [^noissuer] |
| oak.ct.letsencrypt.org/2023 | https://archive.org/details/ct_letsencrypt_oak2023 [^noissuer] |
| sabre.ct.comodo.com | https://archive.org/details/ct_comodo_sabre [^noissuer] |
| mammoth.ct.comodo.com | https://archive.org/details/ct_comodo_mammoth [^noissuer] |
| mammoth2024h1.ct.sectigo.com | https://archive.org/details/ct_sectigo_mammoth2024h1 |
| mammoth2024h2.ct.sectigo.com | https://archive.org/details/ct_sectigo_mammoth2024h2 [WIP] |
| mammoth2025h2.ct.sectigo.com | https://archive.org/details/ct_sectigo_mammoth2025h2 |
| mammoth2026h1.ct.sectigo.com | https://archive.org/details/ct_sectigo_mammoth2026h1 [^noissuer] |
| mammoth2026h2.ct.sectigo.com | https://archive.org/details/ct_sectigo_mammoth2026h2 [^noissuer] |
| sabre2024h1.ct.sectigo.com | https://archive.org/details/ct_sectigo_sabre2024h1 |
| sabre2024h2.ct.sectigo.com | https://archive.org/details/ct_sectigo_sabre2024h2 [WIP] |
| sabre2025h2.ct.sectigo.com | https://archive.org/details/ct_sectigo_sabre2025h2 [WIP] |
| sabre2026h1.ct.sectigo.com | https://archive.org/details/ct_sectigo_sabre2026h1 [^noissuer] |
| sabre2026h2.ct.sectigo.com | https://archive.org/details/ct_sectigo_sabre2026h2 [^noissuer] |

If you archive a log, please submit a pull request to add it to this table.

A very comprehensive list of CT logs can be found at https://sslmate.com/app/ctlogs.

[^noissuer]: These logs were mistakenly archived without the `issuer/` directory.

## Archival Format

Logs are archived in the [c2sp.org/static-ct-api@v1.0.0][] format, although if
they were originally served through RFC 6962 APIs, leaves might miss the
LeafIndex extension. The [sunlight.ReadTileLeafMaybeArchival][] function can
read both types of leaves.

The log is split over multiple zip files, each 10-15GB. Archive `<N>.zip`
contains the tiles at levels -1 (the data entries), 0, 1, and 2 belonging to
subtree

    [ 256×256×256×N, min(256×256×256×(N+1),TreeSize) )

In other words, each zip file contains one level 2 tile, and all those below it.

Every zip file also contains the following files, making it self-contained and
self-verifying:

* `README.txt` — a description of the archival format
* `checkpoint` — a Signed Tree Head in [c2sp.org/tlog-checkpoint][] format, with
  the RFC 6962 STH signature encoded according to [c2sp.org/static-ct-api@v1.0.0][]
* `log.v3.json` — a JSON specification of the log, including its log ID,
  public key, temporal interval, and original URL(s)
* `issuer/*` — the X.509 chain issuers for the whole log
* `tile/{3,4}/*` — higher-level tiles, including the hashes of other level 2
  tiles not included in this archive
* `tile/{0,1,2}/*.p/*` — partial tiles on the right edge of the tree, if any,
  necessary to compute the tree head

[sunlight.ReadTileLeafMaybeArchival]: https://pkg.go.dev/filippo.io/sunlight@v0.6.4-0.20251203100209-1d019a3fb1ac#ReadTileLeafMaybeArchival
[c2sp.org/static-ct-api@v1.0.0]: https://c2sp.org/static-ct-api@v1.0.0
[c2sp.org/tlog-checkpoint]: https://c2sp.org/tlog-checkpoint

## Tools

### Mirroring RFC 6962 Logs

The `vanity-mirror` command fetches an RFC 6962 log and stores it in the Static
CT log format.

    go run geomys.org/ct-archive/cmd/vanity-mirror@main

The log's URL and public key are obtained from the log.v3.json file in the
working directory, and the log is downloaded to the working directory. The
following command creates a log.v3.json file for a log with the given URL:

    curl -sSL https://www.gstatic.com/ct/log_list/v3/all_logs_list.json | \
    jq ".operators[].logs[] | select(.url == \"$URL\") | del(.state, .mmd)" | tee log.v3.json

The origin for the checkpoint is derived from the log's URL.

Progress is tracked by storing partial unsigned checkpoints in the working
directory. Only `get-sth` and `get-entries` requests are made to the log. Once
the download is complete, the final checkpoint is verified against the Signed
Tree Head, and the signature is stored in the checkpoint file.

An optional command-line argument can be provided to specify a different base URL
for fetching the log, e.g. a mirror. This URL is not persisted in the archive.

### Archiving Static CT Logs

The `photocamera-archiver` command packs a local Static CT log into zip files
suitable for archival.

*Note: as of Go 1.25, the archive/zip package produces subtly invalid Zip64
files that some extractors (including sometimes the Internet Archive's) cannot
read. Use https://go.dev/cl/725161 to build and run this tool like in the
instructions below or fix the archives with `zip -F` before uploading them.*

    go install golang.org/dl/gotip@latest
    gotip download 725161
    gotip run geomys.org/ct-archive/cmd/photocamera-archiver@main

The log is read from the working directory, and zip files are created in the
`archive/` subdirectory. All entries are verified against the checkpoint.

### Uploading Archives to the Internet Archive

If the log operator doesn't have the resources to host them long-term, the zip
files can be uploaded to a new Internet Archive item using the `ia` CLI. The
`ia-metadata.py` script populates the metadata from the contents of the item.

Use `ct_operator_nameYYYYhN` as the item identifier, e.g. `ct_sectigo_sabre2024h1`.

    uv tool install internetarchive
    ia configure
    ia upload --metadata="collection:opensource_media" $ITEM archive/*.zip
    uv run --script cmd/ia-metadata.py $ITEM

All items are tagged with the [certificate transparency log][] topic.

[certificate transparency log]: https://archive.org/search?query=subject%3A%22certificate+transparency+log%22&sort=title
