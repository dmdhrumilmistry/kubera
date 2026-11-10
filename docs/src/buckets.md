# Cloud storage buckets

Backups, build artifacts and exported configs often end up in object storage. `kubera scan bucket` lists a bucket, downloads the objects worth scanning and scans them like files on disk, archives included.

```bash
kubera scan bucket s3://acme-backups                       # a whole S3 bucket
kubera scan bucket s3://acme-artifacts/releases/ --verify  # only a prefix
kubera scan bucket s3://public-data --anonymous            # a public bucket, unsigned
kubera scan bucket gs://acme-exports --token-env GCS_TOKEN # Google Cloud Storage
kubera scan bucket az://acmedata/backups                   # Azure Blob Storage (account/container)
```

## Amazon S3 and S3-compatible stores

Requests are signed with SigV4, using the standard environment variables:

```bash
export AWS_ACCESS_KEY_ID=<key id>
export AWS_SECRET_ACCESS_KEY=<secret>
export AWS_SESSION_TOKEN=<session token>   # only for temporary credentials
kubera scan bucket s3://acme-backups
```

Without these variables, an S3 scan needs `--anonymous` (unsigned requests, for public buckets).

The region is detected from the bucket. Set `--region` to skip the lookup. For MinIO, Cloudflare R2 and other S3-compatible stores, pass the endpoint:

```bash
kubera scan bucket s3://builds --endpoint-url https://<account>.r2.cloudflarestorage.com
kubera scan bucket s3://backups --endpoint-url https://minio.internal.example:9000
```

## Google Cloud Storage

GCS takes an OAuth access token from an environment variable:

```bash
export GCS_TOKEN="$(gcloud auth print-access-token)"
kubera scan bucket gs://acme-exports --token-env GCS_TOKEN
```

## Azure Blob Storage

Azure URLs name the storage account, then the container, then an optional prefix: `az://<account>/<container>[/prefix]`. Three ways to authorize:

```bash
# Shared Key: the account key signs every request; the key itself is never sent.
export AZURE_STORAGE_ACCOUNT=acmedata          # optional; must match the URL when set
export AZURE_STORAGE_KEY=<account key>
kubera scan bucket az://acmedata/backups

# A SAS token (container or account level, read + list) from any variable.
export BACKUPS_SAS='sv=2022-11-02&ss=b&srt=co&sp=rl&se=...&sig=...'
kubera scan bucket az://acmedata/backups/2026/ --sas-env BACKUPS_SAS

# A container with public (anonymous) read access.
kubera scan bucket az://azureopendatastorage/mnist --anonymous
```

For Azurite or another endpoint, pass it with `--endpoint-url` (path-style, including the account: `http://127.0.0.1:10000/devstoreaccount1`; plain `http` is refused outside tests). Findings link to the blob URL (without the SAS).

## What gets scanned

- Objects are listed first. **Path excludes and the size limit are checked before anything is downloaded**, so skipped objects cost nothing. `--exclude-path`, `exclude_paths` and the [default excludes](scanning.md#default-excludes) all apply to object keys.
- Text objects up to `--max-file-size` are scanned. Binaries are skipped.
- Archives (zip, jar, tar, tar.gz, ...) up to 512 MiB are opened in memory and their entries scanned, with the same [limits](scanning.md#archives) as filesystem scans.
- Each finding links to the object in the AWS or Google Cloud console, or to the Azure blob URL.

## Options

| Flag | Meaning |
|---|---|
| `--anonymous` | Send unsigned requests (public S3 buckets and Azure containers). |
| `--region REGION` | S3 region (default: detected from the bucket). |
| `--endpoint-url URL` | S3-compatible endpoint (MinIO, R2, ...), or an Azure Blob endpoint (Azurite). |
| `--token-env VAR` | Environment variable with a GCS OAuth access token. |
| `--sas-env VAR` | Environment variable with an Azure SAS token. |
| `--downloads N` | Parallel downloads (default 16). |
| `--max-objects N` | List at most N objects (default 100000). |

All [common scan options](scanning.md#common-options) work too.

## Safety

Credentials are only ever sent to the storage endpoint, over HTTPS, without following redirects. An Azure account key never leaves the process: it only signs requests (Shared Key), like the AWS secret key (SigV4). A SAS token is part of each request URL, so URLs are reduced to their host in error messages. An `http://` endpoint is refused. Objects are never written to disk.
