from middlewared.rclone.base import BaseRcloneRemote
from middlewared.schema import Int, Str


class GoogleCloudStorageRcloneRemote(BaseRcloneRemote):
    name = "GOOGLE_CLOUD_STORAGE"
    title = "Google Cloud Storage"

    buckets = True

    rclone_type = "google cloud storage"

    credentials_schema = [
        Str("token", verbose="Access Token", required=True),
        Int("project_number", verbose="Project Number"),
    ]
