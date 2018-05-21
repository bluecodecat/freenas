from middlewared.rclone.base import BaseRcloneRemote
from middlewared.schema import Str


class WebDavRcloneRemote(BaseRcloneRemote):
    name = "WEBDAV"
    title = "WebDAV"

    rclone_type = "webdav"

    credentials_schema = [
        Str("url", verbose="URL", required=True),
        Str("vendor", verbose="Name of the WebDAV site/service/software",
            enum=["NEXTCLOUD", "OWNCLOUD", "SHAREPOINT", "OTHER"], required=True),
        Str("user", verbose="Username", required=True),
        Str("pass", verbose="Password", required=True),
    ]

    def get_remote_extra(self, credentials, attributes):
        return dict(vendor=attributes["vendor"].lower())
