import asyncio
import ipaddress
import os
import socket

from middlewared.schema import accepts, Bool, Dict, Dir, Int, IPAddr, List, Patch, Str
from middlewared.validators import Range
from middlewared.service import private, CRUDService, SystemServiceService, ValidationErrors
from middlewared.utils.asyncio_ import asyncio_map


class NFSService(SystemServiceService):

    class Config:
        service = "nfs"
        datastore_prefix = "nfs_srv_"
        datastore_extend = 'nfs.nfs_extend'

    @private
    def nfs_extend(self, nfs):
        nfs["userd_manage_gids"] = nfs.pop("16")
        return nfs

    @private
    def nfs_compress(self, nfs):
        nfs["16"] = nfs.pop("userd_manage_gids")
        return nfs

    @accepts(Dict(
        'nfs_update',
        Int('servers', validators=[Range(min=1, max=256)]),
        Bool('udp'),
        Bool('allow_nonroot'),
        Bool('v4'),
        Bool('v4_v3owner'),
        Bool('v4_krb'),
        List('bindip', items=[IPAddr('ip')]),
        Int('mountd_port', required=False, validators=[Range(min=1, max=65535)]),
        Int('rpcstatd_port', required=False, validators=[Range(min=1, max=65535)]),
        Int('rpclockd_port', required=False, validators=[Range(min=1, max=65535)]),
        Bool('userd_manage_gids'),
        Bool('mountd_log'),
        Bool('statd_lockd_log'),
    ))
    async def do_update(self, data):
        old = await self.config()

        new = old.copy()
        new.update(data)

        verrors = ValidationErrors()

        if not new["v4"] and new["v4_v3owner"]:
            verrors.add("nfs_update.v4_v3owner", "This option requires enabling NFSv4")

        if new["v4_v3owner"] and new["userd_manage_gids"]:
            verrors.add(
                "nfs_update.userd_manage_gids", "This option is incompatible with NFSv3 ownership model for NFSv4")

        if verrors:
            raise verrors

        self.nfs_compress(new)

        await self._update_service(old, new)

        self.nfs_extend(new)

        return new


class SharingNFSService(CRUDService):
    class Config:
        namespace = "sharing.nfs"
        datastore = "sharing.nfs_share"
        datastore_prefix = "nfs_"
        datastore_extend = "sharing.nfs.extend"

    @accepts(Dict(
        "sharingnfs_create",
        List("paths", items=[Dir("path")]),
        Str("comment"),
        List("networks", items=[IPAddr("network", cidr=True, v6=False)]),
        List("hosts", items=[Str("host")]),
        Bool("alldirs"),
        Bool("ro"),
        Bool("quiet"),
        Str("maproot_user", required=False, default=None),
        Str("maproot_group", required=False, default=None),
        Str("mapall_user", required=False, default=None),
        Str("mapall_group", required=False, default=None),
        List("security", items=[Str("provider", enum=["SYS", "KRB5", "KRB5I", "KRB5P"])]),
        register=True,
    ))
    async def do_create(self, data):
        verrors = ValidationErrors()

        await self.validate(data, "sharingnfs_create", verrors)

        if verrors:
            raise verrors

        await self.compress(data)
        paths = data.pop("paths")
        data["id"] = await self.middleware.call(
            "datastore.insert", self._config.datastore, data,
            {
                "prefix": self._config.datastore_prefix
            },
        )
        for path in paths:
            await self.middleware.call(
                "datastore.insert", "sharing.nfs_share_path",
                {
                    "share_id": data["id"],
                    "path": path,
                },
            )
        await self.extend(data)

        await self.middleware.call("service.reload", "nfs")

        return data

    @accepts(
        Int("id"),
        Patch(
            "sharingnfs_create",
            "sharingnfs_update",
            ("attr", {"update": True})
        )
    )
    async def do_update(self, id, data):
        verrors = ValidationErrors()
        old = await self.middleware.call(
            "datastore.query", self._config.datastore, [("id", "=", id)],
            {
                "extend": self._config.datastore_extend,
                "prefix": self._config.datastore_prefix,
                "get": True
            },
        )

        new = old.copy()
        new.update(data)

        await self.validate(new, "sharingnfs_update", verrors, old=old)

        if verrors:
            raise verrors

        await self.compress(new)
        paths = new.pop("paths")
        await self.middleware.call(
            "datastore.update", self._config.datastore, id, new,
            {
                "prefix": self._config.datastore_prefix
            }
        )
        await self.middleware.call("datastore.delete", "sharing.nfs_share_path", [["share_id", "=", id]])
        for path in paths:
            await self.middleware.call(
                "datastore.insert", "sharing.nfs_share_path",
                {
                    "share_id": id,
                    "path": path,
                },
            )

        await self.extend(new)
        new["paths"] = paths

        await self.middleware.call("service.reload", "nfs")

        return new

    @accepts(Int("id"))
    async def do_delete(self, id):
        await self.middleware.call("datastore.delete", "sharing.nfs_share_path", [["share_id", "=", id]])
        await self.middleware.call("datastore.delete", self._config.datastore, id)

    @private
    async def validate(self, data, schema_name, verrors, old=None):
        if not data["paths"]:
            verrors.add(f"{schema_name}.paths", "At least one path is required")

        await self.middleware.run_in_io_thread(self.validate_paths, data, schema_name, verrors)

        filters = []
        if old:
            filters.append(["id", "!=", old["id"]])
        other_shares = await self.middleware.call("sharing.nfs.query", filters)
        dns_cache = await self.resolve_hostnames(
            sum([share["hosts"] for share in other_shares], []) + data["hosts"]
        )
        await self.middleware.run_in_io_thread(self.validate_hosts_and_networks, other_shares, data, schema_name,
                                               verrors, dns_cache)

        for k in ["maproot", "mapall"]:
            if not data[f"{k}_user"] and not data[f"{k}_group"]:
                pass
            elif not data[f"{k}_user"] and data[f"{k}_group"]:
                verrors.add(f"{schema_name}.{k}_user", "This field is required when map group is specified")
            else:
                user = await self.middleware.call("user.query", [("username", "=", data[f"{k}_user"])])
                if not user:
                    verrors.add(f"{schema_name}.{k}_user", "User not found")

                if data[f"{k}_group"]:
                    group = await self.middleware.call("group.query", [("group", "=", data[f"{k}_group"])])
                    if not group:
                        verrors.add(f"{schema_name}.{k}_group", "Group not found")

        if data["maproot_user"] and data["mapall_user"]:
            verrors.add(f"{schema_name}.mapall_user", "maproot_user disqualifies mapall_user")

        if data["security"]:
            nfs_config = await self.middleware.call("nfs.config")
            if not nfs_config["v4"]:
                verrors.add(f"{schema_name}.security", "This is not allowed when NFS v4 is disabled")

    @private
    def validate_paths(self, data, schema_name, verrors):
        dev = None
        is_mountpoint = False
        for i, path in enumerate(data["paths"]):
            stat = os.stat(path)
            if dev is None:
                dev = stat.st_dev
            else:
                if dev != stat.st_dev:
                    verrors.add(f"{schema_name}.paths.{i}",
                                "Paths for a NFS share must reside within the same filesystem")

            parent = os.path.abspath(os.path.join(path, ".."))
            if os.stat(parent).st_dev != dev:
                is_mountpoint = True
                if any(os.path.abspath(p).startswith(parent + "/") for p in data["paths"] if p != path):
                    verrors.add(f"{schema_name}.paths.{i}",
                                "You cannot share a mount point and subdirectories all at once")

        if not is_mountpoint and data["alldirs"]:
            verrors.add(f"{schema_name}.alldirs", "This option can only be used for datasets")

    @private
    async def resolve_hostnames(self, hostnames):
        hostnames = list(set(hostnames))

        async def resolve(hostname):
            try:
                return await asyncio.wait_for(self.middleware.run_in_io_thread(socket.gethostbyname, hostname), 5)
            except Exception as e:
                self.logger.warning("Unable to resolve host %r: %r", hostname, e)
                return None

        resolved_hostnames = await asyncio_map(resolve, hostnames, 8)

        return dict(zip(hostnames, resolved_hostnames))

    @private
    def validate_hosts_and_networks(self, other_shares, data, schema_name, verrors, dns_cache):
        explanation = (". This is so because /etc/exports does not act like ACL and it is undefined which rule among "
                       "all overlapping networks will be applied.")

        dev = os.stat(data["paths"][0]).st_dev

        used_networks = set()
        for share in other_shares:
            try:
                share_dev = os.stat(share["paths"][0]).st_dev
            except Exception:
                self.logger.warning("Failed to stat first path for %r", share, exc_info=True)
                continue

            if share_dev == dev:
                for host in share["hosts"]:
                    host = dns_cache[host]
                    if host is None:
                        continue

                    try:
                        network = ipaddress.IPv4Network(f"{host}/32")
                    except Exception:
                        self.logger.warning("Got invalid host %r", host)
                        continue
                    else:
                        used_networks.add(network)

                for network in share["networks"]:
                    try:
                        network = ipaddress.IPv4Network(network, strict=False)
                    except Exception:
                        self.logger.warning("Got invalid network %r", network)
                        continue
                    else:
                        used_networks.add(network)

                if not share["hosts"] and not share["networks"]:
                    used_networks.add(ipaddress.IPv4Network("0.0.0.0/0"))

                if share["alldirs"] and data["alldirs"]:
                    verrors.add(f"{schema_name}.alldirs", "This option is only available once per mountpoint")

        had_explanation = False
        for i, host in enumerate(data["hosts"]):
            host = dns_cache[host]
            if host is None:
                verrors.add(f"{schema_name}.hosts.{i}", "Unable to resolve host")
                continue

            network = ipaddress.IPv4Network(f"{host}/32")
            for another_network in used_networks:
                if network.overlaps(another_network):
                    verrors.add(
                        f"{schema_name}.hosts.{i}",
                        (f"You can't share same filesystem with overlapping networks {network} and {another_network}" +
                         ("" if had_explanation else explanation))
                    )
                    had_explanation = True

            used_networks.add(network)

        had_explanation = False
        for i, network in enumerate(data["networks"]):
            network = ipaddress.IPv4Network(network, strict=False)

            for another_network in used_networks:
                if network.overlaps(another_network):
                    verrors.add(
                        f"{schema_name}.networks.{i}",
                        (f"You can't share same filesystem with overlapping networks {network} and {another_network}" +
                         ("" if had_explanation else explanation))
                    )
                    had_explanation = True

            used_networks.add(network)

        if not data["hosts"] and not data["networks"]:
            if used_networks:
                verrors.add(
                    f"{schema_name}.networks",
                    (f"You can't share same filesystem with all hosts twice" +
                     ("" if had_explanation else explanation))
                )

    @private
    async def extend(self, data):
        data["paths"] = [path["path"]
                         for path in await self.middleware.call("datastore.query", "sharing.nfs_share_path",
                                                                [["share_id", "=", data["id"]]])]
        data["networks"] = data.pop("network").split()
        data["hosts"] = data["hosts"].split()
        data["security"] = [s.upper() for s in data["security"]]
        return data

    @private
    async def compress(self, data):
        data["network"] = " ".join(data.pop("networks"))
        data["hosts"] = " ".join(data["hosts"])
        data["security"] = [s.lower() for s in data["security"]]
        return data
