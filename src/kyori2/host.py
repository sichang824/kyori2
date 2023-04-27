#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import re
import socket
import subprocess
from pathlib import Path
from paramiko import (RSAKey, SFTPClient, SSHClient, AutoAddPolicy)
from errno import ECONNREFUSED, EHOSTUNREACH
from paramiko.ssh_exception import (BadHostKeyException,
                                    NoValidConnectionsError)
from kyori2.command import Command
from kyori2 import logger

__all__ = ["Local", "RemoteHost"]


class CommonCommandUtil:

    def families_and_addresses(self, hostname, port):
        """
        Yield pairs of address families and addresses to try for connecting.

        :param str hostname: the server to connect to
        :param int port: the server port to connect to
        :returns: Yields an iterable of ``(family, address)`` tuples
        """
        guess = True
        addrinfos = socket.getaddrinfo(hostname, port, socket.AF_UNSPEC,
                                       socket.SOCK_STREAM)
        for (family, socktype, proto, canonname, sockaddr) in addrinfos:
            if socktype == socket.SOCK_STREAM:
                yield family, sockaddr
                guess = False

        # some OS like AIX don't indicate SOCK_STREAM support, so just
        # guess. :(  We only do this if we did not get a single result marked
        # as socktype == SOCK_STREAM.
        if guess:
            for family, _, _, _, sockaddr in addrinfos:
                yield family, sockaddr

    def check_connectivity(self, hostname, port, retries=1, timeout=1):

        errors = {}
        to_try = list(self.families_and_addresses(hostname, 1234)) * retries
        for af, addr in to_try:
            try:
                sock = socket.socket(af, socket.SOCK_STREAM)
                if timeout is not None:
                    try:
                        sock.settimeout(timeout)
                    except:
                        pass
                assert sock.connect_ex(addr) == 0
                # Break out of the loop on success
                break
            except socket.error as e:
                # As mentioned in socket docs it is better
                # to close sockets explicitly
                if sock:
                    sock.close()
                # Raise anything that isn't a straight up connection error
                # (such as a resolution error)
                if e.errno not in (ECONNREFUSED, EHOSTUNREACH):
                    raise
                # Capture anything else so we know how the run looks once
                # iteration is complete. Retain info about which attempt
                # this was.
                errors[addr] = e

        # Make sure we explode usefully if no address family attempts
        # succeeded. We've no way of knowing which error is the "right"
        # one, so we construct a hybrid exception containing all the real
        # ones, of a subclass that client code should still be watching for
        # (socket.error)

        if len(errors) == len(to_try):
            raise NoValidConnectionsError(errors)

        return True

    def md5sum(self, path):
        cmd = Command(f"md5sum '{path}'", stringify=True)
        self.exec(cmd)
        md5 = re.split(r"\s", cmd.output)[0]
        return md5

    def checksum(self,
                 local_path: Path,
                 remote_path: Path,
                 hash_algorithm: str = "md5") -> bool:

        if hash_algorithm == "md5":
            cmd = """md5sum '{}'"""
        else:
            cmd = """md5sum '{}'"""

        stdin, stdout, stderr = self.ssh.exec_command(
            cmd.format(str(remote_path)))
        remote_data = stdout.read().decode('utf8')
        remote_md5 = re.split(r"\s", remote_data)[0]
        local_md5 = self.md5sum(local_path)
        return remote_md5 == local_md5

    def is_ip(self, ip):
        """
        判断是否ip
        :param
        ip: "192.1.1.1"
        :return:boolean
        """
        rule = re.compile(
            r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
        )
        if rule.match(ip):
            return True
        else:
            return False


class Local(CommonCommandUtil):

    def __init__(self):
        pass

    def exec(self, cmd, cwd: str = None, shell=True, timeout=30):
        try:
            p = subprocess.Popen(
                cmd.content,
                shell=shell,
                cwd=cwd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            out, err, ret = p.stdout.read(), p.stderr.read(), int(p.wait())
        except Exception as e:
            cmd.exception = e
            cmd.status_code = 1
            logger.debug(cmd.exception)
            return

        logger.debug(f"Return code: {cmd.status_code}, out: {out}, err: {err}")

        if cmd.stringify: out, err = out.decode(), err.decode()
        cmd.output, cmd.error, cmd.status_code = out, err, ret

    def getcwd(self):
        return self.exec("pwd")


class RemoteHost(SSHClient, CommonCommandUtil):
    __slots__ = ("hostname", "port", "username", "password", "connected")

    def __init__(self,
                 hostname,
                 user="root",
                 password=None,
                 pkey=None,
                 port=22,
                 label="default") -> None:

        self.port = port
        self.hostname = hostname
        self.user = user
        self.label = label
        self.password = password

        self.connected = False
        self._sock = (hostname, int(port))
        self._ssh = None
        self._sftp = None

        super().__init__()

        # 需要再之后进行设置
        if pkey:
            self.pkey = RSAKey.from_private_key(open(pkey))
        self.set_missing_host_key_policy(AutoAddPolicy())

    def __str__(self):
        return f"<RemoteHost: {self.label}:{self.user}@{ self.hostname}>"

    def __repr__(self) -> str:
        return f"<RemoteHost: {self.label}:{self.user}@{ self.hostname}>"

    def __del__(self):
        self.close()

    def connect(self) -> None:
        info = {
            "hostname": self.hostname,
            "username": self.user,
            "port": self.port,
            "timeout": 3,  # tcp timeout
            "auth_timeout": 3,
            "banner_timeout": 3,
        }

        logger.debug(f"SSH connect: {info}")

        if self.password:
            info.update({"password": self.password})
        elif self.pkey:
            info.update({"pkey": self.pkey})
        else:
            raise BadHostKeyException(self.hostname, None, None)

        super().connect(**info)
        self.connected = True

        if self.connected:
            self.check_expired()

    @property
    def sftp(self) -> SFTPClient:
        return SFTPClient.from_transport(self.get_transport())

    @property
    def ssh(self) -> SSHClient:
        return self

    def check_expired(self):
        # 密码过期检查
        cmd = Command("uptime", stringify=True)
        self.exec(cmd)
        if "expired" in cmd.error:
            self.close()
            self.connected = False
            raise Exception("password expired.")

    def check_connectivity(self, timeout=3):
        super().check_connectivity(self.hostname, self.port, timeout)

        cmd = Command("uptime", stringify=True)
        try:
            self.exec(cmd, timeout=3)
            return True
        except:
            self.close()
            return False

    def validate(self):
        if not self.is_ip(self.hostname):
            return False
        if all([self.hostname, self.port, self.username, self.password]):
            return True
        if not self.is_ip(self.hostname):
            return False

    def exec_real_time(self, cmd, timeout):
        stdin, stdout, stderr = self.ssh.exec_command(cmd.content,
                                                      bufsize=1,
                                                      timeout=timeout)
        logger.debug(stdin, stdout, stderr)
        for out in iter(stdout.readline, ""):
            _t = out.encode("utf-8")
            # display.default(_t)
            cmd.output += _t

        for err in iter(stderr.readline, ""):
            _t = err.encode("utf-8")
            # display.error(_t)
            cmd.error += _t
        cmd.status_code = int(stdout.channel.recv_exit_status())

    def exec_wait(self, cmd, timeout):
        try:
            stdin, stdout, stderr = self.ssh.exec_command(cmd.content,
                                                          timeout=timeout)
            out, err = stdout.read(), stderr.read()
            ret = int(stdout.channel.recv_exit_status())
        except Exception as e:
            cmd.output = ""
            cmd.error = f"Server execute command failed: {e}"
            cmd.status_code = 1
            logger.exception(cmd.error)
            return

        logger.debug(f"Return code: {ret}, out: {out}, err: {err}")

        if cmd.stringify: out, err = out.decode(), err.decode()
        cmd.output, cmd.error, cmd.status_code = out, err, ret

    def exec(self, cmd, real_time=False, timeout=30):
        logger.debug(f"work dir: {cmd.cwd}")

        if cmd.cwd:
            cmd.content = """cd '{}' && """.format(cmd.cwd) + cmd.content

        logger.debug(f"Server execute {cmd} on {self}")
        if real_time:
            self.exec_real_time(cmd, timeout)
        else:
            self.exec_wait(cmd, timeout)

    def close(self):
        self._ssh = None
        self._sftp = None
        self.connected = False
        logger.debug(f"Server disconnected: {self}")
        return super().close()
