#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import re
import socket
import subprocess
from pathlib import Path
from paramiko import (Transport, RSAKey, SFTPClient, SSHClient, AutoAddPolicy)

from kyori2.command import Command
from kyori2 import logger

__all__ = ["Local", "RemoteHost"]


class CommonCommandUtil:

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


class RemoteHost(Transport, CommonCommandUtil):
    __slots__ = ("hostname", "port", "username", "password", "connected")

    def __init__(self,
                 hostname,
                 user="root",
                 password=None,
                 pkey=None,
                 port=22,
                 label="default"):

        self.port = port
        self.hostname = hostname
        self._sock = (hostname, port)
        self.user = user
        self.label = label
        self.password = password

        if pkey:
            self.pkey = RSAKey.from_private_key(open(pkey))

        self.active = False
        self.connected = False

    def __str__(self):
        return f"<RemoteHost: {self.label}:{self.user}@{ self.hostname}>"

    def __repr__(self) -> str:
        return f"<RemoteHost: {self.label}:{self.user}@{ self.hostname}>"

    def __del__(self):
        self.close()

    @property
    def sftp(self) -> SFTPClient:
        return SFTPClient.from_transport(self)

    @property
    def ssh(self) -> SSHClient:
        ssh = SSHClient()
        ssh.set_missing_host_key_policy(AutoAddPolicy())
        ssh._transport = self
        return ssh

    def check_connectivity(self, timeout=1):
        flag = True
        skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        skt.settimeout(timeout)
        try:
            skt.connect(self._sock)
            skt.shutdown(socket.SHUT_RDWR)
        except Exception as e:
            flag = False
        finally:
            skt.close()
        return flag

    def initial(self) -> bool:
        info = {"username": self.user}
        if self.password:
            info.update({"password": self.password})
        elif self.pkey:
            info.update({"pkey": self.pkey})
        else:
            return self.connected

        try:
            super().__init__(self._sock)
            logger.debug(info)
            self.connect(**info)
            self.connected = True
            logger.debug(f"SSH connect succeed:{self}")
        except Exception as e:
            self.connected = False
            logger.exception(f"SSH connect failed:{self}, {e}")

        if self.connected:
            # 密码过期检查
            cmd = Command("uptime", stringify=True)
            self.exec(cmd)
            if "expired" in cmd.error:
                self.connected = False

        return self.connected

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
        self.connected = False
        super(RemoteHost, self).close()
        logger.debug(f"Server disconnected: {self}")
