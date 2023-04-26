#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import re
import socket
import subprocess
from pathlib import Path
from paramiko import (Transport, RSAKey, SFTPClient, SSHClient)

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
            out = p.stdout.read()
            err = p.stderr.read()
        except Exception as e:
            cmd.exception = e
            logger.debug(cmd.exception)
            return

        if cmd.stringify:
            out = out.decode()
            err = err.decode()

        if out:
            cmd.output = out
        # verbose开关
        elif err:
            cmd.error = err

        logger.debug(out)
        logger.debug(err)
        cmd.status_code = int(p.wait())
        logger.debug(cmd.status_code)

    def getcwd(self):
        return self.exec("pwd")


class RemoteHost(Transport, CommonCommandUtil):
    __slots__ = ("hostname", "port", "username", "password", "connected")

    def __init__(self,
                 hostname,
                 user="root",
                 password=None,
                 key=None,
                 port=22,
                 label="default"):

        self.port = port
        self.hostname = hostname

        self._sock = (hostname, port)

        self.user = user
        self.label = label
        self.key = key
        self.password = password

        self.connected = False
        self.debug_info = None

    def __str__(self):
        return "<RemoteHost: {}:{}@{}>".format(self.label, self.user,
                                               self.hostname)

    @property
    def sftp(self) -> SFTPClient:
        return SFTPClient.from_transport(self)

    @property
    def ssh(self) -> SSHClient:
        ssh = SSHClient()
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
        # SSHClient.set_missing_host_key_policy(AutoAddPolicy())
        succ = "SSH connect succeed:{}".format(self)
        fail = "SSH connect failed:{}".format(self)

        if self.password:
            info = {"username": self.user, "password": self.password}
        elif self.key:
            info = {
                "username": self.user,
                "pkey": RSAKey.from_private_key_file(self.key)
            }
        else:
            return self.connected

        try:
            super().__init__(self._sock)
            self.connect(**info)
            self.connected = True
            logger.debug(succ)

        except Exception as e:
            self.connected = False
            self.debug_info = "{}, {}".format(fail, e)
            logger.exception(fail, e)

        if self.connected:
            # 密码过期检查
            cmd = Command("ls", stringify=True)
            self.execute(cmd)
            if "expired" in cmd.error:
                self.debug_info = "{}, {}".format(fail, cmd.error)
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
            out = stdout.read()
            err = stderr.read()
            if cmd.stringify:
                out = out.decode()
                err = err.decode()
            logger.debug(out)
            logger.debug(err)
            cmd.output = out
            cmd.error = err
            cmd.status_code = int(stdout.channel.recv_exit_status())
            logger.debug(cmd.status_code)
        except Exception as e:
            cmd.output = ""
            cmd.error = f"Server execute command failed: {e}"
            cmd.status_code = 1
            logger.exception(cmd.error, e)

    def exec(self, cmd, real_time=False, timeout=30):
        logger.debug(cmd.cwd)
        if cmd.cwd:
            cmd.content = """cd '{}' && """.format(cmd.cwd) + cmd.content

        msg = "Server execute {} on {}".format(cmd, self)
        logger.debug(msg)
        if real_time:
            self.exec_real_time(cmd, timeout)
        else:
            self.exec_wait(cmd, timeout)

    def dir_exist(self, fd):
        """检查目录是否存在"""
        try:
            self.sftp.stat(fd)
            return True
        except IOError:
            return False

    def close(self):
        disconnected = "Server disconnected:{}".format(self)
        self.connected = False
        super(RemoteHost, self).close()
        logger.debug(disconnected)

    def __del__(self):
        self.close()