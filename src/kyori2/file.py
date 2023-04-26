#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import re
import time

from kyori2.command import Command
from kyori2 import logger

__all__ = ["RemoteFile", "RemoteConfigFile"]

backup_time = time.strftime('%Y%m%d%H%M%S', time.localtime(time.time()))


class RemoteFile(object):

    def __init__(self, host, file_path, backup_path="/tmp"):
        self.host = host
        self.path = file_path
        self.backup_path = backup_path
        self.encoding = "utf8"

        self.comment_symbol = ["#", ";", "//"]

    def __str__(self) -> str:
        return f"<RemoteFile: {self.host.user}@{self.host.hostname}:{self.path}>"

    def __repr__(self) -> str:
        return f"<RemoteFile: {self.host.user}@{self.host.hostname}:{self.path}>"

    @property
    def file(self):
        return self.host.sftp.open(self.path, "r")

    def readall(self):
        if self.encoding:
            return self.file.read().decode(self.encoding)
        else:
            return self.file.read()

    def readlines(self):
        return self.file.readlines()

    def close(self):
        try:
            self.file.close()
        except Exception as e:
            pass

    def write_line(self, line):
        if not line.endswith("\n"):
            line += "\n"
        self.write(line, "a")

    def write(self, _str, _mode="w+"):
        logger.debug("Write file:{}".format(self.__str__()))
        with self.host.sftp.open(self.path, _mode) as f:
            f.write(_str)

    def line_array(self, pattern=r"\s"):
        """
        通过pattern参数将文件的每一行进行分割。
        通常情况下，配置文件有一些注释行，可能以["#", ";", "//"]作为每行的行首
        故在遍历每行时再遍历收集到的注释行行首列表，与行进行匹配，True时将整行添加到缓存_t列表中，
        若注释行行首列表遍历完毕，依然没有退出则对行进行分割后添加到缓存列表_t中
        :param pattern: 用于分割行的字符
        :return: 分割和清洗后的数组
        """
        lines = self.readlines()
        _t = list()
        for line in lines:
            for s in self.comment_symbol:
                if line.startswith(s):
                    _t.append(line)
                    break
            else:
                _t.append(filter(None, re.split(pattern, line)))
        return _t

    def remove_line(self, _str):
        fs = self.file.readlines()
        t = ""
        for line in fs:
            if _str in line:
                continue
            else:
                t += line
        self.write(t)

    def backup(self):
        bk_path = self.backup_path
        src = self.path
        dest = self.backup_path + "/" + src.split("/")[-1] + "_" + backup_time
        cmd = Command("cp {} {}".format(src, dest))

        # 检查目录是否存在
        # 通过异常捕获进行创建目录
        try:
            self.host.sftp.stat(bk_path)
        except IOError:
            self.host.sftp.mkdir(bk_path)
        self.host.execute(cmd)


class RemoteConfigFile(RemoteFile):

    def __init__(self, host, file_path, backup_path="/tmp", pattern=r"="):
        super(RemoteConfigFile, self).__init__(host, file_path, backup_path)
        # pattern变量是配置文件中连接配置项和值的符号，通常情况下有：r"="，r" "，r"："
        self.pattern = pattern

    def configure(self, configuration):
        content = []
        pattern = self.pattern
        key_value_str = "{}{}{}\n"
        # 如果pattern变量没有得到赋值，将会抛出异常，终止程序
        if not pattern:
            raise

        for line in self.readlines():
            # 通过指定的字符分隔，获取当前行的数组
            array = line.split(pattern)
            # 清除键值中的前导和后导空格
            array = list(map(lambda x: x.strip(), array))
            # 遍历所有待配置的键和值
            for key, value in configuration.items():
                # 当前行数组中的的第一个元素等于待配置的键时
                # 将此行完整的替换为带配置的键和值，并且从待配置列表中移除此配置项
                # 跳出此次配置遍历
                if array[0] == key:
                    content.append(key_value_str.format(key, pattern, value))
                    configuration.pop(key)
                    break
            # 所有配置项都遍历结束后，将当前行写回
            else:
                content.append(line)
        # 所有配置检查完毕后，将剩余的未配置项以追加的方式写入到配置文件末尾
        if configuration:
            for key, value in configuration.items():
                if not content[-1].endswith("\n"):
                    content[-1] = content[-1] + "\n"
                content.append(key_value_str.format(key, pattern, value))

        self.write("".join(content))
        self.close()

    def replace(self, configuration):
        context = self.readall()
        for key, value in configuration.items():
            context = re.sub(str(key), str(value), context)
        self.write(context)
        self.close()
