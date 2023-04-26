#!/usr/bin/env python
# -*- coding: UTF-8 -*-
__all__ = ["Command"]


class Command:

    def __init__(self, content, cwd=None, stringify=False):
        self.content = content
        # self.cwd = cwd if cwd else cfg.PROGRAM_PATH
        self.cwd = cwd
        self.normal = ""
        self.error = ""
        self.status_code = -1
        self.exception = None
        self.stringify = stringify
        self.output = ""

    # @property
    # def output(self):
    #     return self._output
    #
    # @output.setter
    # def output(self, val):
    #     if not val:
    #         self._output = ""
    #     if self.stringify:
    #         self._output = str(val)
    #     else:
    #         self._output = ""

    def lines(self):
        if self.output:
            lines = self.output.split("\n")
            lines.remove("")
            return lines
        else:
            return []

    def array(self):
        return [filter(None, line.split(" ")) for line in self.lines()]

    def __str__(self):
        return "<Command: {}>".format(self.content)
