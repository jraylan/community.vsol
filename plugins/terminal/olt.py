#
# (c) 2016 Red Hat Inc.
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
#
from __future__ import absolute_import, division, print_function


__metaclass__ = type

import json
import re

from ansible.errors import AnsibleConnectionFailure
from ansible.module_utils._text import to_bytes, to_text
from ansible.utils.display import Display
from ansible_collections.ansible.netcommon.plugins\
                        .plugin_utils.terminal_base import TerminalBase


display = Display()


class TerminalModule(TerminalBase):

    login_prompt = re.compile(
        rb"^[lL]ogin: ?$",
        re.M,
    )

    password_prompt = re.compile(
        rb"^[pP]assword: ?$",
        re.M,
    )

    terminal_stdout_re = [
        re.compile(
            rb"[\r\n]?^[\w\+\-\.:\/\[\]]+(?:\(config+\))?(?:[>#]) ?"
            rb"(([^\r\n]+\x00)|)$",
            re.M,
        ),
        login_prompt,
        password_prompt,
    ]

    #: compiled bytes regular expressions to remove ANSI codes
    ansi_re = [
        re.compile(rb"\x1b\[\?1h\x1b="),  # CSI ? 1 h ESC =
        re.compile(rb"\x08."),  # [Backspace] .
        re.compile(rb"\x1b\[m"),  # ANSI reset code
        re.compile(
            rb"[\n\r]?^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\s+[A-Za-z]*.*$",
            re.M,
        ),  # Logging info
    ]

    terminal_stderr_re = [
        # Command error
        re.compile(
            rb"^\% .*\.$",
            re.M
        ),
        # Logging info
        re.compile(
            rb"^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\s+[A-Za-z]*.*$",
            re.M,
        ),
    ]

    terminal_initial_prompt = [
        rb"[\r\n]?^[\w\+\-\.:\/\[\]]+(?:\(config+\))?(?:[>#]) ?$",
    ]

    terminal_config_prompt = re.compile(r"^.+\(config\)#$")

    def _exec_cli_command(self, cmd, check_rc=True):
        """
        Executes the CLI command on the remote device and returns
        the output

        :arg cmd: Byte string command to be executed
        """
        result = self._connection.exec_command(cmd)

        if isinstance(result, memoryview):
            result = result.tobytes()

        if isinstance(result, bytes):
            result = result.decode("utf-8", errors="ignore").encode("utf-8")

        elif isinstance(result, str):
            result = result.encode("utf-8", errors="ignore")

        return result

    def get_privilege_level(self):
        prompt = self._get_prompt()
        return 1 + prompt.endswith(b"#") * 14

    def _get_user(self):
        return (
            getattr(self._connection, "user")
            or self._connection._play_context.remote_user
        )

    def _get_password(self):
        return self._connection._play_context.password

    def _get_become_password(self):
        return (
            self._connection.become.get_option(
                'become_pass',
                playcontext=self._connection._play_context,
            ) or self._get_password()
        )

    def _exec_login(self):
        prompt = self._get_prompt()

        if self.login_prompt.search(prompt):
            self._exec_cli_command(to_bytes(self._get_user()))
            prompt = self._get_prompt()

        if self.password_prompt.search(prompt):
            self._exec_cli_command(to_bytes(self._get_password()))

    def on_open_shell(self):
        self._exec_login()
        self._exec_cli_command(b"enable")
        self.on_become(passwd=self._get_become_password())
        self._exec_cli_command(b"terminal length 0")

    def on_become(self, passwd=None):
        if (
            self._get_prompt().endswith(b"#")
            and self.get_privilege_level() == 15
        ):
            return

        cmd = {"command": "enable"}
        if passwd:
            # Note: python-3.5 cannot combine u"" and r"" together.
            # Thus make an r string and use to_text to ensure it's text
            # on both py2 and py3.
            cmd["prompt"] = to_text(
                r"[\r\n]?(?:.*)?[Pp]assword: ?$",
                errors="surrogate_or_strict",
            )
            cmd["answer"] = passwd
            cmd["prompt_retry_check"] = True  # type: ignore
        try:
            self._exec_cli_command(
                to_bytes(json.dumps(cmd), errors="surrogate_or_strict"),
            )
            prompt = self._get_prompt()
            privilege_level = self.get_privilege_level()
        except AnsibleConnectionFailure as e:
            prompt = self._get_prompt()
            raise AnsibleConnectionFailure(
                "failed to elevate privilege to enable mode, "
                "at prompt [%s] with error: %s"
                % (prompt, e.message),
            )

        if (
            prompt is None
            or not prompt.endswith(b"#")
            or privilege_level != 15
        ):
            raise AnsibleConnectionFailure(
                "failed to elevate privilege to enable mode, still at level "
                "[%d] and prompt [%s]"
                % (privilege_level, prompt),
            )

    def on_unbecome(self):
        prompt = self._get_prompt()
        if prompt is None:
            # if prompt is None most likely the terminal is hung up at a prompt
            return

        if self.get_privilege_level() != 15:
            return

        if prompt.endswith(b"(config)#"):
            self._exec_cli_command(b"quit")

        if prompt.endswith(b"#"):
            self._exec_cli_command(b"disable")
