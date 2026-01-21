#
# (c) 2017 Red Hat Inc.
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

DOCUMENTATION = """
author:
- Ansible Networking Team (@ansible-network)
- Raylan (@jraylan)
name: vsololt
short_description: Use vsol olt cliconf to run command on vsol OLT platform
description:
- This plugin provides low level abstraction apis for sending and receiving
  CLI commands from vsol OLTs.
version_added: 0.1.0
"""

EXAMPLES = """

"""

import json
import re

from ansible.module_utils.six import PY3

from ansible.errors import AnsibleConnectionFailure
from ansible.module_utils._text import to_text

if PY3:
    from collections.abc import Mapping
else:
    from ansible.module_utils.common\
        ._collections_compat import Mapping  # type: ignore

from ansible_collections.ansible.netcommon\
    .plugins.module_utils.network.common.config import NetworkConfig, dumps
from ansible_collections.ansible.netcommon\
    .plugins.module_utils.network.common.utils import to_list
from ansible_collections.ansible.netcommon\
    .plugins.plugin_utils.cliconf_base import CliconfBase, enable_mode


class Cliconf(CliconfBase):
    def __init__(self, *args, **kwargs):
        self._device_info = {}
        super(Cliconf, self).__init__(*args, **kwargs)

    @enable_mode
    def get_config(self, source="current", flags=None, format=None):
        if source not in ("current", "saved"):
            raise ValueError(
                "fetching %s configuration is not supported" % source
            )

        if format:
            raise ValueError(
                "'format' value %s is not supported for get_config" % format
            )

        if not flags:
            flags = []
        if source == "current":
            cmd = "display current-config"
        else:
            cmd = "display saved-config"

        cmd += " ".join(to_list(flags))
        cmd = cmd.strip()

        return self.send_command(cmd)

    def get_diff(
        self,
        candidate=None,
        running=None,
        diff_match="line",
        diff_ignore_lines=None,
        path=None,
        diff_replace="line",
    ):
        """
        Generate diff between candidate and running configuration. If
        the remote host supports onbox diff capabilities ie.
        supports_onbox_diff in that case candidate and running
        configurations are not required to be passed as argument.
        In case if onbox diff capability is not supported candidate
        argument is mandatory and running argument is optional.
        :param candidate: The configuration which is expected to be
                    present on remote host.
        :param running: The base configuration which is used to generate
                    diff.
        :param diff_match: Instructs how to match the candidate
                    configuration with current device configuration
                    Valid values are 'line', 'strict', 'exact', 'none'.
                    'line' - commands are matched line by line
                    'strict' - command lines are matched with respect
                    to position
                    'exact' - command lines must be an equal match
                    'none' - will not compare the candidate
                    configuration with the running configuration
        :param diff_ignore_lines: Use this argument to specify one or
                    more lines that should be
                    ignored during the diff.  This is used for lines
                    in the configuration that are automatically
                    updated by the system.  This argument takes a list
                    of regular expressions or exact line matches.
        :param path: The ordered set of parents that uniquely identify
                    the section or hierarchy the commands should be
                    checked against.  If the parents argument
                    is omitted, the commands are checked against the set
                    of top level or global commands.
        :param diff_replace: Instructs on the way to perform the
                    configuration on the device.
                    If the replace argument is set to I(line) then the
                    modified lines are pushed to the device in
                    configuration mode.  If the replace argument is set
                    to I(block) then the entire command block is pushed
                    to the device in configuration mode if any line is
                    not correct.
        :return: Configuration diff in  json format.
               {
                   'config_diff': ''
               }
        """
        diff = {}
        device_operations = self.get_device_operations()
        option_values = self.get_option_values()

        if candidate is None and device_operations["supports_generate_diff"]:
            raise ValueError(
                "candidate configuration is required to generate diff"
            )

        if diff_match not in option_values["diff_match"]:
            raise ValueError(
                "'match' value %s in invalid, valid values are %s"
                % (diff_match, ", ".join(option_values["diff_match"])),
            )

        if diff_replace not in option_values["diff_replace"]:
            raise ValueError(
                "'replace' value %s in invalid, valid values are %s"
                % (diff_replace, ", ".join(option_values["diff_replace"])),
            )

        # prepare candidate configuration
        candidate_obj = NetworkConfig(indent=0)
        candidate_obj.load(candidate)

        if running and diff_match != "none":
            # running configuration
            running_obj = NetworkConfig(
                indent=1, contents=running, ignore_lines=diff_ignore_lines
            )
            config_diff_objs = candidate_obj.difference(
                running_obj,
                path=path,
                match=diff_match,
                replace=diff_replace,
            )
        else:
            config_diff_objs = candidate_obj.items

        diff["config_diff"] = (
            dumps(config_diff_objs, "commands") if config_diff_objs else ""
        )
        return diff

    @enable_mode
    def configure(self):
        """
        Enter global configuration mode based on the
        status of commit_confirm
        :return: None
        """
        self.send_command("configure terminal")

    @enable_mode
    def edit_config(
        self, candidate=None, commit=True, replace=None, comment=None,
    ):
        resp = {}
        operations = self.get_device_operations()
        self.check_edit_config_capability(
            operations, candidate, commit, replace, comment
        )

        results = []
        requests = []
        # commit confirm specific attributes
        commit_confirm = self.get_option("commit_confirm_immediate")
        if commit:
            self.configure()
            for line in to_list(candidate):
                if not isinstance(line, Mapping):
                    line = {"command": line}

                cmd = line["command"]
                if cmd != "end" and cmd[0] != "!":
                    results.append(self.send_command(**line))
                    requests.append(cmd)

            self.send_command("end")
            if commit_confirm:
                self.send_command("configure confirm")

        else:
            raise ValueError("check mode is not supported")

        resp["request"] = requests
        resp["response"] = results
        return resp

    def get(
        self,
        command=None,
        prompt=None,
        answer=None,
        sendonly=False,
        newline=True,
        output=None,
        check_all=False,
    ):
        if not command:
            raise ValueError("must provide value of command to execute")
        if output:
            raise ValueError(
                "'output' value %s is not supported for get" % output
            )

        return self.send_command(
            command=command,
            prompt=prompt,
            answer=answer,
            sendonly=sendonly,
            newline=newline,
            check_all=check_all,
        )

    def _get_info_value(self, data, key):
        pattern = re.compile(
            r'^\s+' + key + r'\s+:\s+([^\s]*)\s*$'
        )

        match = pattern.search(data)

        if match:
            return match.group(1) or ''

        return ""

    def get_device_info(self):
        if not self._device_info:
            device_info = {
                "network_os": "vsol",
                "network_os_version": "",
                "network_os_model": "",
                "network_os_hostname": "",
                "network_os_image": "",
                "network_os_platform": "vsol Integrated Access Software",
                "network_os_type": "OLT"
            }

            reply = self.get(command="display version")
            data = to_text(reply, errors="surrogate_or_strict").strip()

            device_info["network_os_version"] = self._get_info_value(
                data, 'VERSION')

            device_info["network_os_model"] = self._get_info_value(
                data, 'PRODUCT')

            device_info["network_os_image"] = self._get_info_value(
                data, 'PATCH')

            self._device_info = device_info

        return self._device_info

    def get_device_operations(self):
        return {
            "supports_diff_replace": False,
            "supports_commit": False,
            "supports_rollback": False,
            "supports_defaults": True,
            "supports_onbox_diff": False,
            "supports_commit_comment": False,
            "supports_multiline_delimiter": False,
            "supports_diff_match": False,
            "supports_diff_ignore_lines": False,
            "supports_generate_diff": False,
            "supports_replace": False,
        }

    def get_option_values(self):
        return {
            "format": ["text"],
            "diff_match": ["line", "strict", "exact", "none"],
            "diff_replace": ["line", "block"],
            "output": [],
        }

    def get_capabilities(self):
        result = super(Cliconf, self).get_capabilities()

        if "run_commands" not in result["rpc"]:
            result["rpc"] += [
                "run_commands",
            ]
        result["device_operations"] = self.get_device_operations()
        result.update(self.get_option_values())
        return json.dumps(result)

    def run_commands(self, commands=None, check_rc=True):
        if commands is None:
            raise ValueError("'commands' value is required")

        responses = list()
        for cmd in to_list(commands):
            if not isinstance(cmd, Mapping):
                cmd = {"command": cmd}

            output = cmd.pop("output", None)
            if output:
                raise ValueError(
                    "'output' value %s is not supported for run_commands"
                    % output
                )

            try:
                out = self.send_command(**cmd)
            except AnsibleConnectionFailure as e:
                if check_rc:
                    raise
                out = getattr(e, "err", to_text(e))

            responses.append(out)

        return responses

    def get_defaults_flag(self):
        """
        The method identifies the filter that should be used to fetch
        running-configuration with defaults.
        :return: valid default filter
        """
        out = self.get("display running-config ?")
        out = to_text(out, errors="surrogate_then_replace")

        commands = set()
        for line in out.splitlines():
            if line.strip():
                commands.add(line.strip().split()[0])

        if "include-default" in commands:
            return "include-default"
        else:
            return ""

    def set_cli_prompt_context(self):
        """
        Make sure we are in the operational cli mode
        :return: None
        """
        if self._connection.connected:
            out = self._connection.get_prompt()

            if out is None:
                raise AnsibleConnectionFailure(
                    message="cli prompt is not identified from the "
                    "last received response window: %s"
                    % self._connection._last_recv_window,
                )

            if re.search(
                r"(config)#",
                to_text(out, errors="surrogate_then_replace").strip(),
            ):
                self._connection.queue_message(
                    "vvvv", "wrong context, sending quit to device"
                )
                self._connection.send_command("quit")
