# runner.py

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-

import pexpect
import os
try:
    import urlparse
except Exception:
    import urllib.parse as urlparse
import logging
import argparse
try:
    import ConfigParser
except Exception:
    import configparser as ConfigParser
import yaml
import sys
import time

from configobj import ConfigObj, ConfigObjError


class Logger(object):
    """
    my logger tools
    """
    default_formatter = logging.Formatter(
        fmt='%(asctime)s %(levelname)-8s: %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    def __init__(self):
        pass

    @staticmethod
    def add_stream_handler(stream=sys.stdout, level=logging.INFO, formatter=default_formatter):
        logger = logging.getLogger("")
        handler = logging.StreamHandler(stream)
        handler.setFormatter(formatter)
        handler.setLevel(level)
        logger.addHandler(handler)

    @staticmethod
    def add_file_handler(logfile=None, level=logging.DEBUG, formatter=default_formatter):
        if logfile is not None:
            logger = logging.getLogger("")
            handler = logging.FileHandler(logfile, "w")
            handler.setFormatter(formatter)
            handler.setLevel(level)
            logger.addHandler(handler)

    @staticmethod
    def log_test(stream=sys.stdout, stream_level=logging.INFO, logfile=None, logfile_level=logging.DEBUG, formatter=default_formatter):
        Logger.add_file_handler(logfile, logfile_level, formatter)
        Logger.add_stream_handler(stream, stream_level, formatter)
        logger = logging.getLogger("")
        logger.setLevel(logging.DEBUG)


Logger.log_test(logfile="test.log")
cli_servers = ["telnet", "ssh", "raw", "tio"]
log = logging.getLogger("runner")


class log_pexpect(pexpect.spawn):
    def __init__(self, *args, **kwargs):
        super(log_pexpect, self).__init__(*args, **kwargs)
        self.log_test = False

    def expect(self, *args, **kwargs):
        _e = super(log_pexpect, self).expect(*args, **kwargs)
        if self.log_test:
            log.info(self.before)
        return _e

    # I did not find a way to make the telnet client not echo back our
    # commands. This workaround consumes the echo and allows this pattern:
    #         sendline("print 42")
    #         expect("42")  # match command output and not the command itself
    #         expect(prompt)
    # Without this patch,  expect("42") will match the echo first (print 42),
    # and leave the real output untouched
    def sendline(self, s='', expect_echo=True):
        n = super(log_pexpect, self).sendline(s)
        if expect_echo:
            if s:
                self.expect_exact(s)
            self.expect_exact(os.linesep)
        return n

    def set_logfile(self, logfile):
        # logfile_read contains the whole session but has the advantage over
        # logfile that it is not obfuscated by duplicated lines
        if logfile:
            self.logfile_read = open(logfile, "w")
            self.livelog = open(logfile, "r")


def validate_cli(url):
    assert url.scheme in cli_servers, "bad console type \"%s\"" % url.scheme
    assert url.netloc != "", "console server is missing"


def parse_cli_url(string):
    """Check that the argument is a supported console URL"""
    url = urlparse.urlparse(string)
    try:
        validate_cli(url)
    except AssertionError:
        log.error("%s is not a valid console URL" % string)
        raise
    return url


class TelnetCLI(log_pexpect):
    def __init__(self, cli_url, logfile=None, do_spawn=True):
        self.cli_url = parse_cli_url(cli_url)
        if not do_spawn:
            self.closed = True
            return
        cmd = " ".join(self.cmd())
        super(TelnetCLI, self).__init__(cmd)
        self.set_logfile(logfile)

        self.uboot_prompt = "=> "
        self.linux_prompt = "[rO]\S+ *[$#] |[rO]\S+ .*\][$#] "
        self.prompt = self.uboot_prompt
        # Match the last line of the telnet banner
        self.expect("Escape character is ")
        # Wait a little to make sure the connection is really open. Far away or
        # slow servers take about 1.15 seconds to reply.
        index = self.expect(["Connection closed",
                             pexpect.EOF,
                             pexpect.TIMEOUT], timeout=1.3)
        if index == 0 or self.eof():
            log.error("connection failed")
            raise pexpect.EOF(self.before + self.after)

    def cmd(self):
        host, port = self.cli_url.netloc.split(":")
        return ["telnet", host, port]

    def set_uboot_prompt(self, prompt=None):
        if not prompt:
            self.prompt = self.uboot_prompt
        else:
            self.prompt = prompt

    def set_linux_prompt(self, prompt=None):
        if not prompt:
            self.prompt = self.linux_prompt
        else:
            self.prompt = prompt

    def close(self):
        # close() in pexpect.py has one bug, it can not close telnet properly
        # in some situations, see https://bugzilla.redhat.com/show_bug.cgi?id=89653,
        # so override close() here
        if not self.closed:
            self.sendcontrol("]")
            self.expect(">", 3)
            self.sendline("quit", expect_echo=False)
            super(TelnetCLI, self).close()


class PromptNotFound(Exception):
    """An error from trying to convert a command line string to a type."""
    pass


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("config", nargs='+', help="configuration for the test")

    args = parser.parse_args()
    return args


def send_cmd(cli, cmd='', timeout=30, check_prompt=False, check_ret=False,
             expect_echo=True):
    """ Uboot command wrapper that allows multiple types of checks.

    :param cli: command line interface object
    :param cmd: command string
    :param timeout: expect timeout while waiting for prompt
    :param check_prompt: verify prompt after command execution
    :type check_prompt: boolean
    :param check_ret: verify command return code (raise error if not 0)
    :type check_ret: boolean
    :param expect_echo: expect the command echo before continuing, in order
        to avoid timeouts when incomplete echo is displayed
    :type expect_echo: boolean
    :return: command output as string (when using check_prompt or check_ret)
    """
    if not timeout:
        timeout = 30
    log.info("Sending: %s, timeout=%s, prompt=%s, ret=%s, echo=%s" % (cmd, timeout, check_prompt, check_ret, expect_echo))
    cli.sendline(cmd, expect_echo=expect_echo)
    cmd_output = None

    # These codes are workaround for unstability of LS2 simulator.
    # Comment out, or else lars needs to wait for each command 2 seconds.
    """
    # check whether the cmd has been fully sent out,
    # if not, will retry 3 times
    re_send = 3
    while re_send > 0:
        re_send -= 1
        if not valid_uboot_cmd(cli):
            log.info("Resend cmd %s" % cmd)
            cli.sendline(cmd, expect_echo=expect_echo)
        else:
            break
    """

    if check_prompt or check_ret:
        try:
            cli.expect(cli.prompt, timeout)
        except pexpect.TIMEOUT:
            log.error("Prompt not found after \"%s\"! Command output:\n%s" %
                      (cmd, cli.before))
            raise PromptNotFound("Prompt not found after \"%s\"!" % cmd)
        cmd_output = cli.before
    if check_ret:
        log.debug("Return code check")
        cli.sendline("echo $?") #check ret code
        try:
            cli.expect('^0', timeout=2)
        except pexpect.TIMEOUT:
            log.error("Command retcode non-zero for \"%s\"! Command output:\n%s" %
                      (cmd, cmd_output))
            raise Exception("Command retcode non-zero for \"%s\"!" % cmd)
        cli.expect(cli.prompt, timeout=2)
    return cmd_output


def send_uboot_cmd(cli, cmd='', timeout=30, check_prompt=False, check_ret=False,
                   expect_echo=True):
    """ Uboot command wrapper that allows multiple types of checks.

    :param cli: command line interface object
    :param cmd: command string
    :param timeout: expect timeout while waiting for prompt
    :param check_prompt: verify prompt after command execution
    :type check_prompt: boolean
    :param check_ret: verify command return code (raise error if not 0)
    :type check_ret: boolean
    :param expect_echo: expect the command echo before continuing, in order
        to avoid timeouts when incomplete echo is displayed
    :type expect_echo: boolean
    :return: command output as string (when using check_prompt or check_ret)
    """
    if not timeout:
        timeout = 30
    log.info("Sending: %s, timeout=%s, prompt=%s, ret=%s, echo=%s" % (cmd, timeout, check_prompt, check_ret, expect_echo))
    cli.sendline(cmd, expect_echo=expect_echo)
    cmd_output = None

    if check_prompt or check_ret:
        try:
            n = cli.expect([cli.prompt, "Hit any key to stop autoboot:"], timeout)
            if n == 1:
                cli.sendline("\n")
        except pexpect.TIMEOUT:
            log.error("Prompt not found after \"%s\"! Command output:\n%s" %
                      (cmd, cli.before))
            raise PromptNotFound("Prompt not found after \"%s\"!" % cmd)
        cmd_output = cli.before

    else:
        n = cli.expect([cli.prompt, "Hit any key to stop autoboot:"], timeout=300)
        if n == 1:
            cli.sendline("\n")
    if check_ret:
        log.debug("Return code check")
        cli.sendline("echo $?") #check ret code
        try:
            cli.expect('^0', timeout=2)
        except pexpect.TIMEOUT:
            log.error("Command retcode non-zero for \"%s\"! Command output:\n%s" %
                      (cmd, cmd_output))
            raise Exception("Command retcode non-zero for \"%s\"!" % cmd)
        cli.expect(cli.prompt, timeout=2)
    return cmd_output


def config_shell(cli, columns=2000):
    """Configures shell with default values - removes dependency on rootfs.
    Use this before first operation in linux console to ensure a fixed prompt
    and a convenient raw length for long commands

    :param cli: command line interface object
    :param columns: longest command line should be lower than this to avoid
        command echo issues
    """
    log.info("Configuring shell")

    try:
        send_cmd(cli, "which stty", check_ret=True)
    except Exception:
        log.warning("NO stty! Please enable CONFIG_BUSYBOX_CONFIG_STTY!")
    else:
        send_cmd(cli, "stty columns 2000", check_ret=True)

    send_cmd(cli, "export TERM=linux", check_ret=True)

    send_cmd(cli, "export EXTRACT_UNSAFE_SYMLINKS=1", check_ret=True)
    send_cmd(cli, "alias ls='ls --color=never'", check_ret=True)
    send_cmd(cli, "alias grep='grep --color=never'", check_ret=True)
    send_cmd(cli, "mkdir -p /media/ram", check_ret=True)
    send_cmd(cli, "mount -t tmpfs tmpfs /media/ram/", check_ret=True, timeout=2)


def check_boot(cli, timeout=300):
    """Checks for successful login. Verifies the kernel bootlog and logs
    warnings and errors. By default, when a fatal error is encountered
    it raises an exception

    :param cli: command line interface object
    :param cfg: board object (or any dict containing the necessary info)
    :param cont_on_error: if ``True``, continue if an error keyword is found
    :param dump_kernel_cfg: if ``True``, execute zcat /proc/config.gz cmd
    :param timeout: timeout of linux startup
    """
    fatal_errors = [
        "(?i)kernel panic",
        "(?i)Internal error: Oops:",
        "(?i)rebooting in * seconds",
        "ramdisk - allocation error"
    ]
    warnings = [
        "(?i)failed",
        "(?i)warning",
        "(?i)call trace[\s\S]*end trace"
    ]
    password = "root"
    match_list = ["login:", cli.prompt, "press Control-D to continue"] + fatal_errors + warnings
    cli.set_linux_prompt()
    log.debug("linux_prompt as %s" % cli.prompt)

    while True:
        found = cli.expect(match_list, timeout=timeout)
        if found == 0:
            # do login
            cli.sendline("root")
            found = cli.expect(["Password:", cli.prompt], timeout=30)
            if found == 0:
                cli.sendline(password, expect_echo=False)
                cli.sendline(" ")
                cli.expect(cli.prompt)
            cli.sendline(" ")
            config_shell(cli)
            break


def parse_command(cmd):
    cmds = {
        'cmd': '',
        'timeout': None,
        'check_prompt': 'False',
        'check_ret': 'False',
        'expect_echo': 'True'
    }
    if '@@' not in cmd:
        cmds['cmd'] = cmd
    else:
        plist = cmd.split('@@')
        cmds['cmd'] = plist[0]
        for i in plist[1:]:
            if '==' in i:
                k, v = i.split('==')
                if k in cmds:
                    cmds[k] = v
                else:
                    log.warning('%s is ignored in command %s' % (i, cmd))
            else:
                log.warning('%s is ignored in command %s' % (i, cmd))
    if cmds['timeout']:
        cmds['timeout'] = int(cmds['timeout'])
    if cmds['check_prompt'].lower() == "false":
        cmds['check_prompt'] = False
    else:
        cmds['check_prompt'] = True

    if cmds['check_ret'].lower() == "false":
        cmds['check_ret'] = False
    else:
        cmds['check_ret'] = True

    if cmds['expect_echo'].lower() == "false":
        cmds['expect_echo'] = False
    else:
        cmds['expect_echo'] = True

    return cmds


def run_uboot_script(cli, commands):
    cli.set_uboot_prompt()
    for cmd in commands:
        commands = parse_command(cmd)
        if commands["cmd"] == "boot":
            cli.sendline("boot")
            check_boot(cli)
        else:
            send_uboot_cmd(cli, **commands)


def run_linux_script(cli, commands):
    cli.set_linux_prompt()
    for cmd in commands:
        commands = parse_command(cmd)
        send_uboot_cmd(cli, **commands)


def get_cli(url):
    cli = TelnetCLI(url, logfile="cli.log")
    return cli

def run_config_file(yaml_file):

    with open(yaml_file, 'r') as fp:
        data_dic = yaml.safe_load(fp)
        log.info("load yaml config successfully, [%s]." % yaml_file)

        log.debug("yaml config file: %s" % yaml_file)
        url = data_dic.get("url")
        log.info("board connect url: %s" % url)
        #run_scripts(data_dic)
        try:
            cli = get_cli(url)
            uboot_cmds = data_dic.get("uboot_commands", None)
            kernel_commands = data_dic.get("kernel_commands", None)
            if uboot_cmds:
                run_uboot_script(cli, uboot_cmds)
            if kernel_commands:
                run_linux_script(cli, kernel_commands)

        finally:
            if cli:
                cli.close()
def main():
    args = parse_args()
    log.info(args)
    print(args.config)
    for config in args.config:
        run_config_file(config)


if __name__ == "__main__":
    main()
```

## Yaml Config

```yaml
uboot_commands:
  - reboot
  - pci enum
  - setenv serverip         192.168.1.1
  - setenv ethact           FM1@DTSEC5
  - dhcp
#  - dhcp a0000000 xxx/lsdk2004/OOBE-lsdk2004/images/firmware_ls1046afrwy_uboot_qspiboot.img
#  - sf probe 0:0; sf erase 0 +$filesize; sf update a0000000 0 $filesize @@timeout==900@@check_ret==true
  - dhcp a0000000 xxxx/lsdk2004/OOBE-lsdk2004/images/firmware_ls1046afrwy_uboot_sdboot.img
  - mmc write a0000000 8 1fff8 @@timeout==900@@check_ret==true
  - reset

  - setenv serverip         192.168.1.1
  - setenv ethact           FM1@DTSEC5
  - dhcp a0000000 xxxx/lsdk2004/OOBE-lsdk2004/images/firmware_ls1046afrwy_uboot_sdboot.img
  - mmc write a0000000 8 1fff8 @@timeout==900@@check_ret==true
  - reset

  # tftp kernel
  - setenv serverip         192.168.1.1
  - setenv ethact           FM1@DTSEC5
  - dhcp
  - setenv othbootargs      console=ttyS0,115200  earlycon=uart8250,mmio,0x21c0500  ramdisk_size=0x40000000
  - setenv bootargs root=/dev/ram0 rw $othbootargs ip=dhcp
  - tftpboot a0000000 xxxx/lsdk2004/OOBE-lsdk2004/images/lsdk2004_yocto_tiny_LS_arm64.itb @@timeout==900@@check_ret==true
  - setenv bootcmd "bootm a0000000#ls1046afrwy"
  - boot
kernel_commands:
  - uname -a
  - cat /proc/cmdline
  - ping 192.168.1.2 -c 3
  - echo "nameserver 192.168.1.1" > /etc/resolv.conf
  - flex-installer -v
  - flex-installer -i pf -F -d /dev/mmcblk0 @@timeout==900@@check_ret==true

url: "telnet://192.168.1.3:9999"
```

