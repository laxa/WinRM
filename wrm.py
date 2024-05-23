#!/usr/bin/env python3

from winrm.protocol import Protocol
from winrm.exceptions import WinRMOperationTimeoutError
import argparse
import sys
import logging
import re
import cmd
from spnego import NTLMHash

target_regex = re.compile(r"(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)")

def parse_target(target):
    """ Helper function to parse target information. The expected format is:

    <DOMAIN></USERNAME><:PASSWORD>@HOSTNAME

    :param target: target to parse
    :type target: string

    :return: tuple of domain, username, password and remote name or IP address
    :rtype: (string, string, string, string)
    """
    domain, username, password, remote_name = target_regex.match(target).groups('')

    # In case the password contains '@'
    if '@' in remote_name:
        password = password + '@' + remote_name.rpartition('@')[0]
        remote_name = remote_name.rpartition('@')[2]

    return domain, username, password, remote_name

class WinRMShell(cmd.Cmd):
    def __init__(self, client):
        cmd.Cmd.__init__(self)
        self.shell = None
        self.client = client
        self.prompt = '> '
        self.completion = []
        self.shell_id = self.client.open_shell()
        # command_id = self.client.run_command(self.shell_id, 'powershell', [])
        # std_out, std_err, status_code = self.get_command_output(self.shell_id, command_id, wait=False)
        # self.prompt = std_out.decode().rstrip().split('\n')[-1] + ' '
    
    def default(self, line):
        cmd = line.split()[0]
        args = line.split()[1:]
        command_id = self.client.run_command(self.shell_id, cmd, args)
        std_out, std_err, status_code = self.get_command_output(self.shell_id, command_id, wait=False)
        err = std_err.decode().rstrip()
        logging.debug(f'[{status_code}]: {err}')
        output = std_out.decode().rstrip()
        if len(output) > 0:
            print(output)
        if len(err) > 0:
            print(err)
        self.client.cleanup_command(self.shell_id, command_id)

    def do_exit(self, line):
        self.client.close_shell(self.shell_id)
        return True

    def do_EOF(self, line):
        self.client.close_shell(self.shell_id)
        print('')
        return True

    def emptyline(self):
        pass

    def get_command_output(self, shell_id, command_id, wait=True):
        """
        Get the Output of the given shell and command
        @param string shell_id: The shell id on the remote machine.
            See #open_shell
        @param string command_id: The command id on the remote machine.
            See #run_command
        #@return [Hash] Returns a Hash with a key :exitcode and :data.
            Data is an Array of Hashes where the corresponding key
        #   is either :stdout or :stderr.  The reason it is in an Array so so
            we can get the output in the order it occurs on
        #   the console.
        """
        stdout_buffer, stderr_buffer = [], []
        command_done = False
        while not command_done:
            try:
                stdout, stderr, return_code, command_done = \
                    self.client._raw_get_command_output(shell_id, command_id)
                stdout_buffer.append(stdout)
                stderr_buffer.append(stderr)
                if wait == False:
                    command_done = True
            except WinRMOperationTimeoutError:
                # this is an expected error when waiting for a long-running process, just silently retry
                pass
        return b''.join(stdout_buffer), b''.join(stderr_buffer), return_code

def main():
    parser = argparse.ArgumentParser(add_help = True, description = "SMB client implementation.")

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>:<port>, default port is 5985 if not specified.')
    parser.add_argument('-file', type=argparse.FileType('r'), help='input file with commands to execute in the mini shell')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                                                       '(KRB5CCNAME) based on target parameters. If valid credentials '
                                                       'cannot be found, it will use the ones specified in the command '
                                                       'line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
                                                                            '(128 or 256 bits)')

    # TODO: cleanup unused arguments
    # TODO: add timeout options
    group = parser.add_argument_group('connection')

    group.add_argument('-dc-ip', action='store', metavar="ip address",
                       help='IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in '
                            'the target parameter')
    group.add_argument('-target-ip', action='store', metavar="ip address",
                       help='IP Address of the target machine with target port, default port is 5985 if not specified. If omitted it will use whatever was specified as target. '
                            'This is useful when target is the NetBIOS name and you cannot resolve it')
    group.add_argument('-port', choices=['139', '445'], nargs='?', default='445', metavar="destination port",
                       help='Destination port to connect to SMB Server')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password, address = parse_target(options.target)

    if options.target_ip is None:
        options.target_ip = address

    if domain is None:
        domain = ''

    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass
        password = getpass("Password:")

    if options.aesKey is not None:
        options.k = True

    if options.hashes is not None:
        lmhash, nthash = options.hashes.split(':')
        username = [
            NTLMHash(
                username=username,
                nt_hash=nthash,
            )
        ]
    else:
        lmhash = ''
        nthash = ''

    try:
        endpoint = 'http'
        if address.endswith('5986'):
            endpoint += 's'
        if options.target_ip:
            endpoint += f'://{options.target_ip}'
        else:
            endpoint += f'://{address}'
        if ':' not in address:
            endpoint += ':5985'
        endpoint += '/wsman?PSVersion=5.1.19041.1237'
        transport = 'ntlm'
        if options.k:
            transport = 'kerberos'
        # TODO: handle NT hash authentication
        # TODO: Add possibility to use other SPN than HTTP
        if options.target_ip:
            client = Protocol(endpoint=endpoint, transport=transport, username=username, password=password, server_cert_validation='ignore', kerberos_hostname_override=address)
        else:
            client = Protocol(endpoint=endpoint, transport=transport, username=username, password=password, server_cert_validation='ignore')

        shell = WinRMShell(client)

        if options.file is not None:
            logging.info("Executing commands from %s" % options.file.name)
            for line in options.file.readlines():
                if line[0] != '>':
                    print("> %s" % line, end=' ')
                    shell.onecmd(line)
                else:
                    print(line, end=' ')
        else:
            shell.cmdloop()
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(str(e))

if __name__ == "__main__":
    main()
