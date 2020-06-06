import getpass
import datetime
import os
import re
import sqlite3
import sys
import time
import psutil

from codalab.common import CODALAB_VERSION, PermissionError
from codalab.lib.common import get_codalab_home, read_json_or_die, write_pretty_json
from codalab.lib import formatting

MAIN_BUNDLE_SERVICE = 'https://worksheets.codalab.org'


class CodalabManagerState:
    def __init__(self, temporary, state_backend):

        self.temporary = temporary
        self.state_backend = state_backend
        # Read the state, creating it if it doesn't exist.
        self.initialize_state()

    def initialize_state(self):
        if self.temporary:
            pass
        if self.state_backend == "sqlite3":
            return self._initialize_state_sqlite3()
        else:
            return self._initialize_state_json()

    def _initialize_state_json(self):
        if self.temporary:
            pass
        # Read state file, creating if it doesn't exist.
        if not os.path.exists(self.state_path):
            write_pretty_json(
                {
                    'auth': {},  # address -> {username, auth_token}
                    'sessions': {},  # session_name -> {address, worksheet_uuid, last_modified}
                },
                self.state_path,
            )
        self.state = read_json_or_die(self.state_path)

    def _initialize_state_sqlite3(self):
        # Read state database, creating if it doesn't exist.
        self.connection = sqlite3.connect(self.state_path)
        self.connection.row_factory = sqlite3.Row
        with self.connection:
            c = self.connection.cursor()
            c.execute(
                'CREATE TABLE if not exists auth (server text unique, access_token text, expires_at real, '
                'refresh_token text, scope text, token_type text, username text)'
            )
            c.execute(
                'CREATE TABLE if not exists sessions (name text unique, address text, worksheet_uuid text)'
            )
            c.execute('CREATE TABLE if not exists misc (key text unique, value text)')

    @property
    def state_path(self):
        if self.state_backend == "sqlite3":
            return os.getenv('CODALAB_STATE', os.path.join(get_codalab_home(), 'state.db'))
        return os.getenv('CODALAB_STATE', os.path.join(get_codalab_home(), 'state.json'))

    def session_name(self):
        """
        Return the current session name.
        """
        if self.temporary:
            return 'temporary'

        # If specified in the environment, then return that.
        session = os.getenv('CODALAB_SESSION')
        if session:
            return session

        # Otherwise, go up process hierarchy to the *highest up shell* out of
        # the consecutive shells.  Include Python and Ruby so we can script from inside them.
        #   cl bash python bash screen bash gnome-terminal init
        #                  ^
        #                  | return this
        # This way, it's easy to write scripts that have embedded 'cl' commands
        # which modify the current session.
        process = psutil.Process().parent()
        session = 'top'
        max_depth = 10
        while process and max_depth:
            try:
                name = os.path.basename(process.cmdline()[0])
                # When a shell is invoked as a login shell, its process command
                # will be preceded by a dash '-'.
                if (
                    re.match(r'-?(sh|bash|csh|tcsh|zsh|python|ruby|powershell|cmd)(\.exe)?', name)
                    is None
                ):
                    break
                session = str(process.pid)
                process = process.parent()
                max_depth -= 1
            except psutil.AccessDenied:
                # If we hit a root process, just stop searching upwards
                break
        return session

    def session(self):
        """
        Return the current session.
        """
        if self.state_backend == "sqlite3":
            return self._session_sqlite3()
        else:
            return self._session_json()

    def _session_json(self):
        sessions = self.state['sessions']
        name = self.session_name()
        if name not in sessions:
            # New session: set the address and worksheet uuid to the default (main if not specified)
            cli_config = self.config.get('cli', {})
            address = cli_config.get('default_address', MAIN_BUNDLE_SERVICE)
            worksheet_uuid = cli_config.get('default_worksheet_uuid', '')
            sessions[name] = {'address': address, 'worksheet_uuid': worksheet_uuid}
        return sessions[name]

    def _session_sqlite3(self):
        name = self.session_name()
        # Get sessions from the state database
        with self.connection:
            c = self.connection.cursor()
            c.execute("SELECT * FROM sessions WHERE name=?", (name,))
            retrieved_session = c.fetchone()

        if retrieved_session:
            # Session already exists, return it
            return {
                "name": name,
                "address": retrieved_session["address"],
                "worksheet_uuid": retrieved_session["worksheet_uuid"],
            }

        # New session: set the address and worksheet uuid to the default (main if not specified)
        cli_config = self.config.get('cli', {})
        address = cli_config.get('default_address', MAIN_BUNDLE_SERVICE)
        worksheet_uuid = cli_config.get('default_worksheet_uuid', '')
        with self.connection:
            c = self.connection.cursor()
            c.execute("replace into sessions values (?, ?, ?)", (name, address, worksheet_uuid))
        return {"name": name, "address": address, "worksheet_uuid": worksheet_uuid}

    def set_current_worksheet_uuid(self, address, worksheet_uuid):
        """
        Set the current worksheet to the given worksheet_uuid.
        """
        session = self.session()
        session['address'] = address
        if worksheet_uuid:
            session['worksheet_uuid'] = worksheet_uuid
        else:
            if 'worksheet_uuid' in session:
                del session['worksheet_uuid']
        if self.state_backend == "sqlite3":
            with self.connection:
                c = self.connection.cursor()
                c.execute(
                    "replace into sessions values (?, ?, ?)",
                    (session["name"], session["address"], session["worksheet_uuid"]),
                )
        else:
            self.save_json_state()

    def check_version(self, server_version):
        if self.state_backend == "sqlite3":
            return self._check_version_sqlite3(server_version)
        else:
            return self._check_version_json(server_version)

    def _check_version_json(self, server_version):
        # Enforce checking version at most once every 24 hours
        epoch_str = formatting.datetime_str(datetime.datetime.utcfromtimestamp(0))
        last_check_str = self.state.get('last_check_version_datetime', epoch_str)
        last_check_dt = formatting.parse_datetime(last_check_str)
        now = datetime.datetime.utcnow()
        if (now - last_check_dt) < datetime.timedelta(days=1):
            return
        self.state['last_check_version_datetime'] = formatting.datetime_str(now)
        self.save_json_state()

        # Print notice if server version is newer
        if list(map(int, server_version.split('.'))) > list(map(int, CODALAB_VERSION.split('.'))):
            message = (
                "NOTICE: "
                "The instance you are connected to is running CodaLab v{}. "
                "You are currently using an older v{} of the CLI. "
                "Please update codalab using\n"
                "   pip install -U codalab\n"
            ).format(server_version, CODALAB_VERSION)
            sys.stderr.write(message)

    def _check_version_sqlite3(self, server_version):
        # Enforce checking version at most once every 24 hours
        epoch_str = formatting.datetime_str(datetime.datetime.utcfromtimestamp(0))
        with self.connection:
            c = self.connection.cursor()
            c.execute("SELECT value FROM misc WHERE key=?", ("last_check_version_datetime",))
            last_check_version_datetime = c.fetchone()
        if last_check_version_datetime:
            last_check_str = last_check_version_datetime["value"]
        else:
            last_check_str = epoch_str
        last_check_dt = formatting.parse_datetime(last_check_str)
        now = datetime.datetime.utcnow()
        if (now - last_check_dt) < datetime.timedelta(days=1):
            return
        # Update the last_check_version_datetime
        with self.connection:
            c = self.connection.cursor()
            c.execute(
                "replace into misc (key, value) values (?, ?)",
                ("last_check_version_datetime", formatting.datetime_str(now)),
            )

        # Print notice if server version is newer
        if list(map(int, server_version.split('.'))) > list(map(int, CODALAB_VERSION.split('.'))):
            message = (
                "NOTICE: "
                "The instance you are connected to is running CodaLab v{}. "
                "You are currently using an older v{} of the CLI. "
                "Please update codalab using\n"
                "   pip install -U codalab\n"
            ).format(server_version, CODALAB_VERSION)
            sys.stderr.write(message)

    def logout(self, address):
        """
        Clear credentials associated with given address.
        """
        if self.state_backend == "sqlite3":
            return self._logout_sqlite3(address)
        else:
            return self._logout_json(address)

    def _logout_json(self, address):
        if address in self.state['auth']:
            del self.state['auth'][address]
            self.save_json_state()

    def _logout_sqlite3(self, address):
        with self.connection:
            c = self.connection.cursor()
            c.execute("delete from auth where server=?", (address,))

    def _authenticate(self, cache_key, auth_handler):
        if self.state_backend == "sqlite3":
            return self._authenticate_sqlite3(cache_key, auth_handler)
        else:
            return self._authenticate_json(cache_key, auth_handler)

    def _authenticate_json(self, cache_key, auth_handler):
        auth = self.state['auth'].get(cache_key, {})

        def _cache_token(token_info, username=None):
            '''
            Helper to update state with new token info and optional username.
            Returns the latest access token.
            '''
            # Make sure this is in sync with auth.py.
            token_info['expires_at'] = time.time() + float(token_info['expires_in'])
            del token_info['expires_in']
            auth['token_info'] = token_info
            if username is not None:
                auth['username'] = username
            self.save_state()
            return token_info['access_token']

        # Check the cache for a valid token
        if 'token_info' in auth:
            token_info = auth['token_info']
            expires_at = token_info.get('expires_at', 0.0)

            # If token is not nearing expiration, just return it.
            if expires_at >= (time.time() + 10 * 60):
                return token_info['access_token']

            # Otherwise, let's refresh the token.
            token_info = auth_handler.generate_token(
                'refresh_token', auth['username'], token_info['refresh_token']
            )
            if token_info is not None:
                return _cache_token(token_info)

        # If we get here, a valid token is not already available.
        auth = self.state['auth'][cache_key] = {}

        username = os.environ.get('CODALAB_USERNAME')
        password = os.environ.get('CODALAB_PASSWORD')
        if username is None or password is None:
            print('Requesting access at %s' % cache_key)
        if username is None:
            sys.stdout.write('Username: ')  # Use write to avoid extra space
            sys.stdout.flush()
            username = sys.stdin.readline().rstrip()
        if password is None:
            password = getpass.getpass()

        token_info = auth_handler.generate_token('credentials', username, password)
        if token_info is None:
            raise PermissionError("Invalid username or password.")
        return _cache_token(token_info, username)

    def _authenticate_sqlite3(self, cache_key, auth_handler):
        # Get sessions from the state database
        with self.connection:
            c = self.connection.cursor()
            c.execute("SELECT * FROM auth WHERE server=?", (cache_key,))
            retrieved_auth = c.fetchone()
        auth = dict(retrieved_auth) if retrieved_auth else {}

        def _generate_token_info(access_token, expires_at, refresh_token, scope, token_type):
            if not all([access_token, expires_at, refresh_token, scope, token_type]):
                # Return {} if any piece of the token info is missing.
                return {}
            return {
                "access_token": access_token,
                "expires_at": expires_at,
                "refresh_token": refresh_token,
                "scope": scope,
                "token_type": token_type,
            }

        def _cache_token(token_info, username, server):
            '''
            Helper to update state with new token info and optional username.
            Returns the latest access token.
            '''
            # Make sure this is in sync with auth.py.
            token_info['expires_at'] = time.time() + float(token_info['expires_in'])
            with self.connection:
                c = self.connection.cursor()
                c.execute(
                    "replace into auth values (?, ?, ?, ?, ?, ?, ?)",
                    (
                        server,
                        token_info["access_token"],
                        token_info["expires_at"],
                        token_info["refresh_token"],
                        token_info["scope"],
                        token_info["token_type"],
                        username,
                    ),
                )
            return token_info['access_token']

        token_info = _generate_token_info(
            auth.get("access_token"),
            auth.get("expires_at"),
            auth.get("refresh_token"),
            auth.get("scope"),
            auth.get("token_type"),
        )
        # Check the cache for a valid token
        if token_info:
            expires_at = token_info.get('expires_at', 0.0)

            # If token is not nearing expiration, just return it.
            if expires_at >= (time.time() + 10 * 60):
                return token_info['access_token']

            # Otherwise, let's refresh the token.
            token_info = auth_handler.generate_token(
                'refresh_token', auth['username'], token_info['refresh_token']
            )
            if token_info is not None:
                return _cache_token(token_info, auth['username'], cache_key)

        # If we get here, a valid token is not already available.
        username = os.environ.get('CODALAB_USERNAME')
        password = os.environ.get('CODALAB_PASSWORD')
        if username is None or password is None:
            print('Requesting access at %s' % cache_key)
        if username is None:
            sys.stdout.write('Username: ')  # Use write to avoid extra space
            sys.stdout.flush()
            username = sys.stdin.readline().rstrip()
        if password is None:
            password = getpass.getpass()

        token_info = auth_handler.generate_token('credentials', username, password)
        if token_info is None:
            raise PermissionError("Invalid username or password.")
        return _cache_token(token_info, username, cache_key)

    def __del__(self):
        """
        Clean up the CodalabManagerState by closing the SQLite connection, if applicable.
        """
        if self.state_backend == "sqlite3" and getattr(self, "connection", None):
            self.connection.close()

    def save_json_state(self):
        if self.temporary:
            return
        write_pretty_json(self.state, self.state_path)
