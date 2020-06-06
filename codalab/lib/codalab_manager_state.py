import os
import sqlite3

from codalab.lib.common import get_codalab_home, read_json_or_die, write_pretty_json


class CodalabManagerState:
    def __init__(self, temporary):
        self.temporary = temporary
        # Read the state, creating it if it doesn't exist.
        self.initialize_state()

    def state_path(self):
        raise NotImplementedError

    def get_auth(self, server, default={}):
        raise NotImplementedError

    def set_auth(
        self, server, access_token, expires_at, refresh_token, scope, token_type, username
    ):
        raise NotImplementedError

    def delete_auth(self, server):
        raise NotImplementedError

    def get_session(self, name, default={}):
        raise NotImplementedError

    def set_session(self, name, address, worksheet_uuid):
        raise NotImplementedError

    def get_last_check_version_datetime(self, default=None):
        raise NotImplementedError

    def set_last_check_version_datetime(self, timestamp):
        raise NotImplementedError


class CodalabManagerJsonState(CodalabManagerState):
    def initialize_state(self):
        if self.temporary:
            self.state = {'auth': {}, 'sessions': {}}
            return
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

    @property
    def state_path(self):
        return os.getenv('CODALAB_STATE', os.path.join(get_codalab_home(), 'state.json'))

    def get_auth(self, server, default={}):
        return self.state["auth"].get(server, default)

    def set_auth(
        self, server, access_token, expires_at, refresh_token, scope, token_type, username
    ):
        self.state["auth"][server] = {
            "token_info": {
                "access_token": access_token,
                "expires_at": expires_at,
                "refresh_token": refresh_token,
                "scope": scope,
                "token_type": token_type,
            },
            "username": username,
        }
        self._save_json_state()

    def delete_auth(self, server):
        self.state["auth"].pop(server)

    def get_session(self, name, default={}):
        return self.state["sessions"].get(name, default)

    def set_session(self, name, address, worksheet_uuid):
        self.state["sessions"]["name"] = {"address": address, "worksheet_uuid": "worksheet_uuid"}
        self._save_json_state()

    def get_last_check_version_datetime(self, default=None):
        return self.state.get("last_check_version_datetime", default)

    def set_last_check_version_datetime(self, timestamp):
        self.state["last_check_version_datetime"] = timestamp
        self._save_json_state()

    def _save_json_state(self):
        if self.temporary:
            return
        write_pretty_json(self.state, self.state_path)


class CodalabManagerSqlite3State(CodalabManagerState):
    def initialize_state(self):
        if self.temporary:
            self.connection = sqlite3.connect(":memory:")
        else:
            # Read state database, creating if it doesn't exist.
            self.connection = sqlite3.connect(self.state_path)
        self.connection.row_factory = sqlite3.Row
        # Create the necessary tables, if they don't exist
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
        return os.getenv('CODALAB_STATE', os.path.join(get_codalab_home(), 'state.db'))

    def get_auth(self, server, default={}):
        with self.connection:
            c = self.connection.cursor()
            c.execute("SELECT * FROM auth WHERE server=?", (server,))
            retrieved_auth = c.fetchone()
        return dict(retrieved_auth) if retrieved_auth else default

    def set_auth(
        self, server, access_token, expires_at, refresh_token, scope, token_type, username
    ):
        with self.connection:
            c = self.connection.cursor()
            c.execute(
                "replace into auth values (?, ?, ?, ?, ?, ?, ?)",
                (server, access_token, expires_at, refresh_token, scope, token_type, username),
            )

    def delete_auth(self, server):
        with self.connection:
            c = self.connection.cursor()
            c.execute("delete from auth where server=?", (server,))

    def get_session(self, name, default={}):
        with self.connection:
            c = self.connection.cursor()
            c.execute("SELECT * FROM sessions WHERE name=?", (name,))
            retrieved_session = c.fetchone()
        return dict(retrieved_session) if retrieved_session else default

    def set_session(self, name, address, worksheet_uuid):
        with self.connection:
            c = self.connection.cursor()
            c.execute("replace into sessions values (?, ?, ?)", (name, address, worksheet_uuid))

    def get_last_check_version_datetime(self, default=None):
        with self.connection:
            c = self.connection.cursor()
            c.execute("SELECT value FROM misc WHERE key=?", ("last_check_version_datetime",))
            last_check_version_datetime = c.fetchone()
        return last_check_version_datetime["value"] if last_check_version_datetime else default

    def set_last_check_version_datetime(self, timestamp):
        with self.connection:
            c = self.connection.cursor()
            c.execute(
                "replace into misc (key, value) values (?, ?)",
                ("last_check_version_datetime", timestamp),
            )

    def __del__(self):
        """
        Clean up the CodalabManagerState by closing the SQLite connection, if applicable.
        """
        if getattr(self, "connection", None):
            self.connection.close()


codalab_manager_state_types = {
    "json": CodalabManagerJsonState,
    "sqlite3": CodalabManagerSqlite3State,
}
