from __future__ import annotations

import pickle
from typing import Any


class Database:
    def __init__(self, path):
        self._path = path
        self._data = {}

    @classmethod
    def load(cls, path):
        db = cls(path)
        try:
            with open(path, "rb") as f:
                db._data = pickle.load(f)
        except OSError:
            pass
        return db

    def save(self):
        with open(self._path, "wb") as f:
            pickle.dump(self._data, f)

    def __getitem__(self, key):
        return DatabaseCursor(self)[key]

    def __setitem__(self, key, value):
        DatabaseCursor(self)[key] = value

    def __getattr__(self, key: str):
        if key.startswith("_"):
            return super().__getattr__(key)
        else:
            return DatabaseCursor(self).__getattr__(key)

    def __setattr__(self, key: str, value: Any):
        if key.startswith("_"):
            super().__setattr__(key, value)
        else:
            DatabaseCursor(self).__setattr__(key, value)


class DatabaseCursor:
    def __init__(self, database: Database, path: tuple = ()):
        self._database = database
        self._path = path

    @property
    def value(self):
        return self._database._data.get(self._path, None)

    @value.setter
    def value(self, value):
        self._database._data[self._path] = value

    def _has_value(self):
        return self._database._data.get(self._path, None) is not None

    def __getitem__(self, key):
        if isinstance(key, (tuple, list)):
            return DatabaseCursor(self._database, (*self._path, *key))
        else:
            return DatabaseCursor(self._database, (*self._path, key))

    def __setitem__(self, key, value):
        if isinstance(key, (tuple, list)):
            self._database._data[(*self._path, *key)] = value
        else:
            self._database._data[(*self._path, key)] = value

    def __getattr__(self, key: str):
        if key.startswith("_"):
            return super().__getattr__(key)
        else:
            cursor = self[key]
            value = cursor.value
            if value is not None:
                return value
            return cursor

    def __setattr__(self, key: str, value: Any):
        if key.startswith("_") or key == 'value':
            super().__setattr__(key, value)
        else:
            self[key] = value

    def __bool__(self):
        return False


db = Database.load("/data/posmbot.db")
