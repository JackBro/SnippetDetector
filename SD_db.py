"""
    SD_db   class used to define SQlite related operations needed by Snippet Detector scripts.

    by ZaiRoN (zairon.wordpress.com)

    Copyright (C) 2015

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

import os
import sqlite3
import idc

class sd_db:

    def __init__(self):
        self.db_conn = None
        self._cursor = None


    """
        get_db_folder   get the database folder name, it depends on the user's choice on the local/global db.
                        Local database is located inside the disassembled binary file sub folder, under 'SD_local_DB'
                        name. Global database is inside a sub folder of Snippet Detector scripts folder. In this case
                        the name of the folder is simply 'SnippetDetector_DB'.
                        Params:
                        _local      true if local database has been specified, false otherwise
                        _create     true if folder should be created (valid for SD_AddSnippet.py only)
    """
    def get_db_folder(self, _local, _create):
        if _local == 1:         # local db
            _folder = os.path.dirname(idc.GetInputFilePath()) + os.sep + 'SD_local_DB'
        else:                   # global db
            _folder = os.path.dirname(os.path.realpath(__file__)) + os.sep + "SnippetDetector_DB"

        if not os.path.isdir(_folder):
            if _create:
                # First saved snippet, SnippetDetector database folder doesn't exist. Create it!
                os.makedirs(_folder, 755)
        return _folder

    """
        open_db_connection
    """
    def open_db_connection(self, _file):
        self.db_conn = sqlite3.connect(_file)
        self.db_conn.text_factory = str
        self._cursor = self.db_conn.cursor()

    """
        close_db_connection
    """
    def close_db_connection(self):
        self.db_conn.close()

    """
        create_snippet_db_table     create the table snippet_db, the fields are:
                                    - name                  snippet name
                                    - description           snippet description
                                    - syntactic_bytes       syntactic bytes sequence
                                    - semantic_bytes        semantic bytes sequence
                                    - comments              sequence of instruction comments
    """
    def create_snippet_table(self):
        self._cursor.execute("CREATE TABLE snippet_db (name TEXT, description TEXT, syntactic_bytes BLOB, semantic_bytes BLOB, comments BLOB, PRIMARY KEY(syntactic_bytes ASC))")

    """
        save_snippet    save the new snippet inside the database.
    """
    def save_snippet(self, _snippet_name, _snippet_description, _syntactic_bytes, _semantic_bytes, _comments):
        self._cursor.execute("INSERT INTO snippet_db (name, description, syntactic_bytes, semantic_bytes, comments) VALUES (?, ?, ?, ?, ?)", (_snippet_name, _snippet_description, sqlite3.Binary(_syntactic_bytes), sqlite3.Binary(_semantic_bytes), sqlite3.Binary(_comments)))
        self.db_conn.commit()

    """
        update_snippet      update an existing snippet. (I think SQlite UPDATE query is the best approach to follow
                            but I don't know why new comments are not saved...)
    """
    def update_snippet(self, _snippet_name, _snippet_description, _syntactic_bytes, _semantic_bytes, _comments):
        self._cursor.execute("DELETE from snippet_db WHERE semantic_bytes=?", (sqlite3.Binary(_semantic_bytes),))
        self.save_snippet(_snippet_name, _snippet_description, sqlite3.Binary(_syntactic_bytes), sqlite3.Binary(_semantic_bytes), sqlite3.Binary(_comments))

    """
        delete_snippet      delete a snippet from the database
                            Param:
                            - _syntactic_bytes     syntactic bytes sequence used to search the snippet to delete
    """
    def delete_snippet(self, _syntactic_bytes):
        self._cursor.execute("DELETE from snippet_db WHERE syntactic_bytes=?", (sqlite3.Binary(_syntactic_bytes),))
        self.db_conn.commit()

    """
        is_syntactic_bytes_inside_db    is the snippet (in his syntactic bytes sequence) inside the db?
                                        Param:
                                        - _syn_bytes      syntactic bytes sequence
    """
    def is_syntactic_bytes_inside_db(self, _synt_bytes):
        self._cursor.execute("SELECT * FROM snippet_db WHERE syntactic_bytes = ?", (sqlite3.Binary(_synt_bytes),))
        result = self._cursor.fetchone()
        if result is None:
            return False
        return True

    """
        get_snippet_by_syntactic_bytes      search for a snippet with a given syntactic bytes sequence
                                            Param:
                                            - _syn_bytes      syntactic bytes sequence
    """
    def get_snippet_by_syntactic_bytes(self, _synt_bytes):
        self._cursor.execute("SELECT * FROM snippet_db WHERE syntactic_bytes = ?", (sqlite3.Binary(_synt_bytes),))
        return self._cursor.fetchone()

    """
    #   count_semantic_snippet      count the number of times a semantic bytes sequence occours inside the database
    #                               Param:
    #                               - _sem_bytes    semantic bytes sequence
    """
    def count_semantic_snippet(self, _sem_bytes):
        self._cursor.execute("SELECT * FROM snippet_db WHERE semantic_bytes = ?", (sqlite3.Binary(_sem_bytes),))
        return len(self._cursor.fetchall())

    """
    #   get_snippets_by_semantic_bytes      search for all the snippets with the given semantic bytes sequence
    #                                       Param:
    #                                       - _sem_bytes    semantic bytes sequence
    #
    #   """
    def get_snippets_by_semantic_bytes(self, _sem_bytes):
        self._cursor.execute("SELECT * FROM snippet_db WHERE semantic_bytes = ?", (sqlite3.Binary(_sem_bytes),))
        return self._cursor.fetchall()

    """
        get_snippet_by_semantic_bytes       search for a snippet with the given semantic bytes sequence
                                            Param:
                                            - _sem_bytes      semantic bytes sequence
    """
    def get_snippet_by_semantic_bytes(self, _sem_bytes):
        self._cursor.execute("SELECT * FROM snippet_db WHERE semantic_bytes = ?", (sqlite3.Binary(_sem_bytes),))
        return self._cursor.fetchone()