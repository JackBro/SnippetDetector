"""
    SD_DeleteSnippet    delete a snippet from the local or global database. It's possible to delete a snippet with
                        a syntactic match only.

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

from SD_db import sd_db
from SD_Common import sd_common

# ask for the local/global database
db_answer = AskYN(1, 'Do you want to delete the snippet from the local database?\n[YES = local, NO = global, CANCEL = abort]')
if db_answer == -1:
    print('[SNIPPET DETECTOR] Delete snippet operation aborted.')
else:
    # start/end address function is automatically taken from the cursor
    sd_c = sd_common()
    func_start, func_end = sd_c.get_start_end_function(ScreenEA())
    if func_start != BADADDR & func_end != BADADDR:
        not_inside = True
        # create database file path
        sddb = sd_db()
        n_instr = sd_c.get_total_instructions(func_start, func_end)
        db_file = sddb.get_db_folder(db_answer, True) + os.sep + 'sd_db_' + str(n_instr) + '.sd'
        if os.path.isfile(db_file):
            # db exists, open db
            sddb.open_db_connection(db_file)

            # get syntactic bytes
            syntactic_bytes = GetManyBytes(func_start, func_end - func_start, False)
            if sddb.is_syntactic_bytes_inside_db(syntactic_bytes):
                # snippet has been found inside the database, delete it
                sddb.delete_snippet(syntactic_bytes)
                print('\n[SNIPPET DETECTOR] Snippet correctly deleted.')
                not_inside = False
            sddb.close_db_connection()
        if not_inside:
            # snippet is not inside database
            print('\n[SNIPPET DETECTOR] Snippet is not inside database.')
    else:
        print("[SNIPPET DETECTOR] Unable to get number of instruction inside function at 0x%X." % func_start)
