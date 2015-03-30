"""
    SD_UpdateSnippet        update information of an already saved snippet (syntactic bytes sequence should be the
                            same). It's possible to update the name, the description and one or more comments about
                            the snippet.

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
from SD_Semantic import semantic


# ask for the local/global database
db_answer = AskYN(1, 'Do you want to update the snippet from the local database?')
if db_answer == -1:
    print('\n[SNIPPET DETECTOR] Update snippet operation aborted')
else:
    sd_c = sd_common()

    # start/end address function is automatically taken from the cursor
    func_start, func_end = sd_c.get_start_end_function(ScreenEA())
    if func_start != BADADDR & func_end != BADADDR:
        n_instr = sd_c.get_total_instructions(func_start, func_end)
        if n_instr != 0:
            # get database file path
            sddb = sd_db()
            db_file = sddb.get_db_folder(db_answer, False) + os.sep + 'sd_db_' + str(n_instr) + '.sd'
            if os.path.isfile(db_file):
                # db exists, open db
                sddb.open_db_connection(db_file)

                # get syntactic bytes
                syntactic_bytes = GetManyBytes(func_start, func_end - func_start, False)
                if sddb.is_syntactic_bytes_inside_db(syntactic_bytes):
                    # snippet has been found inside the database, get info and update
                    sd_sem = semantic()
                    semantic_bytes = sd_sem.from_syntactic_to_semantic(func_start, func_end)
                    if semantic_bytes is not None:
                        snippet_name = GetFunctionName(func_start)
                        snippet_description = GetFunctionCmt(func_start, False)
                        comments = sd_c.get_comments(func_start, func_end)
                        sddb.update_snippet(snippet_name, snippet_description, syntactic_bytes, semantic_bytes, comments)
                        print('\n[SNIPPET DETECTOR] Snippet correctly updated!')
                    else:
                        print('\n[SNIPPET DETECTOR] Unable to convert syntactical snippet into semantic one at 0x' % func_start)
                else:
                    # snippet is not inside database
                    print('\n[SNIPPET DETECTOR] Snippet is not inside database')
                sddb.close_db_connection()
            else:
                print('\n[SNIPPET DETECTOR] Snippet not updated')
        else:
            print('\n[SNIPPET DETECTOR] Unable to get number of instruction inside function at 0x%X...' % func_start)

