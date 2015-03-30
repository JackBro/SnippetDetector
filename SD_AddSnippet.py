"""
    SD_AddSnippet   Add a snippet to local/global database. A new snippet is defined by:
                    - snippet name: directly taken from the name of the function
                    - snippet description: taken from the comment (if there's one) of the function
                    - syntactic and semantic bytes sequences
                    - snippet comments: all the available comments added by the user

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
from SD_Common import sd_common

db_type = ['global', 'local']

# ask for local/global database
db_answer = AskYN(1, 'Do you want to save the snippet inside the local database?')
if db_answer == -1:
    print('\n[SNIPPET DETECTOR] Add snippet operation aborted')
else:
    # start/end address function is automatically taken from the cursor
    sd_c = sd_common()
    func_start, func_end = sd_c.get_start_end_function(ScreenEA())
    if func_start != BADADDR & func_end != BADADDR:
        # create database file path
        sddb = sd_db()
        n_instr = sd_c.get_total_instructions(func_start, func_end)
        db_file = sddb.get_db_folder(db_answer, True) + os.sep + 'sd_db_' + str(n_instr) + '.sd'
        if not os.path.isfile(db_file):
            # create database file
            sddb.open_db_connection(db_file)
            sddb.create_snippet_table()
        else:
            sddb.open_db_connection(db_file)

        # is the syntactic bytes sequence already inside the db?
        syntactic_bytes = GetManyBytes(func_start, func_end - func_start, False)
        _snippet = sddb.get_snippet_by_syntactic_bytes(syntactic_bytes)
        fail = False
        add_snippet = False
        if _snippet:
            print('\n[SNIPPET DETECTOR] Snippet is already inside the database (syntactic match):')
            fail = True
        else:
            # get semantic bytes sequence
            sd_sem = semantic()
            semantic_bytes = sd_sem.from_syntactic_to_semantic(func_start, func_end)
            if semantic_bytes is not None:
                # is the semantic bytes sequence already inside the db?
                _snippet = sddb.get_snippet_by_semantic_bytes(semantic_bytes)
                if not _snippet:
                    # add snippet
                    add_snippet = True
                else:
                    # semantic bytes sequence could be not unique
                    save_answer = AskYN(1, 'Snippet is already inside the database (semantic match), do you want'
                                           ' to add this snippet too?')
                    if save_answer == 1:
                        # add the snippet
                        add_snippet = True
                    else:
                        fail = True
                        print('[SNIPPET DETECTOR] Snippet is already inside the database (semantic match):')
            else:
                print('\n[SNIPPET DETECTOR] Unable to convert syntactical snippet into semantic one...')
        if fail:
            # print the information about the snippet inside the database
            print('Snippet name: %s' % _snippet[0])
            print('Snippet description: %s\n' % _snippet[1])
        if add_snippet:
            # time to save the new snippet inside the database
            comments = sd_c.get_comments(func_start, func_end)
            snippet_name = GetFunctionName(func_start)
            snippet_description = GetFunctionCmt(func_start, False)
            sddb.save_snippet(snippet_name, snippet_description, syntactic_bytes, semantic_bytes, comments)
            print('\n[SNIPPET DETECTOR] Snippet correctly inserted inside %s database!' % db_type[db_answer])

        sddb.close_db_connection()
    else:
        print('\n[SNIPPET DETECTOR] Unable to get function start/end addresses from cursor at 0x%X...' % ScreenEA())
