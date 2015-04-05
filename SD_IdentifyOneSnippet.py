"""
    SD_IdentifySnippet      scan the entire database searching for one specific snippet only.

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

db_answer = AskYN(1, 'Do you want to search inside local database?\n[YES = local, NO = global, CANCEL = abort]')
if db_answer == -1:
    print('\n[SNIPPET DETECTOR] Search snippet operation aborted...')
else:
    sd_c = sd_common()
    func_start, func_end = sd_c.get_start_end_function(ScreenEA())
    if func_start != BADADDR & func_end != BADADDR:
        n_instr = sd_c.get_total_instructions(func_start, func_end)
        if n_instr != 0:
            match = False
            # get database file path
            sddb = sd_db()
            db_file = sddb.get_db_folder(db_answer, False) + os.sep + 'sd_db_' + str(n_instr) + '.sd'
            if os.path.isfile(db_file):
                # db exists, open db
                sddb.open_db_connection(db_file)
                # is the syntactic bytes sequence inside the db?
                syntactic_bytes = GetManyBytes(func_start, func_end - func_start, False)
                _snippet = sddb.get_snippet_by_syntactic_bytes(syntactic_bytes)
                if not _snippet:
                    # no syntactic match...
                    sd_sem = semantic()
                    semantic_bytes = sd_sem.from_syntactic_to_semantic(func_start, func_end)
                    if semantic_bytes is not None:
                        sem_count = sddb.count_semantic_snippet(semantic_bytes)
                        if sem_count != 0:
                            print('\n[SNIPPET DETECTOR] Semantic match found!')
                            if sem_count == 1:
                                # 1 semantic match, apply it
                                _snippet = sddb.get_snippet_by_semantic_bytes(semantic_bytes)
                                match = True
                            else:
                                # more than 1 semantic match, show possible matches
                                print('----- %d semantic snippets found: -----\n' % sem_count)
                                snippets = sddb.get_snippets_by_semantic_bytes(semantic_bytes)
                                i = 1
                                for snippet in snippets:
                                    print('- Snippet %d\nname: %s\ndescription: %s' % (i, snippet[0], snippet[1]))
                                    i += 1

                                # ask for the number of snippet to apply (0 means skip)
                                choice = AskLong(0, 'Insert the snippet number to apply')
                                if choice > 0:
                                    _snippet = snippets[choice - 1]
                                    match = True
                    else:
                        print('\n[SNIPPET DETECTOR] Unable to convert syntactical snippet into semantic one at 0x%x' % func_start)
                else:
                    # syntactic snippet has been found
                    print('\n[SNIPPET DETECTOR] Syntactic match found!')
                    match = True
                sddb.close_db_connection()
            if match:
                # apply the snippet info
                applied = sd_c.apply_snippet_to_disasm(func_start, _snippet)
                if applied:
                    print('Snippet detected and applied!')
                else:
                    print('No changes applied.')
            else:
                print('\n[SNIPPET DETECTOR] Snippet not detected...')
        else:
            print("\n[SNIPPET DETECTOR] Unable to get number of instruction inside function at 0x%X..." % func_start)
