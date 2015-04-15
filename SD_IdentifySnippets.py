"""
    SD_IdentifySnippets     scan the entire database searching for known snippets. It can detect both syntactic and
                            semantic snippets.

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
    print('\n[SNIPPET DETECTOR] Search snippets operation aborted')
else:
    # iterate through all the segment functions
    n_synt = n_sem = n_doubt = 0
    ea = ScreenEA()
    sd_c = sd_common()
    for func_start in Functions(SegStart(ea), SegEnd(ea)):
        func_end = GetFunctionAttr(func_start, FUNCATTR_END)

        n_instr = len(list(Heads(func_start, func_end)))
        if n_instr != 0:
            # get database file path
            sddb = sd_db()
            db_file = sddb.get_db_folder(db_answer, False) + os.sep + 'sd_db_' + str(n_instr) + '.sd'
            if os.path.isfile(db_file):
                # db exists, open db
                sddb.open_db_connection(db_file)
                match = False
                # is the syntactic bytes sequence inside the db?
                syntactic_bytes = GetManyBytes(func_start, func_end - func_start, False)
                _snippet = sddb.get_snippet_by_syntactic_bytes(syntactic_bytes)
                if not _snippet:
                    # no syntactic match...
                    sd_sem = semantic()
                    semantic_bytes = sd_sem.from_syntactic_to_semantic(func_start, func_end)
                    if semantic_bytes is not None:
                        # is the semantic bytes sequence inside the db?
                        sem_count = sddb.count_semantic_snippet(semantic_bytes)
                        if sem_count != 0:
                            print('\n[SNIPPET DETECTOR] Semantic match at 0x%X' % func_start)
                            if sem_count == 1:
                                _snippet = sddb.get_snippet_by_semantic_bytes(semantic_bytes)
                                match = True
                                n_sem += 1
                            else:
                                # more than 1 semantic match, show possible matches only
                                n_doubt += 1
                                print('----- %d semantic snippets found: -----' % sem_count)
                                snippets = sddb.get_snippets_by_semantic_bytes(semantic_bytes)
                                i = 1
                                for snippet in snippets:
                                    print('- Snippet %d\nname: %s\ndescription: %s' % (i, snippet[0], snippet[1]))
                                    i += 1
                    else:
                        print('\n[SNIPPET DETECTOR] Unable to convert syntactical snippet into semantic one at 0x%x' % func_start)
                else:
                    # syntactic snippet has been found
                    print('\n[SNIPPET DETECTOR] Syntactic match at 0x%X' % func_start)
                    match = True
                    n_synt += 1

                if match:
                    apply = sd_c.apply_snippet_to_disasm(func_start, _snippet)
                    if apply:
                        print('Snippet name: %s' % _snippet[0])
                        if _snippet[1]:
                            print('Snippet description: %s' % _snippet[1])
                    else:
                        print('Database snippet not applied...')

                sddb.close_db_connection()
        else:
            print('\n[SNIPPET DETECTOR] Unable to get number of instruction inside function at 0x%x...' % func_start)
    if (n_synt + n_sem + n_doubt) == 0:
        print('\n[SNIPPET DETECTOR] Nothing found...')
    else:
        print('\n[SNIPPET DETECTOR] %d syntactic snippet, %d semantic snippet and %d multiple matches has been found' % (n_synt, n_sem, n_doubt))
