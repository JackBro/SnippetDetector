# Snippet Detector
- - -

Snippet Detector is an IDA Python scripts project used to detect snippets from 32bit disassembled files. *snippet* is the word used to identify a generic sequence of instructions (at the moment a snippet is indeed a defined function). The aim of the tool is to collect many disassembled snippets inside a database for the detection process. The snippet collection is then used in the identification process of one or more snippet from a fresh disassembled file. This could speed up the disassembling process. The tool can also be used to share your analysis with someone else in an easy and fast way.

###### Local and global database
The snippet database is divided into sub-databases, depending on the number of the snippet instructions. The name of each database is something like *sd_db_xx.db*, where xx represents the number of the instructions inside the snippet. I decided to split the database because it takes a lot of time searching through one big file only.
Snippet Detector can use two kind of databases: local and global.
- *local* is located inside the disassembled exe folder (under 'SD_local_DB' name). I usually use the local db if I need to pass my research to someone else. *Local* is strictly related to the current file analysis.
- *global* is located inside the Snippet Detector project folder (under 'SnippetDetector_DB' name), and it's a huge repository where I usually save all the studied snippets. *Global* is not related to any single analysis.

Why do I need two databases? You are not obliged to use both, you can work with one, another or both databases as you prefer.

Every database entry contains the information about a snippet, here are the fields for a single saved snippet:
- *name*: the name of the snippet (the name of the function)
- *description*: a little description of the snippet (the comment of the function)
- *syntactic bytes sequence*: the bytes defining the snippet
- *semantic bytes sequence*: the bytes defining the meaning of the instruction
- *comments*: the available instructions comment added by the user

Global and local databases are implemented as SQlite database and the syntactic bytes sequence is used as a primary key.

###### Semantic bytes sequence
I think everything is clear except the *semantic bytes sequence* term I have used in the snippet entry description. The detection check is done in two different levels: syntactic and semantic.
The syntactic matching is obvious, two instructions are identical if and only if they have the same bytes; apply this method to a series of instructions and you'll have the definition of a syntactic matching on snippets of code.
A semantic bytes sequence is a sequence of bytes defining the general meaning of the snippet. Suppose to have:

```
74 20                  jz 401040
33 00                  xor eax, [eax]
E8 14 00 00 00         call 401062
C7 45 F8 38 5B 41 00   mov  dword ptr [ebp-8],  415B38h
```
The idea is to convert every instruction of the snippet into another one without changing the semantic meaning of it. The conversion is done removing the operand(s). After the conversion I'll get something like that:
```
74      jz byte_val
33 00   xor eax, [eax]
E8      call dword_val
C7 45   mov  dword ptr [ebp-byte_val], dword_val
```
All the instructions are changed except the second one because it doesn't use operands.

It's obvious that inside a database (local or global) you can have two or more identical semantical bytes sequence. i.e.:
```
snippet #1:
   6A 35            push 35
   E8 12 34 56 78   call Sleep

snippet #2:
   6A 12            push 12
   E8 AB CD EF 01   call SetLastError
```
Both of them are saved inside the database, and they share the same semantic bytes sequence '6A E8'. Now, suppose you have to identify a function with two instructions like this:
```
6A 47            push 47
E8 11 22 33 44   call unknown
```
Snippet Detector is able to identify two semantic matches. This new function has the same semantic bytes sequence of snippet #1 and #2, but there's a big difference between the two snippets, that's why it's important to have more than one identical semantic bytes sequence.
Well, this is an extreme example because it doesn't have sense to save a short snippet, but it's important to take in mind that with multiple choices you can have the possibility to apply the most appropriate snippet.
* * *

###### SD_AddSnippet.py
The script is used to add a new snippet inside the preferred database (local or global).

To add a new snippet is pretty simple, you have to position the cursor inside the snippet you want to save and run the script. SD shows a dialog box asking for the local or global database. After that, if everything is ok you will have a new snippet inside the database.

_ _ _

###### SD_UpdateSnippet.py
Update information of an already saved snippet. You can change the name, the description and one or more comments. It's possible to update a snippet if and only if there's a syntactic match only.


To update a snippet you have to position the cursor inside the snippet you want to update and run the script.

_ _ _

###### SD_DeleteSnippet.py

Script used to delete a snippet from the local or global database. It's possible to delete a snippet if and only if there's a syntactic macth only.

To delete a snippet you have to position the cursor inside the snippet you want to delete and run the script.

_ _ _

###### SD_IdentifySnippets.py
Script used to identify snippets from the disassembled file. You can search known snippets from the local or global database.

Once a syntactic or semantic matching occurs SD automatically renames the function, adds the function description and all the necessary comments. It always happens except in case of a multiple semantic matching occurs. In this case, the script simply notes the multiple matches printing a message inside the output area. The message looks like:

```
[SNIPPET DETECTOR] Semantic match at 0x12345678
3 semantic snippets found:
Snippet 1
name: snippet_1_name
description: snippet_1_description
Snippet 2
name: snippet_2_name
description: snippet_2_description
Snippet 3
name: snippet_3_name
description: snippet_3_description
```
In this case the disassembled function is not modified. You can later apply one of the snippets using another script SD_IdentifyOneSnippet.

As I said before the script automatically renames the function name, and just in case the name is already inside IDA database you are asked to insert a new unused name.

_ _ _

###### SD_IdentifyOneSnippets.py
This script is the limited version of SD_IdentifySnippets because it tries to identify one snippet only. You can apply to every function you want to identify, and it's useful especially when you have to deal with multiple matches because it lets you decide what's the snippet to apply. To decide the snippet to apply you are asked to insert the number of the choosen snippet, nothing else.

* * *
##### INSTALLATION
SnippetDetector is an IDA Python script and it doesn't need external Python packages. It works with Python 2.7 (I haven't tested with previous versions). Install the scripts inside your preferred folder and start playing with SnippetDetector.