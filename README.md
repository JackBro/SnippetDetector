#SnippetDetector
One year ago I blogged about a tool of mine I use to recognize snippets from a disassembled binary file. The tool often speeds up my dead list analysis process. The annoying thing is that it works in cooperation with IDA, and it's somehow a waste of time because I have to switch from one program to another and vice versa a lot of time. Since of IDA is the most used disassembler program out there I decided to morph my project into an IDA Python scripts project.

The project is called Snippet Detector (SD in short), and the aim is to collect as many disassembled snippets as I can. At the moment a snippet is indeed a defined function and it's everything saved inside a database. The info inside the database can be later applied to a new disassembled file hoping to find one or more matches.

My idea is to exchange the saved information about a malware (or a generic disassembled file) with someone else in an easy way. Suppose I put on the net my local SD database of Zeus malware, it's  available for everyone and you can use it as a local database increasing your possibility to reduce the analysis time facing a new malware born from Zeus source code. You can even use my database to understand obscure parts of the malware itself, just like a new form of a didactical approach. At last, but not least, it could be helpful when a group of people need to work on the same target because you can pass your findings to your collegue making the reversing session a little bit faster than usual.

###The database
There are basically two databases, a global and a local database. The global db is used to store all the snippets you collected during your analysis sessions. The local db is generally used to store some snippets only.
Why do I need two databases? You are not obliged to use both, you can work with one, another or both databases as you prefer. The idea is to have a global database with all the snippets you have added, and a local with snippets from the current disassembled file only.

Global and local databases are implemented as SQlite db. Global db is unique and it's stored inside SD folder; a local db is unique for a single disassembled file and it's located inside the disassembled file folder (under "SD_local_DB" name). Inside you hard disk you will have one global db and one or more local dbs.

###Syntactic and semantic matching
The check is done in two different levels: syntactic and semantic.
The syntactic matching is obvious, two instructions are identical if and only if they have the same bytes; apply this method to a series of instructions and you'll have the definition of a syntactic matching on snippets of code.
The idea behind the semantic match is easy to understand, but it needs a little introduction. Suppose to have:
```
C7 45 F8 38 5B 41 00   mov  dword ptr [ebp-8],  415B38h
C7 45 F4 34 12 40 00   mov  dword ptr [ebp-0C], 401234h
```
Two mov instructions with different bytes definition, but both of them are used to move a dword value into a dword in memory.
The idea is to convert every instruction of the snippet into another one without changing the semantic meaning of it. The conversion is simply done removing the operand(s). After the conversion I'll get something like that:
```
C7 45   mov  dword ptr [ebp-byte_val], dword_val
C7 45   mov  dword ptr [ebp-byte_val], dword_val
```
In their simplified form the two instructions are semantically identical.

This is exactly the core of my idea, if the meaning of two instructions is the same (syntactic or semantic) I could say they are used for the same thing. Applying these facts to a series of instructions I came up with the idea of this tool.

###Python scripts

The pack contains eight files, but only some of them are directly executed as an IDA Python script:

- SD_AddSnippet.py: add a new snippet to the database. You decide to save the snippet inside the local or global database. The global database is located inside the script folder, the local database is inside the disassembled file folder. It saves the next informations:
   - snippet name: directly taken from the name of the function
   - snippet description: taken from the comment (if there's one) of the function
   - syntactic bytes sequence
   - semantic bytes sequence
   - snippet comments: all the instructions comment
- SD_DeleteSnippet.py: delete a snippet from the local or global database
- SD_UpdateSnippet.py: update information of an already saved snippet. It's possible to update the name/description/comments
- SD_IdentifyOneSnippet.py: try to identify one snippet only
- SD_IdentifySnippets.py: try to identify all the snippets of the disassembled file. It scans all the functions inside the currently disassembled file trying to find a possible match in the local/global database (syntactic/semantic match)

The next files are used by the previous ones:
- SD_db.py: class used to define all SQlite related operations needed by Snippet Detector scripts
- SD_Common.py: common functions definition class
- SD_Semantic.py: semantic related stuff

###Installation
To install Snippet Detector, just copy every .py file inside your preferred folder.

###Practical example
Here is a brief explanation of Snippet Detector in practice. Look inside 'Test sample' folder, I have created a simple and minimal local database with few snippets from Zeus malware (hash: 70c1be0e03046d03c02d1ffc4a858653, pwd is 'infected'). There are only 10 saved snippets taken from various parts of the file:
```
	Core::initOSBasic
	Core::GetPeSettingsPath
	Crypt::crc32Hash
	Fs::_pathCombine
	MalwareTools::_getOsGuid
	MalwareTools::_generateKernelObjectName
	Process::_getUserByProcessHandle
	Registry::_setValueAsBinary
	Wahook::checkAvalibleBytes
	WinSecurity::_getUserByToken
```
To save a snippet is really simple, once you have completed the analysis of the function, point the cursor inside one of the instructions of the function and run SD_AddSnippet.py script. Select local or global database, nothing else.
Now, suppose you need to analyze Kins malware (hash: 7b5ac02e80029ac05f04fa5881a911b2, pwd is 'infected'), it's now obvious that there are some correspondences between the two malwares, but in the past it was not so obvious. Anyway, put SD_local_DB folder inside the Kins folder; now, you can run SD_IdentifySnippets.py hoping to find some matches (don't forget to use the local database). Once the script has been totally executed you'll see the report of the operation:
```
[SNIPPET DETECTOR] Semantic match at 0x407711
Snippet name: core_initOsBasic
Snippet description: static bool __inline initOsBasic(DWORD flags)

[SNIPPET DETECTOR] Semantic match at 0x41A7DB
Snippet name: Crypt_crc32Hash
Snippet description: DWORD Crypt::crc32Hash(const void *data, DWORD size)

[SNIPPET DETECTOR] Semantic match at 0x41AA43
Snippet name: Process__getUserByProcessHandle
Snippet description: TOKEN_USER *Process::_getUserByProcessHandle(HANDLE process, LPDWORD sessionId)


[SNIPPET DETECTOR] Semantic match at 0x41CAAE
Snippet name: WinSecurity__getUserByToken
Snippet description: TOKEN_USER *WinSecurity::_getUserByToken(HANDLE token)

[SNIPPET DETECTOR] Semantic match at 0x41D630
Snippet name: Registry__setValueAsBinary
Snippet description: bool Registry::_setValueAsBinary(HKEY key, const LPWSTR subKey, const LPWSTR value, DWORD type, const void *buffer, DWORD bufferSize)

[SNIPPET DETECTOR] Semantic match at 0x41DBA1
Snippet name: wahook_checkAvalibleBytes
Snippet description: static DWORD_PTR checkAvalibleBytes(HANDLE process, void *address)

[SNIPPET DETECTOR] Semantic match at 0x41EC8D
Snippet name: Fs__pathCombine
Snippet description: bool Fs::_pathCombine(LPWSTR dest, const LPWSTR dir, const LPWSTR file)

[SNIPPET DETECTOR] 0 syntactic snippet, 7 semantic snippet and 0 multiple matches has been found
```
SD is able to semantically identify 7 of 10 functions (it's quite hard to find a syntactic match, you should know why...), and you can now start checking the file with a little initial help. I have also added a 'multiple matches' voice in case there's a semantic corrispondence with more than one saved snippet. In this case you can decide what's the best snippet to apply, just use SD_IdentifyOneSnippet.py script.

###In the end
Snippet Detector is in early beta version, I'm planning to add some more features in the future. Feel free to report bugs/comments/criticisms directly to my mail address.
