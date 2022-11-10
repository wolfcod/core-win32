I like code refactoring, so, after around 7 years from ]HackingTeam[ leak... I want to play refactoring this old project.
It's just a refactoring, nothing about functionality.

## Journal
The code base is full of problems, written in a mix of C, C++ and some routine in assembly, with inline assembly function as macro.
This does not allow to have a cross platform project (32/64/arm) and as results there are two project, 'H4DLL' and 'H64DLL' as *extension* of 32 bit version.

With the mitigations adopted in modern C++ compiler, a lot of warnings and errors are identified by the compiler.

Some header files are used as extension of a source code file, it turns out that is not possible to include multiple time the same file, particularly trying to push out some source code (which it's a non sense to have in the main object).


## core-win32
RCS Agent for Windows (32bit)

## core-win64
RCS Agent for Windows (64bit)


