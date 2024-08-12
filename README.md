# H4DLL
H4DLL (32bit windows project) build in release => it's 694Kb

I like code refactoring, so, after around 7 years from ]HackingTeam[ leak... I want to play refactoring this old project.
It's just a refactoring, nothing about functionality.

## Issues
In the latest years, when I had time I spent some hours to understand how to refactor this project.
Actually, most of the comments available in the source code are only in italian, there is nothing about "debugging", like messages or other information useful to debug due the nature of this old project.

Trying to clean the source code in the past, I moved some "features" into different projects (folder /modules), but, if you cannot build a module for some reasons, there is a lot of code dependencies which prevent to link the final file.

Thinking about the project, it will be much easier to "delete" everything and to restart (considering right now most of the techniques and stuff present there are not valid), but the goal is just to refactor.. thinking how this project could be in modern era.

## Journal
The code base is full of problems, written in a mix of C, C++ and some routine in assembly, with inline assembly function as macro.
This does not allow to have a cross platform project (32/64/arm) and as results there are two project, 'H4DLL' and 'H64DLL' as *extension* of 32 bit version.

With the mitigations adopted in modern C++ compiler, a lot of warnings and errors are identified by the compiler.

Some header files are used as extension of a source code file, it turns out that is not possible to include multiple time the same file, particularly trying to push out some source code (which it's a non sense to have in the main object).


## core-win32
RCS Agent for Windows (32bit)

## core-win64
RCS Agent for Windows (64bit)


