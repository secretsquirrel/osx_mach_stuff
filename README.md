# OSX Mach Stuff


Nemo's work from uniformed back in 2006 on mach programming.

Updating the code to 10.10 for a mental exercise and to learn mach programming.

## Chapter 7 replacing ptrace


Chapter 7 is where it really starts from a programming POV.

To see the example working:


		On 10.10:
		gcc -o chapter_7 chapter_7.c

		brew install nasm

		nasm -f macho64 test.asm -o test.o  && ld -e _main -macosx_version_min 10.8 -arch x86_64 test.o -lSystem

		./a.out &
		sudo ./chapter_7 [a.out pid]
		[snip output]

