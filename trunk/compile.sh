#Remove the -m64 option to compile for IA32
gcc -D_KERNEL -mcmodel=kernel -m64 -mno-red-zone -c ./sol_xl.c
ld -dy -r -N"misc/gld" sol_xl.o -o sol_xl
