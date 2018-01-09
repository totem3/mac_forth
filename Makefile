.PHONY: test
test:
	gcc -o test test.c && ./test

debug:
	gcc -o test test.c -g3 && lldb ./test
