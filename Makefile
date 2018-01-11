.PHONY: test
test:
	gcc -o test test.c && ls tests/* | xargs -I {} ./test_ft {}

debug:
	gcc -o test test.c -O0 -g3 -m32 && lldb ./test
