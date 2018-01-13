.PHONY: build
build:
	gcc -o forth0 forth0.c ; echo ": main ;" | ./forth0 foo
test:
	gcc -o test test.c && ls tests/* | xargs -I {} ./test_ft {}

debug:
	gcc -o test test.c -O0 -g3 && lldb ./test
