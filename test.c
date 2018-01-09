#include "./forth0.c"

static void hello(void) {
  printf("hello\n");
}

int main () {
  init();

  begin_def("hello", 0);
  B(0x55);                         // PUSH RBP
  B(0x48),B(0x89),B(0xe5);         // MOV RBP, RSP
  B(0x48),B(0x83),B(0xec),B(0x20); // SUB RSP, 32
  B(0x48),B(0x83),B(0xe4),B(0xf0); // AND RSP, ~0xf
  B(0x48),B(0xb8),Q(hello);        // MOV RAX, hello
  B(0xff),B(0xd0);                 // CALL RAX
  B(0x48),B(0x89),B(0xec);         // MOV RSP, RBP
  B(0x5d);                         // POP RBP
  B(0xc3);                         // RET
  end_def();

  ((void(*)())WORD_BODY(find_word("hello")))();

  return 0;
}
