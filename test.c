#include "./forth0.c"

static void hello(void) {
  printf("hello\n");
}

int main() {
  init();

  begin_def("lit42", 0);
  B(0x48),B(0x83),B(0xeb),B(0x08); // SUB RBX, 8
  B(0x48),B(0xc7),B(0x03),D(42);   // MOV QWORD PTR [RBX], 42
  B(0xc3); // RET
  end_def();

  execute(find_word("lit42"));
  printf("%hhu", sp[0]);

  return 0;
}
