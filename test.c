#include "./forth0.c"

static void hello(void) {
  printf("hello\n");
}

int main () {
  init();

  def_cfun("hello", hello, 0);
  ((void(*)())WORD_BODY(find_word("hello")))();

  return 0;
}
