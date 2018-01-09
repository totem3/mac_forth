#include "./forth0.c"

static void hello(void) { printf("hello, "); }
static void world(void) { printf("world!\n"); }

int main() {
  init();

  def_cfun("hello", hello, 0);
  def_cfun("world", world, 0);

  fin = stdin;
  text_interpreter();

  return 0;
}
