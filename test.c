#include "./forth0.c"

int main () {
  init();

  begin_def("nop1", 0); B(0xc3 /* RET */); end_def();
  begin_def("nop2", 0); B(0xc3 /* RET */); end_def();
  printf("%s\n", WORD_NAME(find_word("nop1"))); // nop1 が表示される
  printf("%s\n", WORD_NAME(find_word("nop2"))); // nop2 が表示される
  ((void(*)())WORD_BODY(find_word("nop1")))(); // クラッシュしない
  ((void(*)())WORD_BODY(find_word("nop2")))(); // クラッシュしない
  printf("%p\n",find_word("nop3")); // ヌルポインタ的な何かが表示される(表示内容は処理系定義)
  printf("OK!\n");
  return 0;
}
