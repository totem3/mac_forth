#include "./forth0.c"

int main () {
  init();

  // nop1 を定義する
  begin_def("nop1", 0);
  B(0xc3); // RET
  end_def();

  // フィールドアクセス用マクロが動くかテスト
  printf("%s\n", WORD_NAME(mrd2)); // nop1 と表示される
  printf("%llu\n", WORD_IMMEDIATE(mrd2)); // 0 と表示される
  printf("%x\n", *WORD_BODY(mrd2)); // c3 と表示される
  printf("%llu\n", WORD_SIZE(mrd2)); // 49 と表示される
  ((void(*)())WORD_BODY(mrd2))(); // クラッシュしないはず
  printf("OK!\n");
  return 0;
}
