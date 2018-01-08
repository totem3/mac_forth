#include <stdio.h>
#include <stdint.h>
#include <sys/mman.h>
#include <string.h>

// hello と表示して 42 を返す関数
static uint64_t hello42(void) {
  printf("hello\n");
  return 42;
}

int main() {
  unsigned int codeBytes = 4096;
  // 1. 読み書き実行可能なメモリ領域を確保
  uint8_t *mem = mmap(
       NULL,
       codeBytes,
       PROT_READ | PROT_WRITE | PROT_EXEC,
       MAP_ANONYMOUS | MAP_PRIVATE,
       0,
       0);

  // 2. 確保したメモリ領域にプログラムを書き込む
  uint8_t prog[] = {0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x20, 0x48, 0x83, 0xe4, 0xf0, 0xff, 0xd7, 0x48, 0x89, 0xec, 0x5d, 0xc3};
  memcpy(mem, prog, 19);
  /* mem[ 0] = 0x55;                                                 // PUSH RBP */
  /* mem[ 1] = 0x48; mem[ 2] = 0x89; mem[ 3] = 0xe5;                 // MOV RBP, RSP */
  /* mem[ 4] = 0x48; mem[ 5] = 0x83; mem[ 6] = 0xec; mem[ 7] = 0x20; // SUB RSP, 32 */
  /* mem[ 8] = 0x48; mem[ 9] = 0x83; mem[10] = 0xe4; mem[11] = 0xf0; // AND, RSP, ~0xf */
  /* mem[12] = 0xff; mem[13] = 0xd7;                                 // CALL RDI やっぱりここがおかしい */
  /* mem[14] = 0x48; mem[15] = 0x89; mem[16] = 0xec;                 // MOV RSP, RBP */
  /* mem[17] = 0x5d;                                                 // POP RBP */
  /* mem[18] = 0xc3;                                                 // RET */

 (*(uint8_t **)(mem+18)) = 0x99999;
  // 3. 書き込んだプログラムを実行
  uint64_t ret = ((uint64_t(*)(void *))(mem))(hello42);

  printf("%llu\n", ret);
  return 0;
}
