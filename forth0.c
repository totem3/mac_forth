#include <stdio.h>
#include <stdint.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>

static uint8_t *mem;
static uint8_t *sp;

#define import           (mem+0x200)
#define import_limit     (mem+0x300)
#define startup          (mem+0x300)
#define startup_limit    (mem+0x320)
#define c_to_ft          (mem+0x320)
#define c_to_ft_limit    (mem+0x330)
#define word_definitions (mem+0x400)

#define ftmain (*(uint64_t *)(mem+0x3a8))
#define state  (*(uint64_t *)(mem+0x3b0))
#define fin    (*(FILE **)(mem+0x3b8))
#define token  ((char *)(mem+0x3c0))
#define mrd1   (*(uint8_t **)(mem+0x3e0))
#define mrd2   (*(uint8_t **)(mem+0x3e8))
#define ep     (*(uint8_t **)(mem+0x3f0))

#define WORD_SIZE(word) (((uint64_t *)(word))[-1])
#define WORD_HEAD(word) ((uint8_t *)(word)-WORD_SIZE(word))
#define WORD_NAME(word) ((char *)WORD_HEAD(word))
#define WORD_IMMEDIATE(word) (*(uint64_t *)(WORD_HEAD(word)+32))
#define WORD_BODY(word) (WORD_HEAD(word)+40)

#define B(b) (*(uint8_t *)ep=(uint8_t)(b),ep+=1)
#define D(d) (*(uint32_t *)ep=(uint32_t)(d),ep+=4)
#define Q(q) (*(uint64_t *)ep=(uint64_t)(q),ep+=8)

#define WORD_PREV(word) ((uint8_t *)(word)-WORD_SIZE(word))

static uint8_t *find_word(const char *name) {
  uint8_t *word = mrd2; // 最新のdefinition(most recent definition) へのポインタ
  while (WORD_SIZE(word)) {
    if (!strcmp(WORD_NAME(word), name)) return word;
    word = WORD_PREV(word);
  }
  return 0;
}

static void begin_def(const char *name, int immediate) {
    ep = mrd2;
    strncpy((char *)ep, name, 32); ep+=32;
    Q(immediate);
}

static void end_def(void) {
  Q(ep - mrd2 + 8); // size
  mrd2 = ep;
  ep = 0;
}

static void def_cfun(const char *name, void *cfun, int immediate) {
  begin_def(name, immediate);
  B(0x48),B(0x89),B(0xe5);         // MOV RBP, RSP
  B(0x48),B(0x83),B(0xec),B(0x20); // SUB RSP, 32
  B(0x48),B(0x83),B(0xe4),B(0xf0); // AND RSP, ~0xf0
  B(0x48),B(0xb8),Q(cfun);         // MOV RAX, cfun
  B(0xff),B(0xd0);                 // CALL RAX
  B(0x48),B(0x89),B(0xec);         // MOV RSP, RBP
  B(0xc3);                         // RET
  end_def();
}

static void execute(uint8_t *word) {
  sp = ((uint8_t *(*)(uint8_t *,uint8_t *))c_to_ft)(WORD_BODY(word),sp);
}

static void write_hex(uint8_t *outp, uint8_t *limit, const char *data) {
  for (int i = 0; data[i]; i += 3, ++outp) {
    if (limit <= outp) {
      printf("error: too many data: write_hex\n");
      exit(EXIT_FAILURE);
    }
    *outp = strtol(&data[i], 0, 16);
  }
}

void init() {
    unsigned int code_bytes = 640 * 1024;
    mem = (uint8_t*) mmap(
            NULL,
            code_bytes,
            PROT_READ | PROT_WRITE | PROT_EXEC,
            MAP_ANONYMOUS | MAP_PRIVATE,
            0,
            0);
    sp = mem + code_bytes;
    mrd2 = word_definitions;

    static const char *c_to_ft_image =
        "53 "       // PUSH RBX
        "55 "       // PUSH RBP
        "48 89 d3 " // MOV RBX, RDX
        "ff d7 "    // CALL RDI
        "48 89 d8 " // MOV RAX, RBX
        "5d "       // POP RBP
        "5b "       // POP RBX
        "c3 "       // RET
        ;
    write_hex(c_to_ft, c_to_ft_limit, c_to_ft_image);
}
