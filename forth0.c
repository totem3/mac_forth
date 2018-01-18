#include <stdio.h>
#include <stdint.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <sys/stat.h>
#include "darwin-xnu/EXTERNAL_HEADERS/mach-o/loader.h"
#include "darwin-xnu/osfmk/mach/machine.h"
#include <assert.h>

static unsigned int code_bytes;
static uint8_t *mem;
static uint8_t *sp;

#define import           (mem+0xfb0+0x240)
#define import_limit     (mem+0xfb0+0x340)
#define startup          (mem+0xfb0+0x340)
#define startup_limit    (mem+0xfb0+0x360)
#define c_to_ft          (mem+0xfb0+0x360)
#define c_to_ft_limit    (mem+0xfb0+0x370)
#define word_definitions (mem+0xfb0+0x440)

#define ftmain (*(uint64_t *)(mem+0xfb0+0x3e8))
#define state  (*(uint64_t *)(mem+0xfb0+0x3f0))
#define fin    (*(FILE **)(mem+0xfb0+0x3f8))
#define token  ((char *)(mem+0xfb0+0x400))
#define mrd1   (*(uint8_t **)(mem+0xfb0+0x420))
#define mrd2   (*(uint8_t **)(mem+0xfb0+0x428))
#define ep     (*(uint8_t **)(mem+0xfb0+0x430))

/* #define import           (mem+0x200) */
/* #define import_limit     (mem+0x300) */
/* #define startup          (mem+0x300) */
/* #define startup_limit    (mem+0x320) */
/* #define c_to_ft          (mem+0x320) */
/* #define c_to_ft_limit    (mem+0x330) */
/* #define word_definitions (mem+0x400) */

/* #define ftmain (*(uint64_t *)(mem+0x3a8)) */
/* #define state  (*(uint64_t *)(mem+0x3b0)) */
/* #define fin    (*(FILE **)(mem+0x3b8)) */
/* #define token  ((char *)(mem+0x3c0)) */
/* #define mrd1   (*(uint8_t **)(mem+0x3e0)) */
/* #define mrd2   (*(uint8_t **)(mem+0x3e8)) */
/* #define ep     (*(uint8_t **)(mem+0x3f0)) */

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

static void parse_name(void) {
    token[0] = '\0';
    fscanf(fin, "%31s%*[^ \t\n\r]", token);
    getc(fin);
}

static void perform_compilation_semantics(uint8_t *word) {
  if (WORD_IMMEDIATE(word)) {
    execute(word);
  } else {
    B(0xe8),D(WORD_BODY(word) - (ep + 4));
  }
}

static void perform_interpretation_semantics(uint8_t *word) {
  execute(word);
}

static void text_interpreter(void) {
    while (1) {
        parse_name();

        if (token[0] == '\0') return;

        uint8_t *word = find_word(token);
        if (word) {
            if (state) {
                perform_compilation_semantics(word);
            } else {
                perform_interpretation_semantics(word);
            }
            continue;
        }

        char *p;
        long long i = strtoll(token, &p, 0);
        if (!*p) {
            if (state) {
                // compilation
                B(0x48),B(0x83),B(0xeb),B(0x08); // SUB RBX, 8
                B(0x48),B(0xb8),Q(i);            // MOV RAX, i
                B(0x48),B(0x89),B(0x03);         // MOV [RBX], RAX
            } else {
                // interpretation
                sp -= 8;
                *(int64_t *)sp = i;
            }
            continue;
        }

        printf("undefined word: %s\n", token);
        exit(EXIT_FAILURE);
    }
}

static void colon(void) {
    parse_name();
    begin_def(token, 0);
    state = 1;
}

static void semicolon(void) {
    B(0xc3);
    end_def();
    state = 0;
}

static void paren(void) {
    while (1) {
        int c = getc(fin);
        if (c == EOF || c == ')') return;
    }
}

static void X(void) {
  parse_name();
  B(strtol(token, 0, 0));
}

static void print_rdi_as_int(uint64_t n) {
  printf("%" PRId64, n);
  fflush(stdout);
}

static void print_args_as_int(uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
  printf("%llu %llu %llu %llu", a, b, c, d);
  fflush(stdout);
}

static void print_rdi_as_cstr(const char *s) {
  printf("%s", s);
  fflush(stdout);
}

static void s_quote(void) {
  B(0x48),B(0x83),B(0xeb),B(0x08); // SUB RBX, 8
  B(0x48),B(0x8d),B(0x05),D(8);    // LEA RAX, [RIP+8]
  B(0x48),B(0x89),B(0x03);         // MOV [RBX], RAX
  B(0xe9),D(0);                    // JMP REL32
  uint8_t *rel32 = ep;

  while (1) {
    int c = getc(fin);
    if (c == EOF || c == '"') break;
    if (c == '\\') c = getc(fin);
    B(c);
  }
  B(0);

  *(uint32_t *)(rel32 - 4) = ep - rel32;
}

void init() {
    code_bytes = 0xfb0 + 640 * 1024 + 152;
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
        "48 89 f3 " // MOV RBX, RSI
        "ff d7 "    // CALL RDI
        "48 89 d8 " // MOV RAX, RBX
        "5d "       // POP RBP
        "5b "       // POP RBX
        "c3 "       // RET
        ;
    write_hex(c_to_ft, c_to_ft_limit, c_to_ft_image);
    def_cfun(":", colon, 0);
    def_cfun(";", semicolon, 1);
    def_cfun("(", paren, 1);
    def_cfun("X", X, 1);
    def_cfun("print-rdi-as-int", print_rdi_as_int, 0);
    def_cfun("print-args-as-int", print_args_as_int, 1);
    def_cfun("print-rdi-as-cstr", print_rdi_as_cstr, 0);
    def_cfun("s\"", s_quote, 1);
    begin_def("base+", 0);
    B(0x48),B(0x8d),B(0x05),D(mem - (ep + 4)); // LEA RAX, [RIP - mem]
    B(0x48),B(0x01),B(0x03);                   // ADD [RBX], RAX
    B(0xc3);
    end_def();
}

typedef struct mach_header_64 mach_header_t;
typedef struct segment_command_64 segment_command_t;
typedef struct entry_point_command entry_point_command_t;

#define origin 0x100000000
static void save(const char *filename) {
    uint64_t offset = 0;
    uint64_t data_offset = 0;
    uint64_t ncmds = 0;
    uint64_t vmaddr = 0x0000000001000000;
    uint64_t vmsize = 0x0000000000100000;

    struct mach_header_64 *header = (struct mach_header_64*)mem;
    header->magic = MH_MAGIC_64;
    header->cputype = (CPU_ARCH_ABI64 | CPU_TYPE_X86);
    header->cpusubtype = CPU_SUBTYPE_LIB64 | CPU_SUBTYPE_X86_64_ALL;
    header->ncmds = 0;
    header->sizeofcmds = 0;
    header->filetype = MH_EXECUTE;
    header->flags = MH_PIE | MH_TWOLEVEL | MH_PRELOAD;

    offset += sizeof(struct mach_header_64);

    struct segment_command_64 *zero = (struct segment_command_64*)(mem + offset);
    zero->cmd = LC_SEGMENT_64;
    zero->cmdsize = sizeof(struct segment_command_64);
    zero->vmsize = vmaddr;
    strcpy(zero->segname, SEG_PAGEZERO);
    offset += sizeof(struct segment_command_64);
    ncmds += 1;

    struct segment_command_64 *text = (struct segment_command_64*)(mem + offset);
    text->cmd = LC_SEGMENT_64;
    text->cmdsize = sizeof(struct segment_command_64);
    strncpy(text->segname, SEG_TEXT, 16);
    text->vmaddr = vmaddr;
    text->fileoff = 0;
    text->vmsize = vmsize;
    /* text->vmsize = code_bytes - 0xfb; //vmsize; */
    text->filesize = code_bytes - 0xfb;
    printf("code_bytes %u\n", code_bytes);
    printf("filesize %llu\n", text->filesize);
    text->maxprot = 0x7;
    text->initprot = 0x7;
    uint32_t nsects = 0;
    text->nsects = nsects;
    text->flags = 0;

    offset += sizeof(struct segment_command_64);
    ncmds += 1;

    // section 0
    /* uint8_t prg[] = {0x48,0xc7,0xc0,0x02,0x00,0x00,0x00,0xc3}; */
    /* size_t prgsize = sizeof(prg); */

    struct section_64 *text_sect = (struct section_64*)(mem + offset);
    strncpy(text_sect->sectname, SECT_TEXT, 16);
    strncpy(text_sect->segname, SEG_TEXT, 16);
    text_sect->addr = 0; //vmaddr + offset
    /* text_sect->size = prgsize; */
    text_sect->offset = 0;
    text_sect->align = 0;
    text_sect->flags = 0x80000400;

    size_t prgsize = code_bytes - 0xfb0 - 152;
    printf("prgsize %zu\n", prgsize);
    text_sect->size = prgsize;
    offset += sizeof(struct section_64);
    data_offset += text_sect->size;
    nsects += 1;
    /* text->vmsize = prgsize; */
    /* text->filesize = prgsize; */

    text->nsects = nsects;
    text->cmdsize += (sizeof(struct section_64) * nsects);

    struct segment_command_64 *linkedit = (struct segment_command_64*)(mem+offset);
    linkedit->cmd = LC_SEGMENT_64;
    linkedit->cmdsize = sizeof(struct segment_command_64);
    strncpy(linkedit->segname, SEG_LINKEDIT, 16);
    linkedit->vmaddr = 0; // vmdadr + offset
    linkedit->vmsize = 4096;
    linkedit->fileoff = 4096;
    linkedit->filesize = 152;
    linkedit->maxprot = 7;
    linkedit->initprot = 1;

    offset += sizeof(struct segment_command_64);
    data_offset += 152;
    ncmds += 1;

    struct dyld_info_command *dyld_info_only = (struct dyld_info_command*)(mem+offset);
    dyld_info_only->cmd = LC_DYLD_INFO_ONLY;
    dyld_info_only->cmdsize = sizeof(struct dyld_info_command);
    dyld_info_only->export_off = 0xfb0 + 640 * 1024; //4096;
    dyld_info_only->export_size = 48;

    offset += sizeof(struct dyld_info_command);
    ncmds += 1;

    struct symtab_command *symtab = (struct symtab_command*)(mem + offset);
    symtab->cmd = LC_SYMTAB;
    symtab->cmdsize = sizeof(struct symtab_command);
    symtab->symoff = 640 * 1024 + 0xfb0 + 56; //4152; // 0x1038
    symtab->nsyms = 3;
    symtab->stroff = 640 * 1024 + 0xfb0 + 56 + 48; //4200; // 0x1068
    symtab->strsize = 48;

    offset += sizeof(struct symtab_command);
    ncmds += 1;

    struct dysymtab_command *dysymtab = (struct dysymtab_command*)(mem + offset);
    dysymtab->cmd = LC_DYSYMTAB;
    dysymtab->cmdsize = sizeof(struct dysymtab_command);
    dysymtab->nextdefsym = 2;
    dysymtab->iundefsym = 2;
    dysymtab->nundefsym = 1;

    offset += sizeof(struct dysymtab_command);
    ncmds += 1;

    struct dylinker_command* dylinker = (struct dylinker_command*)(mem + offset);
    dylinker->cmd = LC_LOAD_DYLINKER;
    dylinker->cmdsize = sizeof(struct dylinker_command) + 20;
    union lc_str name = {0x0c};
    dylinker->name = name;
    offset += sizeof(struct dylinker_command);
    strncpy((char*)(mem+offset), "/usr/lib/dyld", 20);

    offset += 20;
    ncmds += 1;

    struct entry_point_command *entry = (struct entry_point_command*)(mem + offset);
    entry->cmd = LC_MAIN;
    entry->cmdsize = sizeof(struct entry_point_command);
    entry->entryoff = (uint64_t)(startup-mem); //4016;
    entry->stacksize = 0;

    offset += sizeof(struct entry_point_command);
    ncmds += 1;

    struct dylib_command *dylib = (struct dylib_command*)(mem + offset);
    dylib->cmd = LC_LOAD_DYLIB;
    dylib->cmdsize = 56;// sizeof(struct dylib_command) + 0;
    union lc_str libname = {24};
    struct dylib lib = {
        .name = libname,
        .timestamp = 2,
        .current_version = 81148930,
        .compatibility_version = 65536
    };
    dylib->dylib = lib;

    offset += sizeof(struct dylib_command);

    strncpy((char*)mem+offset, "/usr/lib/libSystem.B.dylib", 32);

    offset += 32;
    ncmds += 1;

    header->ncmds = ncmds;
    header->sizeofcmds = offset - sizeof(struct mach_header_64);
    /* assert(header->sizeofcmds == 728); */

    if (offset < 0xfb0) {
        offset += (0xfb0 - offset);
    }

    text_sect->addr = vmaddr + offset;
    text_sect->offset = offset;

    /* memcpy((mem+offset), prg, sizeof(prg)); */
    offset += text_sect->size;
    printf("vmsize %u\n", code_bytes);
    printf("section size %llu\n", text_sect->size);
    printf("vmaddr + vmsize %llu\n", text->vmaddr + text->vmsize);
    printf("addr   + size   %llu\n", text_sect->addr + text_sect->size);
    assert(text->vmaddr + text->vmsize > text_sect->addr + text_sect->size);

    /* linkedit->vmaddr = vmaddr + 0x1000; //offset; */
    /* linkedit->vmaddr = vmaddr + 0xfb0+640*1024; //offset; */
    linkedit->fileoff = text_sect->offset + text_sect->size;
    linkedit->vmaddr = vmaddr + linkedit->fileoff;

    static const uint8_t startup_image[] = {
        0xbb, 0x00, 0x10, 0x4a, 0x00,
        0xbf, 0xa8, 0x13, 0x40, 0x00,
        0xff, 0x10,
        0xb8, 0xa0, 0x12, 0x40, 0x00,
        0xff, 0x10
    };
    memcpy(startup, startup_image, 19);


    FILE *fp = fopen(filename, "wb");
    fwrite(mem, 1, code_bytes, fp);
    fclose(fp);
    chmod(filename, 0777);
}

int main(int argc, char **argv) {
  init();
  fin = stdin;
  text_interpreter();
  if (1 < argc) save(argv[1]);
  return 0;
}
