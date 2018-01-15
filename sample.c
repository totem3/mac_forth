#include <stdio.h>
#include <stdint.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <sys/stat.h>
#include "EXTERNAL_HEADERS/mach-o/loader.h"
#include "osfmk/mach/machine.h"

static uint8_t *mem;

void init() {
    unsigned int code_bytes = 640 * 1024;
    mem = (uint8_t*) mmap(
            NULL,
            code_bytes,
            PROT_READ | PROT_WRITE | PROT_EXEC,
            MAP_ANONYMOUS | MAP_PRIVATE,
            0,
            0);
}

typedef struct mach_header_64 mach_header_t;
typedef struct segment_command_64 segment_command_t;
typedef struct entry_point_command entry_point_command_t;
typedef struct dylinker_command dylinker_command_t;
typedef struct section_64 section_t;


#define origin 0x100000000
#define PLACEHOLDER (uint64_t)0
static void save(const char *filename) {
    uint64_t offset = 0;
    uint64_t vmaddr = 0x0000000100000000;
    uint64_t vmsize = 4096;
    uint64_t ncmds = 0;
    /* uint64_t vmsize = 0x0000000000000400; */

    mach_header_t *header = (mach_header_t*)mem + offset;
    header->magic = MH_MAGIC_64;
    header->cputype = (CPU_ARCH_ABI64 | CPU_TYPE_X86);
    header->cpusubtype = CPU_SUBTYPE_LIB64 | CPU_SUBTYPE_X86_64_ALL;
    header->filetype = MH_EXECUTE;
    header->flags = MH_PIE | MH_TWOLEVEL | MH_PRELOAD;

    offset += sizeof(mach_header_t);
    ncmds++;
    printf("1 offset %llu\n", offset);
    segment_command_t *seg1 = (segment_command_t*)(mem + offset);
    seg1->cmd = LC_SEGMENT_64;
    seg1->cmdsize = sizeof(segment_command_t);
    strcpy(seg1->segname, SEG_PAGEZERO);
    seg1->vmaddr = 0;
    seg1->vmsize = 0;//vmsize;
    seg1->fileoff = 0;
    seg1->filesize = 0;
    seg1->maxprot = (vm_prot_t)0x0;
    seg1->initprot = (vm_prot_t)0x0;
    seg1->nsects = 0;
    seg1->flags = 0;

    offset += (sizeof(segment_command_t));
    ncmds++;
    printf("2 offset %llu\n", offset);
    segment_command_t *seg2 = (segment_command_t*)(mem + offset);
    seg2->cmd = LC_SEGMENT_64;
    seg2->cmdsize = sizeof(segment_command_t) + sizeof(section_t);
    strcpy(seg2->segname, SEG_TEXT);
    seg2->vmaddr = vmaddr;
    seg2->vmsize = 0x10;//vmsize; // 0x0000000000002000;
    seg2->fileoff = 0;//start_of_data; // sizeof(mach_header_t) + sizeof(segment_command_t) * 2 + sizeof(entry_point_command_t);
    /* seg2->filesize = 0x120; */
    seg2->filesize = 0x10;
    seg2->maxprot = (vm_prot_t)0x7;
    seg2->initprot = (vm_prot_t)0x5;
    seg2->nsects = 1;
    seg2->flags = 0;

    offset += (sizeof(segment_command_t));
    printf("3 offset %llu\n", offset);

    section_t *text_section = (section_t*)(mem + offset);
    strcpy(text_section->sectname, "__text");
    strcpy(text_section->segname, "__TEXT");
    printf("start_of_data %llx\n", PLACEHOLDER);
    text_section->addr = vmaddr + PLACEHOLDER;
    text_section->size = 0x10;
    text_section->offset = PLACEHOLDER;
    text_section->align = 4;
    text_section->nreloc = 0;
    text_section->flags = S_ATTR_PURE_INSTRUCTIONS |  S_ATTR_SOME_INSTRUCTIONS;

    printf("vmaddr + vmsize = %llx\n", seg2->vmaddr + seg2->vmsize);
    printf("addr + size = %llx\n", text_section->addr + text_section->size);

    offset += (sizeof(section_t));
    ncmds++;
    printf("4 offset %llu\n", offset);
    entry_point_command_t *entry = (entry_point_command_t*)(mem + offset);
    entry->cmd = LC_MAIN;
    entry->cmdsize = 24;
    entry->entryoff = 0;
    entry->stacksize = 0;

    offset += sizeof(entry_point_command_t);
    ncmds++;
    dylinker_command_t *dylinker = (dylinker_command_t*)(mem + offset);
    dylinker->cmd = LC_LOAD_DYLINKER + 20;
    dylinker->cmdsize = sizeof(dylinker_command_t);
    union lc_str name = { 0x0c };
    dylinker->name = name;
    offset += sizeof(dylinker_command_t);
    strncpy((char*)(mem+offset), "/usr/lib/dyld", 20);


    header->ncmds = ncmds;
    header->sizeofcmds = offset - sizeof(mach_header_t);

    offset += 20;
    printf("5 offset %llu\n", offset);
    mem[offset++] = 0x00;
    mem[offset++] = 0x55;
    mem[offset++] = 0x48;
    mem[offset++] = 0x89;
    mem[offset++] = 0xE5;
    mem[offset++] = 0x31;
    mem[offset++] = 0xC0;
    mem[offset++] = 0xC7;
    mem[offset++] = 0x45;
    mem[offset++] = 0xFC;
    mem[offset++] = 0x00;
    mem[offset++] = 0x00;
    mem[offset++] = 0x00;
    mem[offset++] = 0x00;
    mem[offset++] = 0x5D;
    mem[offset++] = 0xC3;

    FILE *fp = fopen(filename, "wb");
    /* fwrite(mem, 1, 0x200, fp); */
    printf("start_of_data %llu\n", PLACEHOLDER);
    /* fwrite(mem, 1, start_of_data + 8, fp); */
    fwrite(mem, 1, 4096, fp);
    fclose(fp);
    chmod(filename, 0777);
}

int main(int argc, char **argv) {
  init();
  if (1 < argc) save(argv[1]);
  return 0;
}
