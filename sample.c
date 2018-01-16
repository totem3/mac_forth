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
    uint64_t filesize = 1024;

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

    offset += (sizeof(segment_command_t));
    ncmds++;
    printf("2 offset %llu\n", offset);

    // {{{ TEXT SEGMENT
    segment_command_t *text_seg = (segment_command_t*)(mem + offset);
    text_seg->cmd = LC_SEGMENT_64;
    text_seg->cmdsize = sizeof(segment_command_t) + sizeof(section_t);
    strcpy(text_seg->segname, SEG_TEXT);
    text_seg->vmaddr = vmaddr;
    text_seg->vmsize = vmsize; // 0x0000000000002000;
    text_seg->fileoff = 0;//start_of_data; // sizeof(mach_header_t) + sizeof(segment_command_t) * 2 + sizeof(entry_point_command_t);
    text_seg->filesize = 0; // filesize;//0x10;
    text_seg->maxprot = VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE;
    text_seg->initprot = VM_PROT_READ | VM_PROT_EXECUTE;
    text_seg->nsects = 1;
    text_seg->flags = 0;
    /// TEXT SEGMENT }}}


    offset += (sizeof(segment_command_t));
    printf("3 offset %llu\n", offset);

    /// {{{ TEXT SECTION
    section_t *text_section = (section_t*)(mem + offset);
    strcpy(text_section->sectname, SECT_TEXT);
    strcpy(text_section->segname, SEG_TEXT);
    text_section->align = 4;
    text_section->nreloc = 0;
    text_section->flags = S_ATTR_PURE_INSTRUCTIONS |  S_ATTR_SOME_INSTRUCTIONS;
    // TEXT SECTION }}}

    offset += (sizeof(section_t));
    ncmds++;
    printf("4 offset %llu\n", offset);

    /// {{{ ENTRY POINT
    entry_point_command_t *entry = (entry_point_command_t*)(mem + offset);
    entry->cmd = LC_MAIN;
    entry->cmdsize = 24;
    entry->entryoff = 0;
    entry->stacksize = 0;
    //  ENTRY POINT}}}

    offset += sizeof(entry_point_command_t);
    ncmds++;

    /// {{{ DYLINKER COMMAND
    dylinker_command_t *dylinker = (dylinker_command_t*)(mem + offset);
    dylinker->cmd = LC_LOAD_DYLINKER;
    dylinker->cmdsize = sizeof(dylinker_command_t) + 20 + 8;
    union lc_str name = { 0x0c };
    dylinker->name = name;
    offset += sizeof(dylinker_command_t);
    strncpy((char*)(mem+offset), "/usr/lib/dyld", 20 + 8);
    // DYLINKER COMMAND }}}

    offset += 20 + 8;

    // fill header
    header->ncmds = ncmds;
    header->sizeofcmds = offset - sizeof(mach_header_t);

    // fill textsegment
    printf("offset %llud\n", offset);
    text_seg->filesize = offset;

    // fill text_section
    text_section->addr = vmaddr + offset;
    text_section->size = 0x10;
    text_section->offset = offset;

    // fill entry
    entry->entryoff = offset;

    uint64_t vm_end = text_seg->vmaddr + text_seg->vmsize;
    uint64_t section_end = text_section->addr + text_section->size;
    printf("vmaddr + vmsize = %llx\n", text_seg->vmaddr + text_seg->vmsize);
    printf("addr + size = %llx\n", text_section->addr + text_section->size);

    if (section_end > vm_end) {
        printf("failed\n");
        return;
    }


    printf("5 offset %llu\n", offset);
    uint8_t prog[16] = {0x55,0x48,0x89,0xE5,0x31,0xC0,0xC7,0x45,0xFC,0x00,0x00,0x00,0x00,0x5D,0xC3, 0x00};
    memcpy(mem+offset, prog, 16);

    FILE *fp = fopen(filename, "wb");
    /* fwrite(mem, 1, 0x200, fp); */
    printf("start_of_data %llu\n", offset);
    fwrite(mem, 1, 4096, fp);
    fclose(fp);
    chmod(filename, 0777);
}

int main(int argc, char **argv) {
  init();
  if (1 < argc) save(argv[1]);
  return 0;
}
