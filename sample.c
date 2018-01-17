#include <stdio.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include "osfmk/mach/machine.h"
#include "EXTERNAL_HEADERS/mach-o/loader.h"
#include <string.h>
#include <assert.h>

void print_sect(const struct section_64* scp) {
    printf("section %s in %s\n", scp->sectname, scp->segname);
    printf("->addr %llx\n", scp->addr);
    printf("->size %llx\n", scp->size);
    printf("->offset %x\n", scp->offset);
    printf("->align %x\n", scp->align);
    printf("->flags %x\n", scp->flags);
}

int main()
{
    unsigned int code_bytes = 5 * 1024;
    uint8_t* mem = (uint8_t*) mmap(
            NULL,
            code_bytes,
            PROT_READ | PROT_WRITE | PROT_EXEC,
            MAP_ANONYMOUS | MAP_PRIVATE,
            0,
            0);
    uint64_t offset = 0;
    uint64_t data_offset = 0;
    uint64_t ncmds = 0;
    uint64_t vmaddr = 0x0000000100000000;
    uint64_t vmsize = 0x0000000000001000;

    struct mach_header_64 *header = (struct mach_header_64*)mem;
    header->magic = MH_MAGIC_64;
    header->cputype = (CPU_ARCH_ABI64 | CPU_TYPE_X86);
    header->cpusubtype = CPU_SUBTYPE_LIB64 | CPU_SUBTYPE_X86_64_ALL;
    header->ncmds = 0;
    header->sizeofcmds = 0;
    header->filetype = MH_EXECUTE;
    header->flags = MH_PIE | MH_TWOLEVEL | MH_PRELOAD;

    offset += sizeof(struct mach_header_64);

    printf("sizeof segment %lu\n", sizeof(struct segment_command_64));
    printf("sizeof section %lu\n", sizeof(struct section_64));
    printf("offset %llu\n", offset);
    struct segment_command_64 *zero = (struct segment_command_64*)(mem + offset);
    zero->cmd = LC_SEGMENT_64;
    zero->cmdsize = sizeof(struct segment_command_64);
    zero->vmsize = vmaddr;
    strcpy(zero->segname, SEG_PAGEZERO);
    offset += sizeof(struct segment_command_64);
    ncmds += 1;

    printf("offset %llu\n", offset);
    struct segment_command_64 *text = (struct segment_command_64*)(mem + offset);
    text->cmd = LC_SEGMENT_64;
    text->cmdsize = sizeof(struct segment_command_64);
    strncpy(text->segname, SEG_TEXT, 16);
    text->vmaddr = vmaddr;
    text->vmsize = vmsize;
    text->fileoff = 0;
    text->filesize = 4096;
    text->maxprot = 0x7;
    text->initprot = 0x5;
    uint32_t nsects = 0;
    text->nsects = nsects;
    text->flags = 0;

    offset += sizeof(struct segment_command_64);
    ncmds += 1;

    // section 0
    printf("offset %llu\n", offset);
    struct section_64 *text_sect = (struct section_64*)(mem + offset);
    strncpy(text_sect->sectname, SECT_TEXT, 16);
    strncpy(text_sect->segname, SEG_TEXT, 16);
    text_sect->addr = 0; //vmaddr + offset
    text_sect->size = 8;
    text_sect->offset = 0;
    text_sect->align = 0;
    text_sect->flags = 0x80000400;

    offset += sizeof(struct section_64);
    data_offset += 8;
    nsects += 1;

    // section 1
    printf("offset %llu\n", offset);
    struct section_64 *unwind_sect = (struct section_64*)(mem + offset);
    strncpy(unwind_sect->sectname, "__unwind_info", 16);
    strncpy(unwind_sect->segname, SEG_TEXT, 16);
    unwind_sect->addr = 0; //vmaddr + offset
    unwind_sect->size = 0x48;
    unwind_sect->offset = 0;
    unwind_sect->align = 2;
    unwind_sect->flags = 0x80000400;

    nsects += 1;
    offset += sizeof(struct section_64);

    data_offset += 0x48;
    text->nsects = nsects;
    text->cmdsize += (sizeof(struct section_64) * nsects);
    printf("text->nsects %d\n", text->nsects);
    printf("sizeof segment %lu\n", sizeof(struct segment_command_64));
    printf("sizeof section %lu\n", sizeof(struct section_64));
    printf("text->cmdsize %d\n", text->cmdsize);

    printf("linkedit offset %llu\n", offset);
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
    dyld_info_only->export_off = 4096;
    dyld_info_only->export_size = 48;

    offset += sizeof(struct segment_command_64);
    data_offset += 152;
    ncmds += 1;

    struct symtab_command *symtab = (struct symtab_command*)(mem + offset);
    symtab->cmd = LC_SYMTAB;
    symtab->cmdsize = sizeof(struct symtab_command);
    symtab->symoff = 4152; // 0x1038
    symtab->nsyms = 3;
    symtab->stroff = 4200; // 0x1068
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

    struct uuid_command* uuid = (struct uuid_command*)(mem + offset);
    uuid->cmd = LC_UUID;
    uuid->cmdsize = sizeof(struct uuid_command);
    /* uuid->uuid = 0;*/

    offset += sizeof(struct uuid_command);
    ncmds += 1;

    struct version_min_command *version = (struct version_min_command*)(mem + offset);
    version->cmd = LC_VERSION_MIN_MACOSX;
    version->cmdsize = sizeof(struct version_min_command);
    version->version = 658432;
    version->sdk = 658432;

    offset += sizeof(struct version_min_command);
    ncmds += 1;

    struct source_version_command *source = (struct source_version_command*)(mem + offset);
    source->cmd = LC_SOURCE_VERSION;
    source->cmdsize = sizeof(struct source_version_command);
    source->version = 0;

    offset += sizeof(struct source_version_command);
    ncmds += 1;

    struct entry_point_command *entry = (struct entry_point_command*)(mem + offset);
    entry->cmd = LC_MAIN;
    entry->cmdsize = sizeof(struct entry_point_command);
    entry->entryoff = 4016;
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
        .current_version = 1684210434,
        .compatibility_version = 65536
    };
    dylib->dylib = lib;

    offset += sizeof(struct dylib_command);

    strncpy((char*)mem+offset, "/usr/lib/libSystem.B.dylib", 32);

    offset += 32;
    ncmds += 1;

    struct linkedit_data_command *function_start = (struct linkedit_data_command*)(mem+offset);
    function_start->cmd = LC_FUNCTION_STARTS;
    function_start->cmdsize = sizeof(struct linkedit_data_command);
    function_start->dataoff = 4144;
    function_start->datasize = 8;

    offset += sizeof(struct linkedit_data_command);
    ncmds += 1;


    struct linkedit_data_command *data_in_code = (struct linkedit_data_command*)(mem+offset);
    data_in_code->cmd = LC_DATA_IN_CODE;
    data_in_code->cmdsize = sizeof(struct linkedit_data_command);
    data_in_code->dataoff = 3152;
    data_in_code->datasize = 0;

    offset += sizeof(struct linkedit_data_command);
    ncmds += 1;

    header->ncmds = ncmds;
    printf("offset %llu\n", offset);
    printf("header %lu\n", sizeof(struct mach_header_64));
    header->sizeofcmds = offset - sizeof(struct mach_header_64);
    /* assert(header->sizeofcmds == 728); */

    offset += 0x0cb0;

    text_sect->addr = vmaddr + offset;
    text_sect->offset = offset;

    offset += text_sect->size;

    unwind_sect->addr = vmaddr + offset;
    unwind_sect->offset = offset;

    offset += unwind_sect->size;

    linkedit->vmaddr = vmaddr + 0x1000; //offset;
    printf("inkedit vmaddr %llx\n", vmaddr + offset);
    printf("inkedit vmaddr %llu\n", vmaddr + offset);

    printf("----- header -----\n");
    printf("header->magic %d\n", header->magic);
    printf("header->cputype %d\n", header->cputype);
    printf("header->cpusubtype %d\n", header->cpusubtype);
    printf("header->ncmds %d\n", header->ncmds);
    printf("header->sizeofcmds %d\n", header->sizeofcmds);
    printf("header->filetype %d\n", header->filetype);
    printf("header->flags %d\n", header->flags);

    print_sect(text_sect);
    print_sect(unwind_sect);

    char* filename = "foo";
    FILE *fp = fopen(filename, "wb");
    /* fwrite(mem, 1, 0x200, fp); */
    printf("start_of_data %llu\n", offset);
    fwrite(mem, 1, 4096, fp);
    fclose(fp);
    chmod(filename, 0777);
    return 0;
}
