

_Bool success = 0;

#include "sys/ioccom.h"
#include <stdio.h>
#include <stdlib.h>
#include <system_service.h>
#include <orbis2d.h>
#include <orbisPad.h>
#include <orbisAudio.h>
#include <orbisKeyboard.h>
#include <modplayer.h>
#include <ps4link.h>
#include <debugnet.h>
#include <orbissys.h>
#include <pl_ini.h>
#include <string.h>


#include <unistd.h>

#include <elfloader.h>

#include <ps4/error.h>
#include <kernel.h>

#define	KERN_PRINTF		0x0436040
#define	KERN_BASE_PTR 		0x00001C0
#define	KERN_COPYOUT		0x01ea630
#define	KERN_BZERO		0x01ea510 
#define	KERN_PRISON0 		0x10986A0
#define	KERN_ROOTVNODE 		0x22C1A70
#define KERN_DUMPSIZE 		108806144
#define	KERN_405_XFAST_SYSCALL		0x30EB30	// #3
#define	KERN_474_XFAST_SYSCALL		0x30B7D0	// #3
#define	KERN_455_XFAST_SYSCALL		0x3095D0	// #2
#define	KERN_501_XFAST_SYSCALL		0x1C0		// #1
#define	KERN_505_XFAST_SYSCALL		0x1C0		// #1
#define KERN_405_PRISON_0		0xF26010
#define KERN_455_PRISON_0		0x10399B0
//
#define KERN_474_PRISON_0		0x01042AB0
#define KERN_474_ROOTVNODE		0x021B89E0
//
#define KERN_501_PRISON_0		0x10986A0
#define KERN_505_PRISON_0		0x10986A0
#define KERN_405_ROOTVNODE		0x206D250
#define KERN_455_ROOTVNODE		0x21AFA30
#define KERN_501_ROOTVNODE		0x22C19F0
#define KERN_505_ROOTVNODE		0x22C1A70
#define KERN_405_PRINTF			0x347580
#define KERN_455_PRINTF			0x17F30
#define KERN_501_PRINTF			0x435C70
#define KERN_505_PRINTF			0x436040
#define KERN_405_COPYIN			0x286DF0
#define KERN_405_COPYOUT		0x286D70
#define KERN_455_COPYOUT		0x14A7B0
#define KERN_501_COPYOUT		0x1EA520
#define KERN_505_COPYOUT		0x1EA630
#define KERN_405_MEMSET_ALIGNED		0
#define KERN_455_MEMSET_ALIGNED		0x302BD0
#define KERN_501_MEMSET_ALIGNED		0x3201F0
#define KERN_505_MEMSET_ALIGNED		0x3205C0
#define KERN_405_BZERO_ALIGNED		0x286C30
#define KERN_455_BZERO_ALIGNED		0x14A570
#define KERN_501_BZERO_ALIGNED		0x1EA360
#define KERN_505_BZERO_ALIGNED		0x1EA470


#define TRUE 1
#define FALSE 0

struct filedesc {
	void *useless1[3];
	void *fd_rdir;
	void *fd_jdir;
};

struct proc {
	char useless[64];
	struct ucred *p_ucred;
	struct filedesc *p_fd;
};

struct thread {
	void *useless;
	struct proc *td_proc;
};

struct auditinfo_addr {
	char useless[184];
};

struct ucred {
	uint32_t useless1;
	uint32_t cr_uid;     // effective user id
	uint32_t cr_ruid;    // real user id
	uint32_t useless2;
	uint32_t useless3;
	uint32_t cr_rgid;    // real group id
	uint32_t useless4;
	void *useless5;
	void *useless6;
	void *cr_prison;     // jail(2)
	void *useless7;
	uint32_t useless8;
	void *useless9[2];
	void *useless10;
	struct auditinfo_addr useless11;
	uint32_t *cr_groups; // groups
	uint32_t useless12;
};


long syscall(long num, ...) {
	int64_t result = 0;                               // Storage for the result value.	
	__asm__(".intel_syntax noprefix\n"                // No need to shift anythign here, registers are already set up.
		"xor rax, rax\n"                              // We just need to make sure that rax, the register which holds the syscall number, holds 0 for syscall0.		
		"syscall"                                     // Now we just call the kernel and automaticly the correct registers are used.
		: "=a" (result)                               // Pipe return value in our function.
		::                                            // No input, no clobbering.
	);
	return result;                                    // Return the result to the caller.
}

#define TRUE 1
#define FALSE 0

typedef struct OrbisGlobalConf
{
	Orbis2dConfig *conf;
	OrbisPadConfig *confPad;
	OrbisAudioConfig *confAudio;
	OrbisKeyboardConfig *confKeyboard;
	ps4LinkConfiguration *confLink;
	int orbisLinkFlag;
}OrbisGlobalConf;

OrbisGlobalConf globalConf;
#define SCE_LIBC_HEAP_SIZE_EXTENDED_ALLOC_NO_LIMIT (0xffffffffffffffffUL)
//size_t sceLibcHeapSize = 256 * 1024 * 1024;
size_t sceLibcHeapSize = SCE_LIBC_HEAP_SIZE_EXTENDED_ALLOC_NO_LIMIT;
unsigned int sceLibcHeapExtendedAlloc = 1;




typedef struct Ps4MemoryProtected
{
	void *writable;
	void *executable;
	size_t size;
}Ps4MemoryProtected;
int ps4MemoryProtectedCreate(Ps4MemoryProtected **memory, size_t size)
{
	int executableHandle, writableHandle;
	Ps4MemoryProtected *m;
	long pageSize = 0x4000;//sysconf(_SC_PAGESIZE);

	if (memory == NULL)
		return PS4_ERROR_ARGUMENT_PRIMARY_MISSING;

	if (size == 0)
		return PS4_ERROR_ARGUMENT_SIZE_NULL;

	m = (Ps4MemoryProtected *)malloc(sizeof(Ps4MemoryProtected));
	if (m == NULL)
		return PS4_ERROR_OUT_OF_MEMORY;

	m->size = (size / pageSize + 1) * pageSize; // align to pageSize


	m->executable = mmap(NULL, m->size, 7, 0x1000, -1, 0);
	if (m->executable == MAP_FAILED)
		goto e1;
	m->writable = m->executable;
	if (m->writable == MAP_FAILED)
		goto e1;
	*memory = m;
	return PS4_OK;

e1:
	free(m);

	return PS4_ERROR_OUT_OF_MEMORY; // make error codes proper errnos ... everywhere ... meh
}

int ps4MemoryProtectedDestroy(Ps4MemoryProtected *memory)
{
	int r = 0;
	if (memory == NULL)
		return -1;
	r |= munmap(memory->writable, memory->size);
	r |= munmap(memory->executable, memory->size);
	free(memory);
	return r;
}

int ps4MemoryProtectedGetWritableAddress(Ps4MemoryProtected *memory, void **address)
{
	if (memory == NULL)
		return PS4_ERROR_ARGUMENT_PRIMARY_MISSING;
	if (address == NULL)
		return PS4_ERROR_ARGUMENT_OUT_MISSING;
	*address = memory->writable;
	return PS4_OK;
}

int ps4MemoryProtectedGetExecutableAddress(Ps4MemoryProtected *memory, void **address)
{
	if (memory == NULL)
		return PS4_ERROR_ARGUMENT_PRIMARY_MISSING;
	if (address == NULL)
		return PS4_ERROR_ARGUMENT_OUT_MISSING;
	*address = memory->executable;
	return PS4_OK;
}

int ps4MemoryProtectedGetSize(Ps4MemoryProtected *memory, size_t *size)
{
	if (memory == NULL)
		return PS4_ERROR_ARGUMENT_PRIMARY_MISSING;
	if (size == NULL)
		return PS4_ERROR_ARGUMENT_OUT_MISSING;
	*size = memory->size;
	return PS4_OK;
}

void orbisMemorySet(void *p, unsigned char value, int size)
{

	unsigned char *buf = (unsigned char *)p;
	//for(i=0;i<size;i++)
	//{
	//	buf[i]=value;
	//}
	debugNetPrintf(3, "[ELFLOADER] orbisMemorySet before memset\n");
	memset(buf, value, size);
	debugNetPrintf(3, "[ELFLOADER] orbisMemorySet after memset\n");


}
void orbisMemoryCopy(void *to, void *from, size_t size)
{


	debugNetPrintf(DEBUG, "[ELFLOADER] orbisMemoryCopy before memcpy\n");

	memcpy(to, from, size);
	debugNetPrintf(DEBUG, "[ELFLOADER] orbisMemoryCopy after memcpy\n");

}

/* Defines */

#define elfRelocationSymbol __ELFN(R_SYM)
#define elfRelocationType __ELFN(R_TYPE)
#define elfRelocationInfo __ELFN(R_INFO)

#define elfSymbolBind __ELFN(ST_BIND)
#define elfSymbolType __ELFN(ST_TYPE)
#define elfSymbolInfo __ELFN(ST_INFO)

#define elfIsElf(e) IS_ELF(*elfHeader(e)) // FIXME: Null deref

#define elfClass(e) (e == NULL ? 0 : e->data[4])
#define elfEncoding(e) (e == NULL ? 0 : e->data[5])
#define elfVersion(e) (e == NULL ? 0 : e->data[6])
#define elfABI(e) (e == NULL ? 0 : e->data[7])

/* Constants */

enum { ELF_MAXIMAL_STRING_LENGTH = 4096 };

/* Type */

typedef struct Elf // FIXME: We could cache a lot of offsets here to inc. performance
{
	uint8_t *data;
	size_t size; // FIXME: Do more checks on size
}
Elf;

size_t elfGetSize(Elf *elf)
{
	return elf->size;
}

uint8_t *elfGetData(Elf *elf)
{
	return elf->data;
}

/* --- elf header --- */

ElfHeader *elfHeader(Elf *elf)
{
	if (!elf)
		return NULL;
	return (ElfHeader *)elf->data;
}

uint64_t elfEntry(Elf *elf)
{
	if (!elf)
		return 0;
	ElfHeader *h = elfHeader(elf);
	if (!h)
		return 0;
	return h->e_entry;
}

uint64_t elfLargestAlignment(Elf *elf) //ignore ...
{
	uint16_t index = 0;
	uint64_t alignment = 0;

	while (1)
	{
		ElfSegment *h = elfSegment(elf, &index, ELF_SEGMENT_ATTRIBUTE_TYPE, PT_LOAD);
		if (!h)
			break;

		// FIXME: Tired of bogus 2MB alignment -> ignore
		if (alignment < h->p_align && h->p_align < 0x200000)
			alignment = h->p_align;
		++index;
	}
	return alignment;
}

size_t elfMemorySize(Elf *elf)
{
	ElfSection *sections;
	ElfSegment *segments;

	uint16_t size;
	uint16_t length;
	uint16_t index;

	size_t memorySize = 0;

	if (!elf)
		return 0;

	segments = elfSegments(elf, &size, &length);
	if (segments)
	{
		for (index = 0; index < length; ++index)
		{
			ElfSegment *s = (ElfSegment *)((uint8_t *)segments + index * size);
			if (memorySize < s->p_paddr + s->p_memsz)
				memorySize = s->p_paddr + s->p_memsz;
		}
	}
	else
	{
		length = 0;
		sections = elfSections(elf, &size, &length);
		if (!sections)
			return 0;
		for (index = 0; index < length; ++index)
		{
			ElfSection *s = (ElfSection *)((uint8_t *)sections + index * size);
			if (memorySize < s->sh_addr + s->sh_size)
				memorySize = s->sh_addr + s->sh_size;
		}
	}

	return memorySize;
}

/* --- elf section header --- */

char *elfSectionStrings(Elf *elf, uint64_t *size)
{
	ElfHeader *h;
	uint16_t i;
	ElfSection *s;
	h = elfHeader(elf);
	i = h->e_shstrndx;
	s = elfSection(elf, &i, ELF_SECTION_ATTRIBUTE_NONE, 0);
	if (size)
		*size = s->sh_size;
	return (char *)elf->data + s->sh_offset;
}

uint64_t elfSectionAttribute(ElfSection *elfSection, ElfSectionAttribute attribute)
{
	switch (attribute)
	{
	case ELF_SECTION_ATTRIBUTE_NAME:
		return elfSection->sh_name;
	case ELF_SECTION_ATTRIBUTE_TYPE:
		return elfSection->sh_type;
	case ELF_SECTION_ATTRIBUTE_FLAGS:
		return elfSection->sh_flags;
	case ELF_SECTION_ATTRIBUTE_ADDRESS:
		return elfSection->sh_addr;
	case ELF_SECTION_ATTRIBUTE_OFFSET:
		return elfSection->sh_offset;
	case ELF_SECTION_ATTRIBUTE_SIZE:
		return elfSection->sh_size;
	case ELF_SECTION_ATTRIBUTE_LINK:
		return elfSection->sh_link;
	case ELF_SECTION_ATTRIBUTE_INFO:
		return elfSection->sh_info;
	case ELF_SECTION_ATTRIBUTE_MEMORY_ALIGNMENT:
		return elfSection->sh_addralign;
	case ELF_SECTION_ATTRIBUTE_ENTRY_SIZE:
		return elfSection->sh_entsize;
	default:
		break;
	}
	return 0;
}

ElfSection *elfSections(Elf *elf, uint16_t *size, uint16_t *length)
{
	ElfHeader *h;

	if (!elf)
		return NULL;

	h = elfHeader(elf);

	if (h->e_shoff == 0)
		return NULL;

	if (size != NULL)
		*size = h->e_shentsize;
	if (length != NULL)
		*length = h->e_shnum;

	return (ElfSection *)(elf->data + h->e_shoff);
}

ElfSection *elfSection(Elf *elf, uint16_t *index, ElfSectionAttribute attribute, uint64_t value)
{
	uint16_t size;
	uint16_t length;
	ElfSection *h, *t;
	uint16_t i = 0;

	if (!index)
		index = &i;

	h = elfSections(elf, &size, &length);

	if (!h)
		return NULL;

	for (; *index < length; ++(*index))
	{
		t = (ElfSection *)((uint8_t *)h + *index * size);
		if (attribute == ELF_SECTION_ATTRIBUTE_NONE || elfSectionAttribute(t, attribute) == value)
			return t;
	}

	return NULL;
}

ElfSection *elfSectionByName(Elf *elf, char *name)
{
	uint64_t size;
	char *mem = elfSectionStrings(elf, &size);

	uint32_t offset = elfStringToOffset(mem, size, name);
	ElfSection *sh = elfSection(elf, NULL, ELF_SECTION_ATTRIBUTE_NAME, offset);

	return sh;
}

/* --- elf segment header --- */

uint64_t elfSegmentAttribute(ElfSegment *elfSegment, ElfSegmentAttribute attribute)
{
	switch (attribute)
	{
	case ELF_SEGMENT_ATTRIBUTE_TYPE:
		return elfSegment->p_type;
	case ELF_SEGMENT_ATTRIBUTE_FLAGS:
		return elfSegment->p_flags;
	case ELF_SEGMENT_ATTRIBUTE_OFFSET:
		return elfSegment->p_offset;
	case ELF_SEGMENT_ATTRIBUTE_VIRTUAL_ADDRESS:
		return elfSegment->p_vaddr;
	case ELF_SEGMENT_ATTRIBUTE_PHYSICAL_ADDRESS:
		return elfSegment->p_paddr;
	case ELF_SEGMENT_ATTRIBUTE_FILE_SIZE:
		return elfSegment->p_filesz;
	case ELF_SEGMENT_ATTRIBUTE_MEMORY_SIZE:
		return elfSegment->p_memsz;
	case ELF_SEGMENT_ATTRIBUTE_ALIGNMENT:
		return elfSegment->p_align;
	default:
		break;
	}
	return 0;
}

ElfSegment *elfSegments(Elf *elf, uint16_t *size, uint16_t *length)
{
	ElfHeader *h;

	if (!elf)
		return NULL;

	h = elfHeader(elf);

	if (h->e_phoff == 0)
		return NULL;

	if (size != NULL)
		*size = h->e_phentsize;
	if (length != NULL)
		*length = h->e_phnum;

	return (ElfSegment *)(elf->data + h->e_phoff);
}

ElfSegment *elfSegment(Elf *elf, uint16_t *index, ElfSegmentAttribute attribute, uint64_t value)
{
	uint16_t size;
	uint16_t length;
	ElfSegment *h, *t;
	uint16_t i = 0;

	if (!index)
		index = &i;

	h = elfSegments(elf, &size, &length);

	if (!h)
		return NULL;

	for (; *index < length; ++(*index))
	{
		t = (ElfSegment *)((uint8_t *)h + *index * size);
		if (attribute == ELF_SEGMENT_ATTRIBUTE_NONE || elfSegmentAttribute(t, attribute) == value)
			return t;
	}

	return NULL;
}

/* --- elf dynamic section --- */

uint64_t elfDynamicAttribute(ElfDynamic *elfDynamic, ElfDynamicAttribute attribute)
{
	switch (attribute)
	{
	case ELF_DYNAMIC_ATTRIBUTE_TAG:
		return elfDynamic->d_tag;
	case ELF_DYNAMIC_ATTRIBUTE_VALUE:
		return elfDynamic->d_un.d_val;
	case ELF_DYNAMIC_ATTRIBUTE_POINTER:
		return elfDynamic->d_un.d_ptr;
	default:
		break;
	}
	return 0;
}

uint16_t elfDynamicsLength(ElfDynamic *dyn)
{
	uint16_t i = 0;
	if (dyn != NULL)
		for (; dyn->d_tag != DT_NULL; ++dyn)
			++i;
	return i;
}

ElfDynamic *elfDynamics(Elf *elf, uint16_t *size, uint16_t *length)
{
	ElfSection *h;
	ElfSegment *h2;

	if (!elf)
		return NULL;

	if ((h = elfSection(elf, NULL, ELF_SECTION_ATTRIBUTE_TYPE, SHT_DYNAMIC)))
	{
		if (size != NULL)
			*size = h->sh_entsize;
		if (length != NULL)
			*length = h->sh_size / h->sh_entsize;

		return (ElfDynamic *)(elf->data + h->sh_offset);
	}
	else if ((h2 = elfSegment(elf, NULL, ELF_SEGMENT_ATTRIBUTE_TYPE, PT_DYNAMIC)))
	{
		if (size != NULL)
			*size = sizeof(ElfDynamic);
		if (length != NULL) //h2->p_filesz / sizeof(ElfDynamic);
			*length = elfDynamicsLength((ElfDynamic *)(elf->data + h2->p_offset));

		return (ElfDynamic *)(elf->data + h2->p_offset);
	}

	return NULL;
}

ElfDynamic *elfDynamic(Elf *elf, uint16_t *index, ElfDynamicAttribute attribute, uint64_t value)
{
	uint16_t size;
	uint16_t length;
	ElfDynamic *h, *t;
	uint16_t i = 0;

	if (!index)
		index = &i;

	h = elfDynamics(elf, &size, &length);

	if (!h)
		return NULL;

	for (; *index < length; ++(*index))
	{
		t = (ElfDynamic *)((uint8_t *)h + *index * size);
		if (attribute == ELF_DYNAMIC_ATTRIBUTE_NONE || elfDynamicAttribute(t, attribute) == value)
			return t;
	}

	return NULL;
}

ElfDynamic *elfLoadedDynamics(Elf *elf, uint16_t *size, uint16_t *length)
{
	//ElfSection *h;
	ElfSegment *h2;

	if (!elf)
		return NULL;

	if ((h2 = elfSegment(elf, NULL, ELF_SEGMENT_ATTRIBUTE_TYPE, PT_DYNAMIC)))
	{
		if (size != NULL)
			*size = sizeof(ElfDynamic);
		if (length != NULL)
			*length = elfDynamicsLength((ElfDynamic *)h2->p_vaddr);

		return (ElfDynamic *)h2->p_vaddr;
	}

	return NULL;
}

ElfDynamic *elfLoadedDynamic(Elf *elf, uint16_t *index, ElfDynamicAttribute attribute, uint64_t value)
{
	uint16_t size;
	uint16_t length;
	ElfDynamic *h, *t;
	uint16_t i = 0;

	if (!index)
		index = &i;

	h = elfLoadedDynamics(elf, &size, &length);

	if (!h)
		return NULL;

	for (; *index < length; ++(*index))
	{
		t = (ElfDynamic *)((uint8_t *)h + *index * size);
		if (attribute == ELF_DYNAMIC_ATTRIBUTE_NONE || elfDynamicAttribute(t, attribute) == value)
			return t;
	}

	return NULL;
}

/* --- elf string tables --- */

char *elfStringFromIndex(char *mem, uint64_t size, uint32_t index)
{
	uint64_t i, j = 0;

	if (!mem)
		return NULL;

	if (index == 0)
		return mem;

	for (i = 0; i < size - 1; ++i)
		if (mem[i] == '\0' && ++j == index)
			return mem + i + 1;

	return NULL;
}

char *elfStringFromOffset(char *mem, uint64_t size, uint32_t offset)
{
	if (!mem || offset >= size)
		return NULL;

	return mem + offset;
}

uint32_t elfStringToOffset(char *mem, uint64_t size, char *str)
{
	uint64_t i, j;

	if (!str)
		return 0;

	for (i = 0; i < size; ++i)
	{
		for (j = 0; j < ELF_MAXIMAL_STRING_LENGTH && mem[i + j] == str[j]; ++j)
			if (str[j] == '\0')
				return i;
	}

	return 0;
}

uint32_t elfStringToIndex(char *mem, uint64_t size, char *str)
{
	uint64_t index, i, j;

	if (!str)
		return 0;

	index = 0;
	for (i = 0; i < size; ++i)
	{
		for (j = 0; j < ELF_MAXIMAL_STRING_LENGTH && mem[i + j] == str[j]; ++j)
			if (str[j] == '\0')
				return index;

		if (mem[i] == '\0')
			index++;
	}

	return 0;
}

/* --- elf relocations --- */

uint64_t elfAddendRelocationAttribute(ElfAddendRelocation *elfAddendRelocation, ElfAddendRelocationAttribute attribute)
{
	switch (attribute)
	{
	case ELF_ADDEND_RELOCATION_ATTRIBUTE_INFO:
		return elfAddendRelocation->r_info;
	case ELF_ADDEND_RELOCATION_ATTRIBUTE_OFFSET:
		return elfAddendRelocation->r_offset;
	case ELF_ADDEND_RELOCATION_ATTRIBUTE_ADDEND:
		return elfAddendRelocation->r_addend;
	default:
		break;
	}
	return 0;
}

ElfAddendRelocation *elfAddendRelocations(Elf *elf, char *name, uint16_t *size, uint16_t *length)
{
	ElfSection *h;

	h = elfSectionByName(elf, name);

	if (!h || h->sh_type != SHT_RELA)
		return NULL;

	if (size != NULL)
		*size = h->sh_entsize;
	if (length != NULL)
		*length = h->sh_size / h->sh_entsize;

	return (ElfAddendRelocation *)(elf->data + h->sh_offset);
}

// FIXME this is not performant, better to pass in the base ElfAddendRelocation *, size and length
/*
ElfAddendRelocation *elfAddendRelocation(Elf *elf, char *name, uint16_t *index, ElfAddendRelocationAttribute attribute, uint64_t value)
{
uint16_t size;
uint16_t length;
ElfAddendRelocation *h, *t;
uint16_t i = 0;
if(!index)
index = &i;
h = elfAddendRelocations(elf, name, &size, &length);
if(!h)
return NULL;
for(; *index < length; ++(*index))
{
t = (ElfAddendRelocation *)((uint8_t *)h + *index * size);
if(attribute == ElfAddendRelocationAttributeNone || elfAddendRelocationAttribute(t, attribute) == value)
return t;
}
return NULL;
}
*/

/* --- elf symbols --- */

uint64_t elfSymbolAttribute(ElfSymbol *elfSymbol, ElfSymbolAttribute attribute)
{
	switch (attribute)
	{
	case ELF_SYMBOL_ATTRIBUTE_NAME:
		return elfSymbol->st_name;
	case ELF_SYMBOL_ATTRIBUTE_INFO:
		return elfSymbol->st_info;
	case ELF_SYMBOL_ATTRIBUTE_UNUSED:
		return elfSymbol->st_other;
	case ELF_SYMBOL_ATTRIBUTE_SECTION_INDEX:
		return elfSymbol->st_shndx;
	case ELF_SYMBOL_ATTRIBUTE_VALUE:
		return elfSymbol->st_value;
	case ELF_SYMBOL_ATTRIBUTE_SIZE:
		return elfSymbol->st_size;
	default:
		break;
	}
	return 0;
}

ElfSymbol *elfSymbols(Elf *elf, char *name, uint16_t *size, uint16_t *length)
{
	ElfSection *h;

	h = elfSectionByName(elf, name);

	if (!h || (h->sh_type != SHT_SYMTAB && h->sh_type != SHT_DYNSYM))
		return NULL;

	if (size != NULL)
		*size = h->sh_entsize;
	if (length != NULL)
		*length = h->sh_size / h->sh_entsize;

	return (ElfSymbol *)(elf->data + h->sh_offset);
}

/*
ElfSymbol *elfSymbol(Elf *elf, char *name, uint16_t *index, ElfSymbolAttribute attribute, uint64_t value)
{
uint16_t size;
uint16_t length;
ElfSymbol *h, *t;
uint16_t i = 0;
if(!index)
index = &i;
h = elfSymbols(elf, name, &size, &length);
if(!h)
return NULL;
for(; *index < length; ++(*index))
{
t = (ElfSymbol *)((uint8_t *)h + *index * size);
if(attribute == ElfSymbolAttributeNone || elfSymbolAttribute(t, attribute) == value)
return t;
}
return NULL;
}*/

/* actions */

Elf *elfCreate(void *data, size_t size)
{
	Elf *elf, t;

	if (data == NULL)
		return NULL;

	t.data = data;
	t.size = size;

	if (!elfIsElf(&t))
		return NULL;

	elf = malloc(sizeof(Elf));
	if (elf == NULL)
	{
		debugNetPrintf(DEBUG, "[ELFLOADER] elfCreate error malloc return null\n");
		return NULL;
	}
	elf->data = (uint8_t *)data;
	elf->size = size;

	return elf;
}

Elf *elfCreateLocal(void *elfl, void *data, size_t size)
{
	Elf *elf, t;

	if (elfl == NULL || data == NULL)
		return NULL;

	t.data = data;
	t.size = size;

	if (!elfIsElf(&t))
		return NULL;

	elf = (Elf *)elfl;
	elf->data = (uint8_t *)data;
	elf->size = size;

	return elf;
}

Elf *elfCreateLocalUnchecked(void *elfl, void *data, size_t size)
{
	Elf *elf;

	if (elfl == NULL || data == NULL)
		return NULL;

	elf = (Elf *)elfl;
	elf->data = (uint8_t *)data;
	elf->size = size;

	return elf;
}

void *elfDestroy(Elf *elf)
{
	void *data;

	if (elf == NULL)
		return NULL;

	if (elf->data != NULL)
	{
		//debugNetPrintf(3,"data %x\n",elf->data);

		//data = elf->data;
		munmap(elf->data, elf->size);
		//free(elf->data);
	}

	return elf;
}

void elfDestroyAndFree(Elf *elf)
{
	void *d;

	if (elf == NULL)
		return;
	//debugNetPrintf(3,"elf %x\n",elf);
	d = elfDestroy(elf);
	//debugNetPrintf(3,"d %x\n",d);

	if (d)
		free(d);
}

/* ---  --- */

int elfLoaderIsLoadable(Elf *elf)
{
	ElfHeader *h;

	if (!elfIsElf(elf))
		return 0;

	h = elfHeader(elf);

	return elfClass(elf) == ELFCLASS64 &&
		elfEncoding(elf) == ELFDATA2LSB &&
		elfVersion(elf) == EV_CURRENT &&
		(elfABI(elf) == ELFOSABI_SYSV || elfABI(elf) == ELFOSABI_FREEBSD) &&
		h->e_type == ET_DYN &&
		h->e_phoff != 0 &&
		h->e_shoff != 0 &&
		h->e_machine == EM_X86_64 &&
		h->e_version == EV_CURRENT;
}

int elfLoaderInstantiate(Elf *elf, void *memory)
{
	ElfSection *sections;
	ElfSegment *segments;

	uint16_t size;
	uint16_t length;
	uint16_t index;

	if (elf == NULL)
		return ELF_LOADER_RETURN_ELF_NULL;
	if (memory == NULL)
		return ELF_LOADER_RETURN_NO_WRITABLE_MEMORY;

	segments = elfSegments(elf, &size, &length);
	if (segments)
	{
		debugNetPrintf(DEBUG, "[ELFLOADER] elfLoaderInstantiate in segments length=%d\n", length);

		for (index = 0; index < length; ++index)
		{
			ElfSegment *s = (ElfSegment *)((uint8_t *)segments + index * size);
			if (s->p_filesz)
			{
				debugNetPrintf(DEBUG, "[ELFLOADER] elfLoaderInstantiate before elfLoaderInstantiate memcpy %p %p %d\n", (char *)memory + s->p_paddr, elf->data + s->p_offset, s->p_filesz);

				orbisMemoryCopy((char *)memory + s->p_paddr, elf->data + s->p_offset, s->p_filesz);
				debugNetPrintf(DEBUG, "[ELFLOADER] elfLoaderInstantiate after elfLoaderInstantiate memcpy\n");

			}
			if (s->p_memsz - s->p_filesz)
			{	//memset((char *)memory + s->p_paddr + s->p_filesz, 0, s->p_memsz - s->p_filesz);
				debugNetPrintf(DEBUG, "[ELFLOADER] elfLoaderInstantiate before elfLoaderInstantiate orbisMemorySet\n");

				orbisMemorySet((char *)memory + s->p_paddr + s->p_filesz, 0, s->p_memsz - s->p_filesz);
				debugNetPrintf(DEBUG, "[ELFLOADER] elfLoaderInstantiate after elfLoaderInstantiate orbisMemorySet\n");

			}
		}
	}
	else
	{
		length = 0;
		sections = elfSections(elf, &size, &length);
		if (!sections)
			return 0;
		for (index = 0; index < length; ++index)
		{
			ElfSection *s = (ElfSection *)((uint8_t *)sections + index * size);
			if (!(s->sh_flags & SHF_ALLOC))
				continue;
			if (s->sh_size)
			{
				orbisMemoryCopy((char *)memory + s->sh_addr, elf->data + s->sh_offset, s->sh_size);
				debugNetPrintf(DEBUG, "[ELFLOADER] elfLoaderInstantiate  after elfLoaderInstantiate second memcpy\n");

			}
		}
	}

	return ELF_LOADER_RETURN_OK;
}

int elfLoaderRelativeAddressIsExecutable(Elf *elf, int64_t address)
{
	ElfSection *sections;
	ElfSegment *segments;

	uint16_t size;
	uint16_t length;
	uint16_t index;

	if (elf == NULL)
		return 0;

	segments = elfSegments(elf, &size, &length);
	if (segments)
	{
		for (index = 0; index < length; ++index)
		{
			ElfSegment *s = (ElfSegment *)((uint8_t *)segments + index * size);
			if (address >= s->p_paddr && address <= s->p_paddr + s->p_memsz)
				return s->p_flags & PF_X;
		}
	}
	else
	{
		length = 0;
		sections = elfSections(elf, &size, &length);
		if (!sections)
			return ELF_LOADER_RETURN_NO_SECTIONS_OR_SEGMENTS;
		for (index = 0; index < length; ++index)
		{
			ElfSection *s = (ElfSection *)((uint8_t *)sections + index * size);
			if (address >= s->sh_addr && address <= s->sh_addr + s->sh_size)
				return s->sh_flags & SHF_EXECINSTR;
		}
	}

	return 1; // FIXME: Recheck
}

// FIXME: Implement ps4 aware relocation for functions using dlsym
int elfLoaderRelocate(Elf *elf, void *writable, void *executable)
{
	int i, j;

	uint16_t relocationSize = 0;
	uint16_t relocationsLength = 0;
	ElfAddendRelocation *relocations;

	uint16_t dynamicSymbolSize = 0;
	uint16_t dynamicSymbolsLength = 0;
	ElfSymbol *dynamicSymbols;

	char *r1 = ".rela.dyn";
	char *r2 = ".rela.plt";
	char *rel[2] = { r1, r2 };

	if (elf == NULL)
		return ELF_LOADER_RETURN_ELF_NULL;
	if (writable == NULL)
		return ELF_LOADER_RETURN_NO_WRITABLE_MEMORY;
	if (executable == NULL)
		return ELF_LOADER_RETURN_NO_EXECUTABLE_MEMORY;

	dynamicSymbols = elfSymbols(elf, ".dynsym", &dynamicSymbolSize, &dynamicSymbolsLength);
	//symbols = elfSymbols(elf, ".symtab", &symbolSize, &symbolsLength);

	for (j = 0; j < sizeof(rel) / sizeof(rel[0]); ++j)
	{
		relocationsLength = 0;
		relocations = elfAddendRelocations(elf, rel[j], &relocationSize, &relocationsLength);

		for (i = 0; i < relocationsLength; ++i)
		{
			ElfSymbol *symbol;
			ElfAddendRelocation *relocation = (ElfAddendRelocation *)(((uint8_t *)relocations) + relocationSize * i);
			uint16_t relocationType = (uint16_t)elfRelocationType(relocation->r_info);
			uint16_t relocationSymbol = (uint16_t)elfRelocationSymbol(relocation->r_info);
			uint8_t **offset = (uint8_t **)((uint8_t *)writable + relocation->r_offset);
			int64_t value = 0;

			switch (relocationType)
			{
			case R_X86_64_RELATIVE:
				value = relocation->r_addend;
				break;
			case R_X86_64_64:
				symbol = (ElfSymbol *)(((uint8_t *)dynamicSymbols) + dynamicSymbolSize * relocationSymbol);
				value = symbol->st_value + relocation->r_addend;
				break;
			case R_X86_64_JMP_SLOT:
			case R_X86_64_GLOB_DAT:
				symbol = (ElfSymbol *)(((uint8_t *)dynamicSymbols) + dynamicSymbolSize * relocationSymbol);
				value = symbol->st_value;
				break;
			default:
				return ELF_LOADER_RETURN_UNKNOWN_RELOCATION;
			}

			if (elfLoaderRelativeAddressIsExecutable(elf, value))
				*offset = (uint8_t *)executable + value;
			else
				*offset = (uint8_t *)writable + value;
		}
	}

	return ELF_LOADER_RETURN_OK;
}

int elfLoaderLoad(Elf *elf, void *writable, void *executable)
{
	int r = ELF_LOADER_RETURN_OK;

	if (elf == NULL)
		return ELF_LOADER_RETURN_ELF_NULL;
	if (writable == NULL)
		return ELF_LOADER_RETURN_NO_WRITABLE_MEMORY;
	if (executable == NULL)
		return ELF_LOADER_RETURN_NO_EXECUTABLE_MEMORY;

	if (!elfLoaderIsLoadable(elf))
		return ELF_LOADER_RETURN_IS_NOT_LOADABLE;

	if ((r = elfLoaderInstantiate(elf, writable)) != ELF_LOADER_RETURN_OK)
	{
		debugNetPrintf(DEBUG, "[ELFLOADER] elfLoaderLoad  after elfLoaderInstantiate error return=%d\n", r);

		return r;
	}
	debugNetPrintf(DEBUG, "[ELFLOADER] elfLoaderLoad  after elfLoaderInstantiate return=%d\n", r);
	r = elfLoaderRelocate(elf, writable, executable);
	debugNetPrintf(DEBUG, "[ELFLOADER] elfLoaderLoad after elfLoaderRelocate return=%d\n", r);


	return r;
}

extern ps4LinkConfiguration *configuration;
typedef int(*ElfMain)(int argc, char **argv);
typedef void(*ElfProcessMain)(void *arg);

typedef void(*ElfProcessExit)(int ret);
typedef void(*ElfProcessFree)(void *m, void *t);


typedef struct ElfRunUserArgument
{
	ElfMain main;
	Ps4MemoryProtected *memory;
}
ElfRunUserArgument;

void *orbisUserMain(void *arg)
{
	ElfRunUserArgument *argument = (ElfRunUserArgument *)arg;
	globalConf.confLink = configuration;
	//ps4LinkConfiguration *shared_conf=configuration;
	char pointer_conf[256];
	sprintf(pointer_conf, "%p", &globalConf);
	debugNetPrintf(DEBUG, "[ELFLOADER] orbisUserMain Configuration pointer %p, pointer_conf string %s\n", &globalConf, pointer_conf);
	char *elfName = "elf";
	char *elfArgv[3] = { elfName, pointer_conf, NULL };
	int elfArgc = 2;

	int r;

	if (argument == NULL)
		return NULL;

	r = argument->main(elfArgc, elfArgv);
	ps4MemoryProtectedDestroy(argument->memory);
	//ps4MemoryDestroy(argument->memory);
	free(argument);
	debugNetPrintf(DEBUG, "[ELFLOADER] orbisUserMain return (user): %i\n", r);

	return NULL;
}

int orbisUserRun(Elf *elf)
{
	//pthread_t thread;
	ScePthread thread;
	int ret;
	ElfRunUserArgument *argument;
	void *writable, *executable;
	int r;

	if (elf == NULL)
		return -1;
	debugNetPrintf(DEBUG, "[ELFLOADER] orbisUserRun malloc for argument\n");

	argument = (ElfRunUserArgument *)malloc(sizeof(ElfRunUserArgument));
	if (argument == NULL)
	{
		elfDestroyAndFree(elf);
		debugNetPrintf(DEBUG, "[ELFLOADER] orbisUserRun argument is NULL\n");
		return -1;
	}
	debugNetPrintf(DEBUG, "[ELFLOADER] orbisUserRun after malloc for argument\n");

	if (ps4MemoryProtectedCreate(&argument->memory, elfMemorySize(elf)) != 0)
		//if(ps4MemoryCreate(&argument->memory, elfMemorySize(elf)) != PS4_OK)
	{
		free(argument);
		elfDestroyAndFree(elf);
		debugNetPrintf(DEBUG, "[ELFLOADER] orbisUserRun after elfDestroyAndFree\n");

		return -1;
	}
	debugNetPrintf(DEBUG, "[ELFLOADER] orbisUserRun after ps4MemoryProtectedCreate\n");

	argument->main = NULL;
	ps4MemoryProtectedGetWritableAddress(argument->memory, &writable);
	debugNetPrintf(DEBUG, "[ELFLOADER] orbisUserRun after ps4MemoryProtectedGetWritableAddress writable=%p\n", writable);

	ps4MemoryProtectedGetExecutableAddress(argument->memory, &executable);
	debugNetPrintf(DEBUG, "[ELFLOADER] orbisUserRun after ps4MemoryProtectedGetExecutableAddress executable=%p\n", executable);

	r = elfLoaderLoad(elf, writable, executable);
	//r = elfLoaderLoad(elf, ps4MemoryGetAddress(argument->memory), ps4MemoryGetAddress(argument->memory));
	debugNetPrintf(DEBUG, "[ELFLOADER] orbisUserRun after elfLoaderLoad return r=%d readable=%p executable=%p\n", r, writable, executable);

	if (r == ELF_LOADER_RETURN_OK)
	{
		argument->main = (ElfMain)((uint8_t *)executable + elfEntry(elf));
		debugNetPrintf(DEBUG, "[ELFLOADER] orbisUserRun after set argument->main %p \n", argument->main);

	}
	//elfDestroyAndFree(elf); // we don't need the "file" anymore but if i leave this line i got a memory crash 
	debugNetPrintf(DEBUG, "[ELFLOADER] orbisUserRun after elfDestroyAndFree \n");

	if (argument->main != NULL)
	{	//pthread_create(&thread, NULL, elfLoaderUserMain, argument);
		ret = scePthreadCreate(&thread, NULL, orbisUserMain, argument, "elf_user_thid");
		if (ret == 0)
		{
			debugNetPrintf(DEBUG, "[ELFLOADER] New user elf thread UID: 0x%08X\n", thread);
		}
		else
		{
			debugNetPrintf(DEBUG, "[ELFLOADER] New user elf thread could not create error: 0x%08X\n", ret);
			scePthreadCancel(thread);
			//ps4LinkFinish();
			return PS4_NOT_OK;
		}
	}
	else
	{
		ps4MemoryProtectedDestroy(argument->memory);
		free(argument);
		debugNetPrintf(DEBUG, "[ELFLOADER]orbisUserRun argument->main is released\n");
		return -1;
	}
	return PS4_OK;
}

Elf * orbisReadElfFromHost(char *path)
{
	int fd; //descriptor to manage file from host0
	int filesize;//variable to control file size 
	uint8_t *buf = NULL;//buffer for read from host0 file
	Elf *elf;//elf to create from buf 

			 //we sceKernelOpen file in read only from host0 ps4sh include the full path with host0:/.......
	fd = sceKernelOpen(path, O_RDONLY, 0);

	//If we can't sceKernelOpen file from host0 print  the error and return
	if (fd<0)
	{
		debugNetPrintf(DEBUG, "[ELFLOADER] sceKernelOpen returned error sceKernelOpening file %d\n", fd);
		return NULL;
	}
	//Seek to final to get file size
	filesize = sceKernelLseek(fd, 0, SEEK_END);
	//If we get an error print it and return
	if (filesize<0)
	{
		debugNetPrintf(DEBUG, "[ELFLOADER] sceKernelLseek returned error %d\n", fd);
		sceKernelClose(fd);
		return NULL;
	}
	//Seek back to start
	sceKernelLseek(fd, 0, SEEK_SET);
	//Reserve  memory for read buffer
	//buf=malloc(filesize);
	//char buf[filesize];
	debugNetPrintf(DEBUG, "[ELFLOADER] before orbisSysMmap\n");
	//buzzer1beep();
	//loadnote();

	buf = mmap(NULL, filesize, 0x01 | 0x02, 0x1000 | 0x0002, -1, 0);

	if (buf == MAP_FAILED)
	{
		debugNetPrintf(DEBUG, "[ELFLOADER] mmap returned error tryng one more time\n");

		buf = mmap(NULL, filesize, 0x01 | 0x02, 0x1000 | 0x0002, -1, 0);
		if (buf == MAP_FAILED)
		{
			debugNetPrintf(DEBUG, "[ELFLOADER] mmap returned error again\n");
			sceKernelClose(fd);
			return NULL;
		}
	}
	//Read filsesize bytes to buf
	int numread = sceKernelRead(fd, buf, filesize);
	//if we don't get filesize bytes we are in trouble
	if (numread != filesize)
	{
		sleep(1);
		debugNetPrintf(DEBUG, "[ELFLOADER] sceKernelRead returned error %d\n", numread);
		sleep(1);
		sceKernelClose(fd);
		return NULL;
	}
	//Close file
	sceKernelClose(fd);
	//create elf from elfloader code from hitodama :P
	elf = elfCreate((void*)buf, filesize);
	//check is it is loadable
	if (!elfLoaderIsLoadable(elf))
	{
		debugNetPrintf(DEBUG, "[ELFLOADER] elf %s is not loadable\n", path);
		//free(buf);
		elfDestroy(elf);
		elf = NULL;
	}
	return elf;
}

int access(const char *path, int mode)
{
	return syscall(33, path, mode);
}

void orbisExecUserElf()
{


	Elf *elf = NULL;
	debugNetPrintf(DEBUG, "[ELFLOADER] orbisExecUserElf called\n");

	FILE *fp;


	int fdz = sceKernelOpen("/mnt/usb0/homebrew.elf", 0x0000, 0);
	if (fdz<0)
	{
		elf = orbisReadElfFromHost("/data/orbislink/homebrew.elf");

	}
	else
	{	
		elf = orbisReadElfFromHost("/mnt/usb0/homebrew.elf");

		debugNetPrintf(DEBUG, "[ELFLOADER] Loading from USB Instead\n");

	}


	
	 ///mnt/sandbox/pfsmnt/NPXX33392-app0/Media/Elf/homebrew.elf
	if (elf == NULL)
	{
		debugNetPrintf(DEBUG, "[ELFLOADER] orbisExecUserElf we can't create elf\n");
		//failednote();
		return;
	}
	debugNetPrintf(DEBUG, "[ELFLOADER] orbisExecUserElf ready to run elf\n");
	orbisUserRun(elf);
	return;
}


void finishOrbisLinkApp()
{
	orbisAudioFinish();
	orbisKeyboardFinish();
	orbisPadFinish();
	orbis2dFinish();
	ps4LinkFinish();
}
int initOrbisLinkApp()
{
	int ret;
	int jailbreak_out = 1;
	jailbreak_out=orbisSysJailBreak();

	pl_ini_file init;


	pl_ini_load(&init, "/app0/Media/config.ini");


	char serverIp[16];
	char title_id[36];

	pl_ini_get_string(&init, "ps4link", "serverIp", "192.168.1.3", serverIp, 16);
	//pl_ini_get_string(&init, "ELFLoader", "title_id", "NPSXXXXX", title_id, 36);


	int requestPort = pl_ini_get_int(&init, "ps4link", "requestPort", 18193);
	//int tid = pl_ini_get_int(&init, "ELFLoader", "title_id", 18193);
	int debugPort = pl_ini_get_int(&init, "ps4link", "debugPort", 18194);
	int commandPort = pl_ini_get_int(&init, "ps4link", "commandPort", 18194);
	int level = pl_ini_get_int(&init, "ps4link", "level", 3);



	globalConf.orbisLinkFlag = 0;
	ret = ps4LinkInit(serverIp, requestPort, debugPort, commandPort, level);
	if (!ret)
	{
		ps4LinkFinish();
		return ret;
	}
	while (!ps4LinkRequestsIsConnected())
	{
		debugNetPrintf(DEBUG, "[Welcome to ELF Loader V1]\n");


		debugNetPrintf(DEBUG, "[ELFLOADER] Initialized and connected from pc/mac ready to receive commands\n");
		int padEnabled = pl_ini_get_int(&init, "orbisPad", "enabled", 1);
		int o2dEnabled = pl_ini_get_int(&init, "orbis2d", "enabled", 1);
		int audioEnabled = pl_ini_get_int(&init, "orbisAudio", "enabled", 1);
		int fmsxEnabled = pl_ini_get_int(&init, "fmsx", "enabled", 0);
		int audioSamples = pl_ini_get_int(&init, "orbisAudio", "samples", 1024);
		int audioFrequency = pl_ini_get_int(&init, "orbisAudio", "frequency", 48000);
		int audioFormat = pl_ini_get_int(&init, "orbisAudio", "format", ORBISAUDIO_FORMAT_S16_STEREO);

		if (fmsxEnabled == 1)
		{
			audioEnabled = 1;
			audioSamples = 500;
			audioFrequency = 48000;
			audioFormat = ORBISAUDIO_FORMAT_S16_MONO;
		}
		int keyboardEnabled = pl_ini_get_int(&init, "orbisKeyboard", "enabled", 1);


		if (padEnabled == 1)
		{
			ret = orbisPadInit();
		}
		else
		{
			ret = -1;
		}
		if (ret == 1)
		{

			globalConf.confPad = orbisPadGetConf();
			if (o2dEnabled == 1)
			{
				ret = orbis2dInit();
				debugNetPrintf(DEBUG, "[ELFLOADER] orbis2dInit return %x \n", ret);
			}
			else
			{
				ret = -2;
			}
			if (ret == 1)
			{
				globalConf.conf = orbis2dGetConf();
				if (audioEnabled == 1)
				{
					ret = orbisAudioInit();
				}
				else
				{
					ret = -3;
				}
				if (ret == 1)
				{
					//ret=orbisAudioInitChannel(ORBISAUDIO_CHANNEL_MAIN,1024,48000,ORBISAUDIO_FORMAT_S16_STEREO);
					ret = orbisAudioInitChannel(ORBISAUDIO_CHANNEL_MAIN, audioSamples, audioFrequency, audioFormat);

					sleep(1);
					debugNetPrintf(DEBUG, "[ELFLOADER] orbisAudioInitChannel return %x \n", ret);
					//debugNetPrintf(DEBUG, "[ELFLOADER] config IP %x\n", serverIp);
					sleep(1);
					globalConf.confAudio = orbisAudioGetConf();

					if (keyboardEnabled == 1)
					{
						//ret=orbisKeyboardInit();
						//debugNetPrintf(DEBUG,"orbisKeyboardInit %d\n",ret);
						//if(ret==1)
						//{
						//	globalConf.confKeyboard=OrbisKeyboardGetConf();
						//sleep(1);
						//	ret=orbisKeyboardOpen();
						//	debugNetPrintf(DEBUG,"orbisKeyboardOpen %d\n",ret);
						ret = 0;
						//}
					}

				}
			}
		}
		return ret;


	}
	debugNetPrintf(DEBUG,"[ELFLOADER] orbisSysJailBreak returned %d\n",jailbreak_out);

	//hide orbislink splash
	//sceSystemServiceHideSplashScreen();





}





void copyFile(char *sourcefile, char* destfile)
{
	int src = sceKernelOpen(sourcefile, O_RDONLY, 0);
	if (src != -1)
	{
		int out = sceKernelOpen(destfile, O_WRONLY | O_CREAT | O_TRUNC, 0777);
		if (out != -1)
		{
			size_t bytes;
			char *buffer = malloc(65536);
			if (buffer != NULL)
			{
				while (0 < (bytes = sceKernelRead(src, buffer, 65536)))
					sceKernelWrite(out, buffer, bytes);
				free(buffer);
			}
			sceKernelClose(out);
		}
		else {
		}
		sceKernelClose(src);
	}
	else {
		debugNetPrintf(DEBUG, "[ELFLOADER] fuxking error\n");
	}
}


typedef struct DIR DIR;
struct dirent *(*readdir)(DIR *dirp);
int(*closedir)(DIR *dirp);
DIR *(*opendir)(const char *filename);
char(*getwd)(char*buf);
char (*getcwd)(char *buf, size_t size);


void *unjail(struct thread *td) {

	struct ucred* cred;
	struct filedesc* fd;

	void* kbase = 0;
	uint8_t* kernel_ptr;
	void** got_prison0;
	void** got_rootvnode;


	fd = td->td_proc->p_fd;
	cred = td->td_proc->p_ucred;

	uint64_t fw_version = 0x999;

	if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL];


		fw_version = 0x505;

	}

	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL];

		fw_version = 0x455;
	}

	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_474_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {

		kbase = &((uint8_t*)__readmsr(0xC0000082))[-KERN_474_XFAST_SYSCALL];

		fw_version = 0x474;

	}
	else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_405_XFAST_SYSCALL]), (char[4]) { 0x7F, 0x45, 0x4C, 0x46 }, 4)) {
		fw_version = 0x405;

	}
	else return -1;

	if (fw_version == 0x505) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + 0x436040);
		printfkernel("FW Version 5.05 Detected\n");
	}

	else if (fw_version == 0x405) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_405_PRINTF);
		printfkernel("FW Version 4.05 Detected\n");

	}
	else if (fw_version == 0x455) {

		int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_455_PRINTF);
		printfkernel("FW Version 4.55 Detected\n");

	}
	else if (fw_version == 0x474) {

		//int(*printfkernel)(const char *fmt, ...) = (void *)(kbase + KERN_501_PRINTF);
		//printfkernel("FW Version 5.05 Detected\n");
	}
	else return -1;


	if (fw_version == 0x405) {


		// Kernel pointers resolving

		kernel_ptr = (uint8_t*)kbase;
		got_prison0 = (void**)&kernel_ptr[KERN_405_PRISON_0];
		got_rootvnode = (void**)&kernel_ptr[KERN_405_ROOTVNODE];

	}
	else if (fw_version == 0x455) {

		// Kernel pointers resolving

		kernel_ptr = (uint8_t*)kbase;
		got_prison0 = (void**)&kernel_ptr[KERN_455_PRISON_0];
		got_rootvnode = (void**)&kernel_ptr[KERN_455_ROOTVNODE];

	}

	else if (fw_version == 0x474) {

		// Kernel pointers resolving

		kernel_ptr = (uint8_t*)kbase;
		got_prison0 = (void**)&kernel_ptr[KERN_474_PRISON_0];
		got_rootvnode = (void**)&kernel_ptr[KERN_474_ROOTVNODE];

	}

	else if (fw_version == 0x501) {

		// Kernel pointers resolving

		kernel_ptr = (uint8_t*)kbase;
		got_prison0 = (void**)&kernel_ptr[KERN_501_PRISON_0];
		got_rootvnode = (void**)&kernel_ptr[KERN_501_ROOTVNODE];

	}
	else if (fw_version == 0x505) {

		// Kernel pointers resolving

		kernel_ptr = (uint8_t*)kbase;
		got_prison0 = (void**)&kernel_ptr[KERN_505_PRISON_0];
		got_rootvnode = (void**)&kernel_ptr[KERN_505_ROOTVNODE];

	}
	else return -1;

	cred->cr_uid = 0;
	cred->cr_ruid = 0;
	cred->cr_rgid = 0;
	cred->cr_groups[0] = 0;
	cred->cr_prison = *got_prison0;
	fd->fd_rdir = fd->fd_jdir = *got_rootvnode;

	// Escalate ucred privs, needed for userland access to the filesystem e.g mounting & decrypting files

	void *td_ucred = *(void **)(((char *)td) + 304); // p_ucred == td_ucred

	uint64_t *sonyCred = (uint64_t *)(((char *)td_ucred) + 96);
	*sonyCred = 0xffffffffffffffff;

	// sceSblACMgrGetDeviceAccessType

	uint64_t *sceProcessAuthorityId = (uint64_t *)(((char *)td_ucred) + 88);
	*sceProcessAuthorityId = 0x3800000000000010; // SceShellcore paid
												 // sceSblACMgrHasSceProcessCapability

	uint64_t *sceProcCap = (uint64_t *)(((char *)td_ucred) + 104);
	*sceProcCap = 0xffffffffffffffff; // Max capability

	if (fw_version == 0x505) {

		// Kernel pointers resolving

		kernel_ptr = (uint8_t*)kbase;
		got_prison0 = (void**)&kernel_ptr[KERN_505_PRISON_0];
		got_rootvnode = (void**)&kernel_ptr[KERN_505_ROOTVNODE];

		cpu_disable_wp();

		// Disable ptrace check

		kernel_ptr[0x30D9AA] = 0xEB;

		// Disable process aslr
		*(uint16_t*)&kernel_ptr[0x194875] = 0x9090;

		// Allow sys_dynlib_dlsym in all processes.
		*(uint16_t *)(kbase + 0x237F3B) = 0x01C1;
		//*(uint16_t *)(kbase + 0x237F3B) = 0x101C;

		// Don't restrict dynlib information.
		*(uint64_t *)(kbase + 0x2B2620) = 0x9090909090C3C031;

		// Allow usage of mangled symbols in dynlib_do_dlsym().
		*(uint16_t *)(kbase + 0x2AFB47) = 0x9090;
		*(uint16_t *)(kbase + 0x2AFB47 + 2) = 0x9090;
		*(uint16_t *)(kbase + 0x2AFB47 + 4) = 0x9090;

		*(uint32_t *)(kbase + 0x19ECEB0) = 0;

		*(uint8_t*)(kbase + 0x117B0) = 0xB0;
		*(uint8_t*)(kbase + 0x117B1) = 0x01;
		*(uint8_t*)(kbase + 0x117B2) = 0xC3;

		*(uint8_t*)(kbase + 0x117C0) = 0xB0;
		*(uint8_t*)(kbase + 0x117C1) = 0x01;
		*(uint8_t*)(kbase + 0x117C2) = 0xC3;

		*(uint8_t*)(kbase + 0x13F03F) = 0x31;
		*(uint8_t*)(kbase + 0x13F040) = 0xC0;
		*(uint8_t*)(kbase + 0x13F041) = 0x90;
		*(uint8_t*)(kbase + 0x13F042) = 0x90;
		*(uint8_t*)(kbase + 0x13F043) = 0x90;

		cpu_enable_wp();
	}
	else if (fw_version == 0x455) {


		kernel_ptr = (uint8_t*)kbase;
		got_prison0 = (void**)&kernel_ptr[KERN_455_PRISON_0];
		got_rootvnode = (void**)&kernel_ptr[KERN_455_ROOTVNODE];

		cpu_disable_wp();


		*(uint8_t*)(kbase + 0x143BF2) = 0x90; //0x0F
		*(uint8_t*)(kbase + 0x143BF3) = 0xE9; //0x84
		*(uint8_t*)(kbase + 0x143E0E) = 0x90; //0x74
		*(uint8_t*)(kbase + 0x143E0F) = 0x90; //0x0C

		cpu_enable_wp();

	}
	else if (fw_version == 0x474) {

		kernel_ptr = (uint8_t*)kbase;
		uint8_t *kmem;

		//.......

		cpu_disable_wp();


		// enable mmap of all SELF 5.05
		uint8_t* map_self_patch1 = &kernel_ptr[0x169820];
		uint8_t* map_self_patch2 = &kernel_ptr[0x169810];
		uint8_t* map_self_patch3 = &kernel_ptr[0x143277];

		// sceSblACMgrIsAllowedToMmapSelf result
		kmem = (uint8_t*)map_self_patch1;
		kmem[0] = 0xB8;
		kmem[1] = 0x01;
		kmem[2] = 0x00;
		kmem[3] = 0x00;
		kmem[4] = 0x00;
		kmem[5] = 0xC3;

		//................................

		cpu_enable_wp();

	}

	return 0;

}


static int OrbisRecursiveSearch(char *path, const char *file) {
	DIR *dir;


	char *slash = "/";

	int ret = 1;

	struct dirent *entry;
	//checking if it failed to open and report errors to STDERR
	if ((dir = opendir(path)) == NULL) {
		return EXIT_FAILURE;
	} //debugNetPrintf(DEBUG, "New Search Query for File: %s\n Starting in Dir: %s\n", file, path);


		debugNetPrintf(DEBUG, "Looking for File: %s\n Currently in Dir: %s\n", file, path);

	while ((entry = readdir(dir))) {

		//if is . or .. we continue to prevent winging back and forth

		if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
			continue;

		//we check if the path has already a / if not we add one

		int length = strlen(path);

		if (path[length - 1] != '/') {
			slash = "/";
		}

		length += strlen(entry->d_name) + 2;
		char *newpath = malloc(length);
		if (!newpath) {
			break;
		}

		snprintf(newpath, length, "%s%s%s", path, slash, entry->d_name);

		if (strcmp(entry->d_name, file) == 0) {
			debugNetPrintf(DEBUG, "Was found here %s Search Successful\n", newpath);
			copyFile(newpath, "/data/orbislink/homebrew.elf");
			ret = EXIT_SUCCESS;
			break;
		}
		//checking if is a directory to do a recursive call
		// using DT_DIR to avoid the use of lstat or stat
		// if not directory we free the memory and move on
		if (entry->d_type == DT_DIR)
			OrbisRecursiveSearch(newpath, file);
		else {
			free(newpath);
			continue;
		}

		free(newpath);
	}
	if (closedir(dir) != 0) {
		return EXIT_FAILURE;
	}

	return ret;

}

static void OrbisRecursiveSearch1(char *sourcedir, char* destdir)
{
	DIR *dir;
	struct dirent *dp;
	struct stat info;
	char src_path[1024], dst_path[1024];

	dir = opendir(sourcedir);
	if (!dir)
		return;

	//mkdir(destdir, 0777);

	while ((dp = readdir(dir)) != NULL)
	{
		if (!strcmp(dp->d_name, ".") || !strcmp(dp->d_name, ".."))
		{
			// do nothing (straight logic)
		}
		else
		{
			sprintf(src_path, "%s/%s", sourcedir, dp->d_name);
			printf(dst_path, "%s/%s", destdir, dp->d_name);
			if (!stat(src_path, &info))
			{
				if (S_ISDIR(info.st_mode))
				{
					OrbisRecursiveSearch(src_path, destdir);
				}
				else if (S_ISREG(info.st_mode))
				{
						copyFile(src_path, dst_path);
				}
			}
		}
	}
	closedir(dir);
}


int psxdevloader()
{
	

	int ret = initOrbisLinkApp();
	if (ret >= 0)
	{

		debugNetPrintf(DEBUG, "[ELFLOADER] Starting Up\n");

		syscall(11, unjail);

		debugNetPrintf(DEBUG, "[ELFLOADER] Broken out of the Jail\n");

		debugNetPrintf(DEBUG, "[ELFLOADER] Loading Homebrew.elf from PS4\n");

		int fdz = sceKernelOpen("/data/orbislink/", 0x0000, 0);
		if (fdz<0)
		{
			mkdir("/data/orbislink", 0777);
			debugNetPrintf(DEBUG, "[ELFLOADER] making folder\n");

		}
		else
		{
			//....
		}

		debugNetPrintf(DEBUG, "[ELFLOADER] Starting OrbisRecursiveSearch();\n");

		char *file = "homebrew.elf";

		OrbisRecursiveSearch("/mnt/sandbox/pfsmnt", file);
		if (!OrbisRecursiveSearch)
		{
			debugNetPrintf(DEBUG, "[ELFLOADER] OrbisRecursiveSearch has failed\n");
		}

		debugNetPrintf(DEBUG, "[ELFLOADER] OrbisRecursiveSearch has returned 0\n");

		/************************************************/
		/********* FILE EDITING HERE**********************/
		/*************************************************/


		FILE *f = fopen("/data/orbislink/homebrew.elf", "r+b");
		fseek(f, 0, SEEK_SET);
		unsigned char newByte = 0x7F;
		fwrite(&newByte, sizeof(newByte), 1, f);
		fseek(f, 1, SEEK_SET);
		unsigned char newBytea = 0x45;
		fwrite(&newBytea, sizeof(newBytea), 1, f);
		fseek(f, 2, SEEK_SET);
		unsigned char newByteb = 0x4C;
		fwrite(&newByteb, sizeof(newByteb), 1, f);
		fseek(f, 3, SEEK_SET);
		unsigned char newBytec = 0x46;
		fwrite(&newBytec, sizeof(newByte), 1, f);
		fseek(f, 4, SEEK_SET);
		unsigned char newByted = 0x02;
		fwrite(&newByted, sizeof(newByted), 1, f);
		close(f);


		debugNetPrintf(DEBUG, "[ELFLOADER] File Editing Done\n");

		/************************************************/
		/********* ELF EXCUTING    **********************/
		/*************************************************/

		orbisExecUserElf();

		while (!globalConf.orbisLinkFlag)
		{

		}
	}
	else
	{
		debugNetPrintf(DEBUG, "[ELFLOADER]something wrong happen initOrbisLinkApp return 0x%8x %d \n", ret, ret);
		debugNetPrintf(DEBUG, "[ELFLOADER]Exiting\n");

	}
	finishOrbisLinkApp();

	printf("app done");

	exit(0);

	return 0;
}
