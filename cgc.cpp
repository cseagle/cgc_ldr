/*
   CGC Loader
   Copyright (C) 2014 Chris Eagle
   
   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:
   
   The above copyright notice and this permission notice shall be included in
   all copies or substantial portions of the Software.
   
   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
   THE SOFTWARE.
*/

#define USE_STANDARD_FILE_FUNCTIONS
#define _CRT_SECURE_NO_WARNINGS

#include "../idaldr.h"
#include <typeinf.hpp>

//Some idasdk70 transition macros
#if IDA_SDK_VERSION >= 700

#define beginEA start_ea
#define startEA start_ea 
#define endEA end_ea 
#define doStruct create_struct
#define patch_long patch_dword
#define doByte create_byte
#define doWord create_word
#define doDwrd create_dword

#else //Some idasdk70 transition macros, we are pre 7.0 below

#define start_ea startEA
#define end_ea endEA

#endif //Some idasdk70 transition macros

#ifdef __NT__
#include <windows.h>
#endif

//from intel.hpp
#define R_ds 32 

#include "cgc.h"
#include "sdk_versions.h"

#define f_CGC 0x4141

#define	CI_IDENT	"\177CGC\x01\x01\x01\x43\x01\x00\x00\x00\x00\x00\x00"

void zero_fill(ea_t base, size_t size) {
   //Ida patch_xxx is very SLOW!!!!!
   //workaround is to create temp file containing all your zeros
   //then load that temp file as an additional binary file
   char ftmp[1024];
   qtmpnam(ftmp, sizeof(ftmp));
   size_t block = size;
   if (block > 0x10000) {
      block = 0x10000;
   }
   void *zeros = calloc(block, 1);
   FILE *f = fopen(ftmp, "wb");
   for (size_t done = 0; done < size; done += block) {
      block = size - done;
      if (block > 0x10000) {
         block = 0x10000;
      }
      fwrite(zeros, block, 1, f);
   }
   free(zeros);
   fclose(f);
   linput_t *fin = open_linput(ftmp, false);
   load_binary_file(ftmp, fin, 0, 0, 0, base, size);
   file2base(fin, 0, base, (ea_t)(base + size), FILEREG_PATCHABLE);
   close_linput(fin);
#ifdef __NT__
   DeleteFile(ftmp);   
#else
   unlink(ftmp);
#endif
}

#if IDA_SDK_VERSION >= 700
static int idaapi accept_cgc_file(qstring *fileformatname, qstring *processor,
                                  linput_t *li, const char *filename) {
#else
static int idaapi accept_cgc_file(linput_t *li,
                       char fileformatname[MAX_FILE_FORMAT_NAME], int n) {
#endif
   CGC32_hdr hdr;   
   bool hasPtGnuStack = false;
#if IDA_SDK_VERSION < 700
   if (n) {
      return 0;
   }
#endif
   if(qlread(li, &hdr, sizeof(hdr)) != sizeof(hdr)) {
      return 0;
   }
   if (memcmp(&hdr.e_ident, CI_IDENT, 9) || hdr.e_machine != CM_386 || hdr.e_type != CT_EXEC ||
              hdr.e_version != 1) {
      return 0;
   }
   if (hdr.e_phentsize != sizeof(CGC32_Phdr) || hdr.e_phnum < 1 || hdr.e_phnum > (65536U / sizeof(struct CGC32_Phdr)) || 
      (hdr.e_shnum != 0 && (hdr.e_shentsize != sizeof(CGC32_Shdr) || hdr.e_shstrndx >= hdr.e_shnum))) {
      return 0;
   }

   if (qlseek(li, hdr.e_phoff) != hdr.e_phoff) {
      return 0;
   }
   uint32_t phdrSize = hdr.e_phentsize * hdr.e_phnum;
   CGC32_Phdr *p = (CGC32_Phdr*)::qalloc(phdrSize);
   if (p == NULL) {
      loader_failure("Failed to allocate memory for program headers\n");
   } 
   if (qlread(li, p, phdrSize) != phdrSize) {
      ::qfree(p);
      loader_failure("Failed to read program headers\n");
   }

   for (int i = 0; i < hdr.e_phnum; i++) {
      switch (p[i].p_type) {
         case PT_LOAD: case PT_NULL: case PT_PHDR: case PT_CGCPOV2:
            break;
         case 0x6474e551:  //PT_GNU_STACK
            hasPtGnuStack = true;
            break;
         default:
            //Very strict on what is allowed in PHDRs here.
            ::qfree(p);
            return 0;
      }
   }

   ::qfree(p);

   if (hdr.e_shnum > 0 && hdr.e_shoff < (uint32_t)qlsize(li) && qlseek(li, hdr.e_shoff) == hdr.e_shoff) {
      bool fail = false;
      uint32_t shdrSize = hdr.e_shentsize * hdr.e_shnum;
      CGC32_Shdr *s = (CGC32_Shdr*)::qalloc(shdrSize);
      if (s == NULL) {
         loader_failure("Failed to allocate memory for section headers\n");
      } 
      if (qlread(li, s, shdrSize) != shdrSize) {
         ::qfree(s);
         loader_failure("Failed to read section headers\n");
      }
      char *sectNames = (char*)::qalloc(s[hdr.e_shstrndx].sh_size);
      if (sectNames == NULL) {
         loader_failure("Failed to allocate memory for section strings\n");
      } 
      if (qlseek(li, s[hdr.e_shstrndx].sh_offset) != s[hdr.e_shstrndx].sh_offset) {
         return 0;
      }
      if (qlread(li, sectNames, s[hdr.e_shstrndx].sh_size) != s[hdr.e_shstrndx].sh_size) {
         ::qfree(s);
         ::qfree(sectNames);
         loader_failure("Failed to read section strings\n");
      }
      ::qfree(s);
      ::qfree(sectNames);
      if (fail) {
         return 0;
      }
   }
   if (hasPtGnuStack) {
      msg("Warning: CGC32 binary file contains PT_GNU_STACK\n");
   }
#if IDA_SDK_VERSION < 700
   qsnprintf(fileformatname, MAX_FILE_FORMAT_NAME, "CGC 32 Loader");
#else
   *fileformatname = "CGC 32 Loader";
#endif
   return 1;
}

static til_t *cgcti = NULL;

til_t *init_til(const char *tilFile) {
#if IDA_SDK_VERSION < 700   
   char err[256];
   *err = 0;
   char tilpath[260];
   get_tilpath(tilpath, sizeof(tilpath));     
   return load_til(tilpath, tilFile, err, sizeof(err));
#else  //IDA_SDK_VERSION >= 700
   qstring err;
   return load_til(tilFile, &err);
#endif
}

//Load the CGC header data types, then apply the templates
//at the appropriate offsets in the database
void applyCGCHeaderTemplates(uint32_t base, CGC32_hdr *cgc) {
   if (cgcti == NULL) {
      init_til("gnuunx.til");
      cgcti = init_til("cgc.til");
      if (cgcti == NULL) {
         return;
      }
   }   
#if IDA_SDK_VERSION >= 520
   tid_t cgch = import_type(cgcti, -1, "CGC32_hdr");
   tid_t cgcph = import_type(cgcti, -1, "CGC32_Phdr");
   tid_t cgcsh = import_type(cgcti, -1, "CGC32_Shdr");
   tid_t cgcsym = import_type(cgcti, -1, "CGC32_Sym");
#else
#if IDA_SDK_VERSION >= 510
   add_til2("gnuunx.til", ADDTIL_SILENT);
   add_til2("cgc.til", ADDTIL_SILENT);
#else
   add_til("gnuunx.til");
   add_til("cgc.til");
#endif
   tid_t cgch = til2idb(-1, "CGC32_hdr");
   tid_t cgcph = til2idb(-1, "CGC32_Phdr");
   tid_t cgcsh = til2idb(-1, "CGC32_Shdr");
   tid_t cgcsym = til2idb(-1, "CGC32_Sym");
#endif

   doStruct(base, sizeof(CGC32_hdr), cgch);
   if (cgc->e_phoff) {
      doStruct(base + cgc->e_phoff, sizeof(CGC32_Phdr) * cgc->e_phnum, cgcph);
   }
   if (cgc->e_shoff) {
      doStruct(base + cgc->e_shoff, sizeof(CGC32_Shdr) * cgc->e_shnum, cgcsh);
   }
}

static void make_page(const char *name, uint32_t base, uint32_t perm) {
   if (!add_segm(0, base, base + 0x1000, name, "DATA")) {
      loader_failure();
   }
   for (uint32_t j = base; j < (base + 0x1000); j += 4) {
      patch_long(j, 0);
   }
   segment_t *s = getseg(base);
   if (s != NULL) {
      set_segm_addressing(s, 1);  //set 32 bit addressing
      s->perm = perm;
      s->update();
   }
}

static void idaapi load_cgc_file(linput_t *li, ushort neflags,
                      const char * /*fileformatname*/) {
   CGC32_hdr hdr;
   uint32_t minAddr = 0xffffffff;
   uint32_t mainAddr = 0;
   qlseek(li, 0);
   if (qlread(li, &hdr, sizeof(hdr)) != sizeof(hdr)) {
      loader_failure();
   }
   sel_t ds = find_free_selector();
   set_selector(ds, 0);
   if (hdr.e_phoff != 0) {
      CGC32_Phdr *phdrs = new CGC32_Phdr[hdr.e_phnum];
      ssize_t hsz = hdr.e_phnum * sizeof(CGC32_Phdr);
      if (qlseek(li, hdr.e_phoff) != hdr.e_phoff || qlread(li, phdrs, hsz) != hsz) {
         delete[] phdrs;
         loader_failure();
      }
      uint32_t curr_base = 0;
      uint32_t curr_top = 0;
      uint32_t curr_flags = SEGPERM_READ;
      for (uint32_t i = 0; i < hdr.e_phnum; i++) {
         CGC32_Phdr *ph = &phdrs[i];
         if (ph->p_type == PT_LOAD && ph->p_vaddr != 0 && ph->p_memsz != 0) {
            uint32_t base = ph->p_vaddr & 0xfffff000;
            uint32_t top = (ph->p_vaddr + ph->p_memsz + 0xfff) & 0xfffff000;
            if (curr_base == 0) {
               curr_base = base;
               curr_top = top;
            }
            if (base < minAddr) {
               minAddr = base;
            }

            if (ph->p_flags & PF_X) {
               curr_flags |= SEGPERM_EXEC;
            }
            if (ph->p_flags & PF_R) {
               curr_flags |= SEGPERM_READ;
            }
            if (ph->p_flags & PF_W) {
               curr_flags |= SEGPERM_WRITE;
            }

//            if (hdr.e_shnum == 0) {
            for (uint32_t ea = base; ea < top; ea += 0x1000) {
               segment_t *s = getseg(base);
               if (s == NULL) {
                  zero_fill(ea, 0x1000);
               }
            }
            if (base > curr_top) {
               const char *clazz = (curr_flags & PF_X) ? "CODE" : "DATA";
               if (!add_segm(0, curr_base, curr_top, "LOAD", clazz)) {
                  loader_failure();
               }
               segment_t *s = getseg(curr_base);
               set_segm_addressing(s, 1);  //set 32 bit addressing
               s->perm = curr_flags;
               s->update();

               curr_base = base;
               curr_top = top;
               curr_flags = 0;
            }
            else {
               curr_top = top;
            }
//            }
            if (ph->p_filesz > 0) {
               uint32_t fbase = ph->p_offset & 0xfffff000;
               uint32_t fmax = (ph->p_offset + ph->p_filesz + 0xfff) & 0xfffff000;
               uint32_t fsize = qlsize(li);
               if (fmax > fsize) {
                  fmax = fsize;
               }
//               file2base(li, ph->p_offset, ph->p_vaddr, ph->p_vaddr + ph->p_filesz, FILEREG_PATCHABLE);
               file2base(li, fbase, base, base + (fmax - fbase), FILEREG_PATCHABLE);
            }
         }
      }
      
      if (curr_base > 0) {
         segment_t *s = getseg(curr_base);
         if (s == NULL) {
            const char *clazz = (curr_flags & PF_X) ? "CODE" : "DATA";
            if (!add_segm(0, curr_base, curr_top, "LOAD", clazz)) {
               loader_failure();
            }
            segment_t *s = getseg(curr_base);
            set_segm_addressing(s, 1);  //set 32 bit addressing
            s->perm = curr_flags;
            s->update();
         }
      }
      
      delete[] phdrs;
   }
   
   make_page(".stack", 0xbaaaa000, SEGPERM_READ | SEGPERM_WRITE);
   make_page(".secret", 0x4347c000, SEGPERM_READ | SEGPERM_WRITE);

   if (hdr.e_shoff && hdr.e_shnum && hdr.e_shoff < (uint32_t)qlsize(li)) {
      CGC32_Shdr *shdrs = new CGC32_Shdr[hdr.e_shnum];
      ssize_t ssz = hdr.e_shnum * sizeof(CGC32_Shdr);
      if (qlseek(li, hdr.e_shoff) != hdr.e_shoff || qlread(li, shdrs, ssz) != ssz) {
         delete[] shdrs;
         shdrs = NULL;
      }
      if (shdrs) {
         char *sectNames = (char*)::qalloc(shdrs[hdr.e_shstrndx].sh_size);
         if (sectNames == NULL) {
            loader_failure("Failed to allocate memory for section strings\n");
         } 
         if (qlseek(li, shdrs[hdr.e_shstrndx].sh_offset) != shdrs[hdr.e_shstrndx].sh_offset) {
            loader_failure("seek failure seeking to shstrtab\n");
         }
         if (qlread(li, sectNames, shdrs[hdr.e_shstrndx].sh_size) != shdrs[hdr.e_shstrndx].sh_size) {
            delete[] shdrs;
            ::qfree(sectNames);
            loader_failure("Failed to read section strings\n");
         }
   
         uint32_t symtab = 0;
         uint32_t sym_strtab = 0;
         uint32_t sbase = minAddr;
         
         for (uint32_t i = 0; i < hdr.e_shnum; i++) {
            if (shdrs[i].sh_type == SHT_SYMTAB) {
               symtab = i;
               sym_strtab = shdrs[i].sh_link;
            }
            if (shdrs[i].sh_addr == 0) {
               continue;
            }
            if (shdrs[i].sh_type == SHT_PROGBITS && (shdrs[i].sh_flags & SHF_ALLOC) != 0) {
   /*
               if (sbase < shdrs[i].sh_addr) { //create a segment to bridge the gap
                  add_segm(0, sbase, shdrs[i].sh_addr, NULL, "DATA");
               }
   */
               const char *clazz = (shdrs[i].sh_flags & SHF_EXECINSTR) ? "CODE" : "DATA";
               add_segm(0, shdrs[i].sh_addr, shdrs[i].sh_addr + shdrs[i].sh_size, sectNames + shdrs[i].sh_name, clazz);
               segment_t *s = getseg(shdrs[i].sh_addr);
               if (s != NULL) {
                  uint8_t perm = SEGPERM_READ;
                  set_segm_addressing(s, 1);  //set 32 bit addressing
                  if (shdrs[i].sh_flags & SHF_EXECINSTR) {
                     perm |= SEGPERM_EXEC;
                  }
                  if (shdrs[i].sh_flags & SHF_WRITE) {
                     perm |= SEGPERM_WRITE;
                  }
                  s->perm = perm;
                  s->update();
               }
               if (i < (uint32_t)(hdr.e_shnum - 1)) {
                  sbase = shdrs[i + 1].sh_addr;
               }
            }
            else if (shdrs[i].sh_type == SHT_NOBITS && (shdrs[i].sh_flags & SHF_ALLOC) != 0) {
   /*
               if (sbase < shdrs[i].sh_addr) { //create a segment to bridge the gap
                  add_segm(0, sbase, shdrs[i].sh_addr, NULL, "DATA");
               }
   */
               add_segm(0, shdrs[i].sh_addr, shdrs[i].sh_addr + shdrs[i].sh_size, sectNames + shdrs[i].sh_name, "DATA");
               segment_t *s = getseg(shdrs[i].sh_addr);
               if (s != NULL) {
                  uint8_t perm = SEGPERM_READ;
                  set_segm_addressing(s, 1);  //set 32 bit addressing
                  if (shdrs[i].sh_flags & SHF_EXECINSTR) {
                     perm |= SEGPERM_EXEC;
                  }
                  if (shdrs[i].sh_flags & SHF_WRITE) {
                     perm |= SEGPERM_WRITE;
                  }
                  s->perm = perm;
                  s->update();
               }
               if (i < (uint32_t)(hdr.e_shnum - 1)) {
                  sbase = shdrs[i + 1].sh_addr;
               }
            }
            sbase = shdrs[i].sh_addr + shdrs[i].sh_size;
         }
         ::qfree(sectNames);
         if (symtab) {
            char *strtab = new char[shdrs[sym_strtab].sh_size];
            if (qlseek(li, shdrs[sym_strtab].sh_offset) != shdrs[sym_strtab].sh_offset || 
                qlread(li, strtab, shdrs[sym_strtab].sh_size) != shdrs[sym_strtab].sh_size) {
               delete[] shdrs;
               delete[] strtab;
               return;
            }
   
            uint32_t numSyms = shdrs[symtab].sh_size / shdrs[symtab].sh_entsize;
            CGC32_Sym *syms = new CGC32_Sym[numSyms];
            ssize_t ssz = numSyms * sizeof(CGC32_Sym);
            if (qlseek(li, shdrs[symtab].sh_offset) != shdrs[symtab].sh_offset || qlread(li, syms, ssz) != ssz) {
               delete[] shdrs;
               delete[] strtab;
               delete[] syms;
               return;
            }
            for (uint32_t i = 1; i < numSyms; i++) {
               if (syms[i].st_name) {
                  switch (CGC32_ST_TYPE(syms[i].st_info)) {
                     case STT_FUNC:
                        set_name(syms[i].st_value, strtab + syms[i].st_name, SN_NOWARN);
                        auto_make_code(syms[i].st_value);
                        add_func(syms[i].st_value, BADADDR);
                        if (strcmp(strtab + syms[i].st_name, "main") == 0) {
                           mainAddr = syms[i].st_value;
                        }
                        else if (strcmp(strtab + syms[i].st_name, "_main") == 0) {
                           mainAddr = syms[i].st_value;
                        }
                        break;
                     case STT_OBJECT:
                        set_name(syms[i].st_value, strtab + syms[i].st_name, SN_NOWARN);
                        switch (syms[i].st_size) {
                           case 1:
                              doByte(syms[i].st_value, 1);
                              break;
                           case 2:
                              doWord(syms[i].st_value, 2);
                              break;
                           case 4:
                              doDwrd(syms[i].st_value, 4);
                              break;
                        }
                        break;
                  }
               }
            }
            delete[] syms;
            delete[] strtab;
         }
         
         delete[] shdrs;
      }
   }      

   applyCGCHeaderTemplates(minAddr, &hdr);

   create_filename_cmt();
   add_entry(hdr.e_entry, hdr.e_entry, "_start", true);
   inf.filetype = f_CGC;
   //inf.filetype = f_ELF; //trick IDA into letting us debug
   inf.lflags |= LFLG_PC_FLAT;
   set_default_dataseg(ds);
   inf.beginEA = hdr.e_entry;
   if (mainAddr) {
      jumpto(mainAddr);
   }
   else {
      jumpto(hdr.e_entry);
   }
}

#if IDA_SDK_VERSION < 700
#define LDRF_REQ_PROC 0
#endif

// LOADER DESCRIPTION BLOCK
loader_t LDSC = {
  IDP_INTERFACE_VERSION,
  LDRF_REQ_PROC,    // loader flags
  accept_cgc_file,
  load_cgc_file,
  NULL,
  NULL,
  NULL
};
