/* Copyright (C) 2013 IP Infusion, Inc.  All Rights Reserved. */
#ifndef _PAL_MEMORY_H
#define _PAL_MEMORY_H

#include "pal.h"
#include "memory.h"
#include "pal_memory.def"

#undef pal_mem_set
#define pal_mem_set memset

#undef pal_mem_cpy
#define pal_mem_cpy memcpy

#undef pal_mem_cmp
#define pal_mem_cmp memcmp

#undef pal_mem_move
#define pal_mem_move memmove

/*
   This indicates the machine word alignment requirement for the platform,
   in bytes.  Usually it's the machine word size, but sometimes (some odd
   architectures, such as the i80386sx) it's the system bus size.

   What this really means is a table which looks like this...

     Processor            Suggested (min) (wordsize)
     -------------------  ---------------------
     i80386SX or equiv    2 (1)  (ws=4,bs=2)
     i80386DX or equiv    4 (1)  (ws=4,bs=4)
     80486SLC or equiv    2 (1)  (ws=4,bs=2)
     i80486 or equiv      4 (1)  (ws=4,bs=4)
     Pentium or equiv     4 (1)  (ws=4,bs=8)
     Itanium or equiv     8 (8?) (ws=8,bs=8)
     AMD K6 or equiv      8 (1)  (ws=4,bs=8)
     Athlon or equiv      8 (1)  (ws=4,bs=8)
     M68000,M68020        4 (4)  (ws=4,bs=4)
     M68030,M68040,M68060 4 (1)  (ws=4,bs=4)
     PPC                  4 (4?) (ws=4,bs=4)
     ARM                  4 (4?) (ws=4,bs=4)
     Alpha                8 (8?) (ws=8,bs=8)

   MIPS R7000 and up seem to have 64-bit register files but only 32-bit
   memory addressing.  Not sure what to do about that.  Probably needs to
   be defined based upon the particular processor and board.

   Others probably need to see the board and processor reference books.
   You really should check anyway, in case these figures aren't right for
   your particular application or implementation.

   Note that even if the processor allows this to be set to 1, it usually
   is considerably faster if it is set as suggested above.  This is because
   most processors spend considerably more time reading misaligned memory
   data than aligned.

   This is also used as part of the memory cell validation on free and on
   realloc, since OSes do not generate misaligned cells.  However, it does
   mean that you can't use this to optimise cache hits since it is possible
   that the cell returned by the OS will misalign if you expand it.  This
   must therefore never be larger than the machine word size in bytes.

   THIS MUST BE A POSITIVE POWER OF TWO UNDER ANY CONDITION.  Setting it
   to 1 (2^0) will effectively disable alignment forcing and checking,
   (disabling it can cost dearly in memory cycle time).
*/
#define MEM_ALIGNMENT_REQUIREMENT 4

/*
   Unsigned integer which is the same size as (or larger than) a pointer.

   Pointer math is done using this as override to attempt to ensure the
   integers used don't cause truncation problems.  Most platforms will
   find 'unsigned int' adequate, but some may not.  Examples of places
   where it should NOT work are given, but others may exist (pointer
   class is in x86 notation -- segment bits : offset bits).

     Platform      Pointer    sizeof(void*)  sizeof(int)  Req'd bytes
     ------------  ---------  -------------  -----------  -----------
     MS/PC-DOS     16:16      4              2            4
     Win16         16:16      4              2            4
     Win32s        16:32      6              4            6 (or 8)

   Probably the worst part about these platforms is that the bits don't
   add up in the way expected, so pointer math may be gibberish anyhow.

   Most platforms this should work (some examples)...

     Platform      Pointer    sizeof(void*)  sizeof(int)
     ------------  ---------  -------------  -----------
     OS/2          0:32       4              4
     Win32         0:32       4              4
     Linux         0:32       4              4

   Both above tables from x86 viewpoint because it's the architecture
   with the most environments where sizeof(void*) != sizeof(int).
   Other platforms and environments will vary.

   On really screwey systems where pointers aren't the same size as
   any integer type, and don't meet alignment requirements, some of
   the structs will not be aligned optimally.  This unfortunate effect
   should be only a performance reduction.
*/
typedef u_int32_t mem_int;

/*
   Unsigned integer which is the same size as a machine word.  This is
   used for accounting and other things which need to maintain alignment.
*/
typedef u_int32_t mach_word;

/*
   These are here so when the size of a machine word is defined, the way
   to display it in fixed length hex (and the row header line) can be made
   the proper size.

   The MEM_ADDR_LEN value is the number of nybbles (two per byte) in an
   address on the system, represented as a string.

   The MEM_ADDR_LINE value is a string made up of that many hyphens.
*/
#define MEM_ADDR_LEN  "8"
#define MEM_ADDR_LINE "--------"


#endif /* _PAL_MEMORY_H */
