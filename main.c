/* SPDX-License-Identifier: 0BSD */
/* Copyright (C) 2024 Petr Pazourek
 * Copyright (C) 2014-2024 Pavel Zhovner <pavel@zhovner.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/**************************************************************************//**
 * Mifare dumps parser in human readable format
 * This tool has been originally written in Python, available at
 * https://github.com/zhovner/mfdread
 * under license "I don't fcking care, do whatever you want"
 *****************************************************************************/

/**************************************************************************//**
 * INCLUDE FILES: Header files of modules referenced by this module
 *****************************************************************************/
#include <ctype.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "version.h"
#ifdef _WIN32
#   include <windows.h>
#endif

/**************************************************************************//**
 *                                 DEFINES
 *****************************************************************************/
#define OPT_LONG_HELP       0x100
#define OPT_VERBOSE         0x101
#define OPT_VERSION         0x102

#define ANSI_CTRL_RESET                 "\x1B[0m"
#define ANSI_CTRL_TEXT_RED              "\x1B[0;31m"
#define ANSI_CTRL_TEXT_GREEN            "\x1B[0;32m"
#define ANSI_CTRL_TEXT_BLUE             "\x1B[0;34m"
#define ANSI_CTRL_TEXT_BOLD_INTENSIV_YELLOW  "\x1B[1;93m"

/**************************************************************************//**
 *                    PROTOTYPES OF PRIVATE FUNCTIONS
 *****************************************************************************/

/**************************************************************************//**
 *                              PRIVATE VARIABLES
 *****************************************************************************/
static struct option opts[] = {
    { "help", 0, 0, OPT_LONG_HELP },
    { "version", 0, 0, OPT_VERSION },
    { "verbose", 0, 0, 'v' },
    { "no-color", 0, 0, 'n' },
    { 0, 0, 0, 0 }
};

static const char * progname;
static char *input_file = NULL;
static int verbose = 0;
static bool colored = true;
static bool force_1k = false;
static const char * const bit_rep[8] =
{
    "000", "001", "010", "011", "100", "101", "110", "111"
};

static const char * const permission_trailer[8] =
{
    "- A | A   - | A A",
    "- A | A   A | A A [transport]",
    "- - | A   - | A -",
    "- B | A/B B | - B",
    "- B | A/B - | - B",
    "- - | A/B B | - -",
    "- - | A/B - | - -",
    "- - | A/B - | - -",
};

static const char * const permission_data[8] =
{
    "A/B | A/B   | A/B | A/B [transport]",
    "A/B |  -    |  -  | A/B [value]",
    "A/B |  -    |  -  |  -  [r/w]",
    "  B |   B   |  -  |  -  [r/w]",
    "A/B |   B   |  -  |  -  [r/w]",
    "  B |  -    |  -  |  -  [r/w]",
    "A/B |   B   |   B | A/B [value]",
    " -  |  -    |  -  |  -  [r/w]",
};

static const char *empty_string = "";

static const char *color_keyB = ANSI_CTRL_TEXT_BLUE;
static const char *color_keyA = ANSI_CTRL_TEXT_RED;
static const char *color_access = ANSI_CTRL_TEXT_GREEN;
static const char *color_warning = ANSI_CTRL_TEXT_BOLD_INTENSIV_YELLOW;
static const char *color_default = ANSI_CTRL_RESET;

/**************************************************************************
 Output the command-line options for this daemon.
 **************************************************************************/
static void print_help(void)
{
    printf("\
Usage: %s [OPTION] <FILE>\n\
Parse Mifare dump FILE and show details.\
\n\
Options:\n\
 -h, --help      : Print this help message\n\
     --version   : Print the version number and exit\n\
 -v, --verbose   : Print verbose debug statements\n\
 -1             : Force 1k format\n\
 -n, --no-color  : Do not colorize the output\n"
           , progname);
}

/**************************************************************************
 Print program version
 **************************************************************************/
static void print_version(void)
{
    printf( "%s %d.%02d\n", progname, (int)MAJOR, (int)MINOR);
    printf("Copyright (C) 2024 Petr Pazourek GmbH\n"
           "Copyright (C) 2014-2024 Pavel Zhovner <pavel@zhovner.com>\n"
           "This program is Free Software and has ABSOLUTELY NO WARRANTY\n");
}

/**************************************************************************//**
 *
 *****************************************************************************/
static char *ident_from_argv0(char *argv0)
{
    char *p;

    p = strrchr ( argv0, '/' );
    /* get the program name */
    p = strrchr(argv0, '/');
#ifdef __WIN32__
    /* take care of backslash as dir sep in W32 */
    if (!p)
        p = strrchr(argv0,'\\');
#endif /* WIN32 */
    if (p)
        p++;
    else
        p = argv0;

    return p;
}

/**************************************************************************//**
 * Decodes the access bit string for specific block.
 * Returns the three access bits for the block or -1 if the inverted bits do
 * not match the access bits.
 *****************************************************************************/
static int get_access_condition(unsigned sector, unsigned block,
                                unsigned char* access_bits)
{
    if(sector >= 32)
    {
        /* Mifare 4k uses access rights in clusters of 5 blocks each for sectors
           in a range 32 to 39. */
        block = block / 5;
    }

    unsigned bits, inverted;

    /*C1x C2x C3x access bits for block x*/
    /*/C1x /C2x /C3x inverted access bits for block x*/
    switch(block)
    {
    case 0:
        bits = (access_bits[1] >> 2) & 0x04;    /* C10 */
        bits |= (access_bits[2] << 1) & 0x02;   /* C20 */
        bits |= (access_bits[2] >> 4) & 0x01;   /* C30 */
        inverted = (access_bits[0] << 2) & 0x04;    /* /C10 */
        inverted |= (access_bits[0] >> 3) & 0x02;   /* /C20 */
        inverted |= (access_bits[1] >> 0) & 0x01;   /* /C30 */
        break;

    case 1:
        bits = (access_bits[1] >> 3) & 0x04;    /* C11 */
        bits |= (access_bits[2] << 0) & 0x02;   /* C21 */
        bits |= (access_bits[2] >> 5) & 0x01;   /* C31 */
        inverted = (access_bits[0] << 1) & 0x04;    /* /C11 */
        inverted |= (access_bits[0] >> 4) & 0x02;   /* /C21 */
        inverted |= (access_bits[1] >> 1) & 0x01;   /* /C31 */
        break;

    case 2:
        bits = (access_bits[1] >> 4) & 0x04;    /* C12 */
        bits |= (access_bits[2] >> 1) & 0x02;   /* C22 */
        bits |= (access_bits[2] >> 6) & 0x01;   /* C32 */
        inverted = (access_bits[0] << 0) & 0x04;    /* /C12 */
        inverted |= (access_bits[0] >> 5) & 0x02;   /* /C22 */
        inverted |= (access_bits[1] >> 2) & 0x01;   /* /C32 */
        break;

    case 3:
        bits = (access_bits[1] >> 5) & 0x04;    /* C13 */
        bits |= (access_bits[2] >> 2) & 0x02;   /* C23 */
        bits |= (access_bits[2] >> 7) & 0x01;   /* C33 */
        inverted = (access_bits[0] >> 1) & 0x04;    /* /C13 */
        inverted |= (access_bits[0] >> 6) & 0x02;   /* /C23 */
        inverted |= (access_bits[1] >> 3) & 0x01;   /* /C33 */
        break;

    default:
        return -1;
    }

    if(bits != ((~inverted)&0x07))
    {
        return -1;
    }

    return bits;
}

/**************************************************************************//**
 *
 *****************************************************************************/
static int print_info(FILE *fp)
{
    unsigned data_size;
    unsigned char data[4097];
    int sector;
    int sectors = 0;

    memset(data, 0, sizeof(data));
    data_size = fread(data, sizeof(uint8_t), sizeof(data), fp);

    if(force_1k)
    {
        data_size = 1024;
    }

    switch(data_size)
    {
    case 320u:
        sectors = 5u;
        break;
    case 1024u:
        sectors = 16u;
        break;
    case 2048u:
        sectors = 32u;
        break;
    case 4096u:
        sectors = 32u + 8u;
        break;
    default:
        fprintf(stderr, "Wrong file size: %u bytes.\n"
                "Only 320, 1024, 2048 or 4096 bytes is allowed.", data_size);
        return EXIT_FAILURE;
    }

    printf("File size: %u bytes. Expected %d sectors\n", data_size, sectors);
    /*
     UID 4b:
     11223344440804006263646566676869
     ^^^^^^^^                         UID
             ^^                       BCC
               ^^                     SAK(*)
                 ^^^^                 ATQA
                     ^^^^^^^^^^^^^^^^ Manufacturer data
    */

    /* 4bit UID */
    printf("\tUID: %02x%02x%02x%02x\n", data[0], data[1], data[2], data[3]);
    printf("\tBCC:  %02x\n", data[4]);
    printf("\tSAK:  %02x\n", data[5]);
    printf("\tATQA: %02x%02x\n", data[6], data[7]);

    printf("====================================================================================================\n");
    printf("| Sect | Blck |            Data                  | Access |  r  |  w    |  i  | d/t/r [info]       |\n");
    printf("|      |      |                                  |  cond. |   A | Acc.  | B                        |\n");
    printf("|      |      | %sKey A%s      %sAccess Bits%s     %sKey B%s |        | r w | r   w | r w                      |\n",
           color_keyA, color_default, color_access,
           color_default, color_keyB, color_default);
    for(sector = 0; sector < sectors; sector++)
    {
        unsigned sector_start;
        unsigned char *keyA, *keyB, *access_bits;
        unsigned sector_size;
        unsigned block;
        unsigned blocks;
        unsigned block_size;

        if(sector < 32u)
        {
            blocks = 4u;
            block_size = 16u;
            sector_size = block_size * blocks;
            sector_start = sector * sector_size;
        }
        else
        {
            blocks = 16u;
            block_size = 16u;
            sector_size = block_size * blocks;
            sector_start = 2048u + (sector - 32u) * sector_size;
        }
        keyA = &data[sector_start + sector_size - block_size + 0];
        keyB = &data[sector_start + sector_size - block_size + 10];
        access_bits = &data[sector_start + sector_size - block_size + 6];
        printf("====================================================================================================\n");

        for(block = 0; block < blocks; block++)
        {
            unsigned i;
            unsigned block_start = sector_start + block * block_size;
            char str_sector[6];
            char str_permissions[64] = {0};
            int access_condition = get_access_condition(sector, block, access_bits);
            char str_data_hex[64] = {0};
            char str_data_ascii[64] = {0};
            char str_access_bits[64]= {0};
            int pos;

            /* show sector number nexto to each 2nd block */
            if(block == 1)
            {
                snprintf( str_sector, sizeof(str_sector), "%d", sector);
            }
            else
            {
                strcpy(str_sector, empty_string);
            }

            /* prepare data in hex format */
            if(block == blocks-1)
            {
                pos = 0;

                /* the trailer contains keys and access bits */
                /* print keyA */
                pos += sprintf(&str_data_hex[pos], "%s", color_keyA);
                for(i=0; i<6; i++)
                {
                    pos+= sprintf( &str_data_hex[pos], "%02x", keyA[i]);
                }
                /* print access bits */
                pos += sprintf(&str_data_hex[pos], "%s", color_access);
                for(i=0; i<4; i++)
                {
                    pos+= sprintf( &str_data_hex[pos], "%02x", access_bits[i]);
                }
                /* print keyB */
                pos += sprintf(&str_data_hex[pos], "%s", color_keyB);
                for(i=0; i<6; i++)
                {
                    pos+= sprintf( &str_data_hex[pos], "%02x", keyB[i]);
                }
                pos += sprintf(&str_data_hex[pos], "%s", color_default);
            }
            else
            {
                /* print data of one block */
                for(i=0; i<block_size; i++)
                {
                    sprintf( &str_data_hex[i*2], "%02x", data[block_start + i]);
                }
            }

            if((access_condition < 0) || (access_condition > 7))
            {
                /* invalid access bits */
                sprintf( str_access_bits, "%sERR%s", color_warning,
                    color_default);

                strcpy( str_permissions, empty_string);
            }
            else if((block == 0) && (sector == 0))
            {
                /* The 1st block in the 1st sector contains Manufacturer
                   data that it's not possible to change */
                sprintf( str_access_bits, "%s%s%s", color_access,
                    bit_rep[access_condition], color_default);
                sprintf( str_permissions, "-" );
            }
            else if(block == blocks-1)
            {
                /* prepare access bits in bin format for trailer */
                sprintf( str_access_bits, "%s%s%s", color_access,
                    bit_rep[access_condition], color_default);
                sprintf( str_permissions, "%s", permission_trailer[access_condition]);
            }
            else
            {
                /* prepare access bits in bin format */
                sprintf( str_access_bits, "%s%s%s", color_access,
                    bit_rep[access_condition], color_default);
                sprintf( str_permissions, "%s", permission_data[access_condition]);
            }

            printf("| %-5s|  %-3d | %s |  %s   | %-38s | %s\n", str_sector,
                   block, str_data_hex, str_access_bits,
                   str_permissions, str_data_ascii);

        }
    }
    printf("====================================================================================================\n");

    return 0;
}

/**************************************************************************//**
 *
 *****************************************************************************/
int main(int argc, char **argv)
{
    FILE* fp;
    progname = ident_from_argv0(argv[0]);

    while (1)
    {
        int c, option_index = 0;
        c = getopt_long(argc, argv, "n1hVv", opts, &option_index);
        if (c == -1)
            break;

        switch (c)
        {
        case 'h':
        case OPT_LONG_HELP:
            print_help();
            exit(EXIT_SUCCESS);
            break;

        case OPT_VERSION:
            print_version();
            exit(EXIT_SUCCESS);
            break;

        case 'v':
        case OPT_VERBOSE:
            verbose++;
            break;

        case '1':
            force_1k = true;
            break;

        case 'n':
            colored = false;
            break;

        default:
            print_help();
            exit(EXIT_FAILURE);
            break;
        }
    }

    if( optind == argc )
    {
        fprintf(stderr, "No input file has been specified\n");
        exit(EXIT_FAILURE);
    }
    else if( optind != argc - 1)
    {
        fprintf(stderr, "Only one input file can be specified\n");
        exit(EXIT_FAILURE);
    }
    else
    {
        input_file = argv[optind];
    }

    if(strcmp(input_file, "-") == 0)
    {
        fp = stdin;
    }
    else
    {
        fp = fopen(input_file, "rb");
        if (fp == NULL)
        {
           fprintf(stderr, "Error opening the input file %s", input_file);
           exit(EXIT_FAILURE);
        }
    }

    /* init console to be able to show colors */
#ifdef _WIN32
    HANDLE hOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode;
    GetConsoleMode(hOutput, &dwMode);
    dwMode |= ENABLE_PROCESSED_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    if (!SetConsoleMode(hOutput, dwMode))
    {
        colored = false;
    }
#endif

    if(colored == false)
    {
        /* replace the ANSI codes by an emty string, so the color will not
           be set */
        color_keyB = empty_string;
        color_keyA = empty_string;
        color_access = empty_string;
        color_warning = empty_string;
        color_default = empty_string;
    }

    int r = print_info(fp);

    if(fp != stdin)
    {
        fclose(fp);
    }
    return r;
}
