Mifare dumps parser 
=======

Mifare Classic 1k/4k and Mifare Mini (320 bytes) dumps parser in human readable format.  
Dumps can be grabbed with [mfterm](https://github.com/4ZM/mfterm), [mfoc](https://github.com/nfc-tools/mfoc) or nfc-mfclassic tools from libnfc.org  
Dump file size must be 320, 1024, 2048 or 4096 bytes.

Included ```mfc4k.mfd``` -- Mifare 4k dump for testing, and ```mfc1k.mfd``` -- Mifare 1k dump for testing  

## Another tools
 - [010 Editor](https://www.sweetscape.com/010editor/) — hex editor that has Mifare template. Very handy for editing `mfd` files.
 - [mfterm](https://github.com/4ZM/mfterm) — Mifare terminal. Also can view and edit `mfd` dumps.

#### Building
The build should be as simple as running these commands:

    cmake .
    make
    
#### Usage:
```mfdread ./mfc4k.mfd```

![Mifare mfd dump parser](doc/mfdread1.png)

The total memory of 1024 bytes in Mifare Classic (1k) and 4096 bytes in Mifare 4k is divided into 16 sectors of 64 bytes, each of the sectors is divided into 4 blocks of 16 bytes. Blocks 0, 1 and 2 of each sector can store data and block 3 is used to store keys and access bits (the exception is the ‘Manufacturer Block’ which can not store data).
![Mifare memory structure](doc/MiFare_Memory_Structure.png)

The memory of 1KB and 4KB MIFARE Classic cards is ordered in a similar way. On both cards the first block (block 0) contains the UID, BCC, SAK, ATQA and Manufacturer data. This block is locked and cannot be altered. But some times it can be ;)  
![Mifare zero block structure](doc/0blockmifare.png)

##### Access bits
Access bits define the way the data in the sector trailer and the data blocks can be accessed. Access bits are stored twice – inverted and non-inverted in the sector trailer as shown in the images.
![Mifare zero block structure](doc/MiFare_Access_Bits.png)

Some examples:

Data stored in the sector trailer:  
01 02 03 04 05 06 FF 07 80 69 11 12 13 14 15 16  
01 02 03 04 05 06 – Key A  
FF 07 80 69 – Access bits  
11 12 13 14 15 16 – Key B (or data if Key B is not used)  

Bytes 6, 7, 8 are access data  
FF 07 80  

Binary representation:  
**1**111**1**111 = FF  
**(0)**000**0**111 = 07  
**(1)**000**(0)**000 = 80  

The bits that are bolded and in parentheses are the ones that define access to keys (C13, C23, C33 in the image above) and they form the 001 sequence. The bits that are bolded and not in parentheses are the same bits inverted. They form, as expected, the sequence 110.

From the table above I can see that 001 means that Key A can not be read, but can be written and Key B may be read. This is the "transport configuration" and was read from the card that was never used.

Another example where access bits 6,7,8 are 0x78 0x77 0x88  
![mifare access bits explanation](doc/mifare_access_bits_explanation.png)

#### Terms
Abbreviation  | Meaning 
------------- | -------------
T=CL | ISO 14443-4 protocol
T=0  | ISO 7816-3 character-level protocol
T=1  | ISO 7816-3 block-level protocol
UID  | Unique Identifier, Type A
RID  | Random ID, typically dynamically generated at Power-on Reset (UID0 = “0x08”, Random number in UID1… UID3)
NUID  | Non-Unique Identifier
ATQA  | Answer To Request, type A 
ATQB  | Answer To Request, type B
SAK  | Select Acknowledge, Type A
RATS | Request for Answer To Select
ATS  | Answer To Select 
ATR  | Anser To Reset
APDU  | Application Protocol Data Unit
DIF  | Dual Interface (cards)
COS  | Card Operating System
CL  | Cascade Level acc. to ISO/IEC 14443-3
CT  | Cascade Tag, Type A
NFC  | Near Field Communication
PCD  | Proximity Coupling Device (“Contactless Reader”)
PICC  | Proximity Integrated Circuit (“Contactless Card”)
PKE  | Public Key Encryption (like RSA or ECC)
REQA  | Request Command, Type A (command 0x26)
WUPA | Wake-up type A (command 0x52)
SEL  | Select Command, Type A
RFU  | Reserved for future use
