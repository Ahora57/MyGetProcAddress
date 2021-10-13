#pragma once
#include "NoCrt.h"


namespace WindowsLeak
{

    __forceinline PIMAGE_SECTION_HEADER
        RtlSectionTableFromVirtualAddress(
            IN PIMAGE_NT_HEADERS NtHeaders,
            IN PVOID Base,
            IN ULONG Address
        )

        /*++
        Routine Description:
            This function locates a VirtualAddress within the image header
            of a file that is mapped as a file and returns a pointer to the
            section table entry for that virtual address
        Arguments:
            NtHeaders - Supplies the pointer to the image or data file.
            Base - Supplies the base of the image or data file.
            Address - Supplies the virtual address to locate.
        Return Value:
            NULL - The file does not contain data for the specified directory entry.
            NON-NULL - Returns the pointer of the section entry containing the data.
        --*/

    {
        ULONG i;
        PIMAGE_SECTION_HEADER NtSection;

        NtSection = IMAGE_FIRST_SECTION(NtHeaders);
        for (i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++) {
            if ((ULONG)Address >= NtSection->VirtualAddress &&
                (ULONG)Address < NtSection->VirtualAddress + NtSection->SizeOfRawData
                ) {
                return NtSection;
            }
            ++NtSection;
        }

        return NULL;
    }

    __forceinline PVOID
        RtlAddressInSectionTable(
            IN PIMAGE_NT_HEADERS NtHeaders,
            IN PVOID Base,
            IN ULONG Address
        )

        /*++
        Routine Description:
            This function locates a VirtualAddress within the image header
            of a file that is mapped as a file and returns the seek address
            of the data the Directory describes.
        Arguments:
            NtHeaders - Supplies the pointer to the image or data file.
            Base - Supplies the base of the image or data file.
            Address - Supplies the virtual address to locate.
        Return Value:
            NULL - The file does not contain data for the specified directory entry.
            NON-NULL - Returns the address of the raw data the directory describes.
        --*/

    {
        PIMAGE_SECTION_HEADER NtSection;

        NtSection = RtlSectionTableFromVirtualAddress(NtHeaders,
            Base,
            Address
        );
        if (NtSection != NULL) {
            return(((PCHAR)Base + ((ULONG_PTR)Address - NtSection->VirtualAddress) + NtSection->PointerToRawData));
        }
        else {
            return(NULL);
        }
    }



    __forceinline PVOID RtlpImageDirectoryEntryToData32(
        IN PVOID Base,
        IN BOOLEAN MappedAsImage,
        IN USHORT DirectoryEntry,
        OUT PULONG Size,
        PIMAGE_NT_HEADERS32 NtHeaders
    )
    {
        ULONG DirectoryAddress;

        if (DirectoryEntry >= NtHeaders->OptionalHeader.NumberOfRvaAndSizes) {
            return(NULL);
        }

        if (!(DirectoryAddress = NtHeaders->OptionalHeader.DataDirectory[DirectoryEntry].VirtualAddress)) {
            return(NULL);
        }

        if (Base < MyMmHighestUserAddress) {
            if ((PVOID)((PCHAR)Base + DirectoryAddress) >= MyMmHighestUserAddress) {
                return(NULL);
            }
        }

        *Size = NtHeaders->OptionalHeader.DataDirectory[DirectoryEntry].Size;
        if (MappedAsImage || DirectoryAddress < NtHeaders->OptionalHeader.SizeOfHeaders) {
            return((PVOID)((PCHAR)Base + DirectoryAddress));
        }

        return(RtlAddressInSectionTable((PIMAGE_NT_HEADERS)NtHeaders, Base, DirectoryAddress));
    }


    __forceinline PVOID RtlpImageDirectoryEntryToData64
    (
        IN PVOID Base,
        IN BOOLEAN MappedAsImage,
        IN USHORT DirectoryEntry,
        OUT PULONG Size,
        PIMAGE_NT_HEADERS64 NtHeaders
    )
    {
        ULONG DirectoryAddress;

        if (DirectoryEntry >= NtHeaders->OptionalHeader.NumberOfRvaAndSizes) {
            return(NULL);
        }

        if (!(DirectoryAddress = NtHeaders->OptionalHeader.DataDirectory[DirectoryEntry].VirtualAddress)) {
            return(NULL);
        }

        if (Base < MyMmHighestUserAddress) {
            if ((PVOID)((PCHAR)Base + DirectoryAddress) >= MyMmHighestUserAddress) {
                return(NULL);
            }
        }

        *Size = NtHeaders->OptionalHeader.DataDirectory[DirectoryEntry].Size;
        if (MappedAsImage || DirectoryAddress < NtHeaders->OptionalHeader.SizeOfHeaders) {
            return((PVOID)((PCHAR)Base + DirectoryAddress));
        }

        return(RtlAddressInSectionTable((PIMAGE_NT_HEADERS)NtHeaders, Base, DirectoryAddress));
    }

    __forceinline PVOID
        RtlImageDirectoryEntryToData(
            IN PVOID Base,
            IN BOOLEAN MappedAsImage,
            IN USHORT DirectoryEntry,
            OUT PULONG Size
        )

        /*++
        Routine Description:
            This function locates a Directory Entry within the image header
            and returns either the virtual address or seek address of the
            data the Directory describes.
        Arguments:
            Base - Supplies the base of the image or data file.
            MappedAsImage - FALSE if the file is mapped as a data file.
                          - TRUE if the file is mapped as an image.
            DirectoryEntry - Supplies the directory entry to locate.
            Size - Return the size of the directory.
        Return Value:
            NULL - The file does not contain data for the specified directory entry.
            NON-NULL - Returns the address of the raw data the directory describes.
        --*/

    {
        PIMAGE_NT_HEADERS NtHeaders;

        if (LDR_IS_DATAFILE(Base)) {
            Base = LDR_DATAFILE_TO_VIEW(Base);
            MappedAsImage = FALSE;
        }

        NtHeaders = RtlImageNtHeader(Base);

        if (!NtHeaders)
            return NULL;

        if (NtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            return (RtlpImageDirectoryEntryToData32(Base,
                MappedAsImage,
                DirectoryEntry,
                Size,
                (PIMAGE_NT_HEADERS32)NtHeaders));
        }
        else if (NtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            return (RtlpImageDirectoryEntryToData64(Base,
                MappedAsImage,
                DirectoryEntry,
                Size,
                (PIMAGE_NT_HEADERS64)NtHeaders));
        }
        else {
            return (NULL);
        }
    }




    __forceinline PVOID MiLocateExportName
    (
        IN PVOID DllBase,
        char* FunctionName
    )
        
   
       // https://wasm.in/threads/analog-getprocaddress.34236/
        

    {
        PVOID Func;
        PULONG NameTableBase;
        PUSHORT NameOrdinalTableBase;
        PIMAGE_EXPORT_DIRECTORY ExportDirectory;
        PULONG Addr;
        ULONG ExportSize;
        LONG Low;
        LONG Middle;
        LONG High;
        LONG Result;
        USHORT OrdinalNumber;

        PAGED_CODE();

        Func = NULL;

        //
        // Locate the DLL's export directory.
        //

        ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)RtlImageDirectoryEntryToData(
            DllBase,
            TRUE,
            IMAGE_DIRECTORY_ENTRY_EXPORT,
            &ExportSize);

        if (ExportDirectory) {

            NameTableBase = (PULONG)((PCHAR)DllBase + (ULONG)ExportDirectory->AddressOfNames);
            NameOrdinalTableBase = (PUSHORT)((PCHAR)DllBase + (ULONG)ExportDirectory->AddressOfNameOrdinals);

            //
            // Look in the export name table for the specified function name.
            //

            Low = 0;
            Middle = 0;
            High = ExportDirectory->NumberOfNames - 1;

            while (High >= Low) {

                //
                // Compute the next probe index and compare the export name entry
                // with the specified function name.
                //

                Middle = (Low + High) >> 1;
                Result = NoCRT::string::strcmp(FunctionName,
                    (PCHAR)((PCHAR)DllBase + NameTableBase[Middle]));

                if (Result < 0) {
                    High = Middle - 1;
                }
                else if (Result > 0) {
                    Low = Middle + 1;
                }
                else {
                    break;
                }
            }

            //
            // If the high index is less than the low index, then a matching table
            // entry was not found.  Otherwise, get the ordinal number from the
            // ordinal table and location the function address.
            //

            if (High >= Low) {

                OrdinalNumber = NameOrdinalTableBase[Middle];
                Addr = (PULONG)((PCHAR)DllBase + (ULONG)ExportDirectory->AddressOfFunctions);
                Func = (PVOID)((ULONG_PTR)DllBase + Addr[OrdinalNumber]);

                //
                // If the function address is w/in range of the export directory,
                // then the function is forwarded, which is not allowed, so ignore
                // it.
                //

                if ((ULONG_PTR)Func > (ULONG_PTR)ExportDirectory &&
                    (ULONG_PTR)Func < ((ULONG_PTR)ExportDirectory + ExportSize)) {
                    Func = NULL;
                }
            }
        }

        return Func;
    }

}