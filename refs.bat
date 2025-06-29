//------------------------------------------------
//--- 010 Editor v14.0 Binary Template
//
//      File: ReFS.bt
//   Authors: Konstanin Germanov
//    E-mail: kgermanov@axcient.com
//   Version: 1.2
//   Purpose: Microsoft ReFS
//  Category: Drives
// File Mask: 
//  ID Bytes: [+3] 52 65 46 53
//   History: 
//   1.2 2025-05-23 Konstantin Germanov: Add support resident files, ReFS ver 3.14
//   1.1 2025-05-21 Konstantin Germanov: Add support ReparseTag, ADS, fix 3.7
//   1.0 2023-09-18 Konstantin Germanov: Initial release
//
//------------------------------------------------

LittleEndian();

//---------------  help functions
string Uint64ToHexStr(UINT64 v) {
    local string s;
    SPrintf(s, "0x%Lxh", v);
    return s;
}

//---------------- Reparse Tag
//Names assigned to certain reparse point tags
typedef enum <uint32>
{
	IO_REPARSE_TAG_RESERVED_ZERO=0x00000000,
	IO_REPARSE_TAG_RESERVED_ONE=0x00000001,
	IO_REPARSE_TAG_RESERVED_TWO=0x00000002,
	IO_REPARSE_TAG_MOUNT_POINT=0xA0000003,
	IO_REPARSE_TAG_HSM=0xC0000004,
	IO_REPARSE_TAG_DRIVE_EXTENDER=0x80000005,
	IO_REPARSE_TAG_HSM2=0x80000006,
	IO_REPARSE_TAG_SIS=0x80000007,
	IO_REPARSE_TAG_WIM=0x80000008,
	IO_REPARSE_TAG_CSV=0x80000009,
	IO_REPARSE_TAG_DFS=0x8000000A,
	IO_REPARSE_TAG_FILTER_MANAGER=0x8000000B,
	IO_REPARSE_TAG_SYMLINK=0xA000000C,
	IO_REPARSE_TAG_IIS_CACHE=0xA0000010,
	IO_REPARSE_TAG_DFSR=0x80000012,
	IO_REPARSE_TAG_DEDUP=0x80000013,
	IO_REPARSE_TAG_APPXSTRM=0xC0000014,
	IO_REPARSE_TAG_NFS=0x80000014,
	IO_REPARSE_TAG_FILE_PLACEHOLDER=0x80000015,
	IO_REPARSE_TAG_DFM=0x80000016,
	IO_REPARSE_TAG_WOF=0x80000017,
	IO_REPARSE_TAG_WCI=0x80000018,
	IO_REPARSE_TAG_WCI_1=0x90001018,
	IO_REPARSE_TAG_GLOBAL_REPARSE=0xA0000019,
	IO_REPARSE_TAG_CLOUD=0x9000001A,
	IO_REPARSE_TAG_CLOUD_1=0x9000101A,
	IO_REPARSE_TAG_CLOUD_2=0x9000201A,
	IO_REPARSE_TAG_CLOUD_3=0x9000301A,
	IO_REPARSE_TAG_CLOUD_4=0x9000401A,
	IO_REPARSE_TAG_CLOUD_5=0x9000501A,
	IO_REPARSE_TAG_CLOUD_6=0x9000601A,
	IO_REPARSE_TAG_CLOUD_7=0x9000701A,
	IO_REPARSE_TAG_CLOUD_8=0x9000801A,
	IO_REPARSE_TAG_CLOUD_9=0x9000901A,
	IO_REPARSE_TAG_CLOUD_A=0x9000A01A,
	IO_REPARSE_TAG_CLOUD_B=0x9000B01A,
	IO_REPARSE_TAG_CLOUD_C=0x9000C01A,
	IO_REPARSE_TAG_CLOUD_D=0x9000D01A,
	IO_REPARSE_TAG_CLOUD_E=0x9000E01A,
	IO_REPARSE_TAG_CLOUD_F=0x9000F01A,
	IO_REPARSE_TAG_APPEXECLINK=0x8000001B,
	IO_REPARSE_TAG_PROJFS=0x9000001C,
	IO_REPARSE_TAG_LX_SYMLINK=0xA000001D,
	IO_REPARSE_TAG_STORAGE_SYNC=0x8000001E,
	IO_REPARSE_TAG_WCI_TOMBSTONE=0xA000001F,
	IO_REPARSE_TAG_UNHANDLED=0x80000020,
	IO_REPARSE_TAG_ONEDRIVE=0x80000021,
	IO_REPARSE_TAG_PROJFS_TOMBSTONE=0xA0000022,
	IO_REPARSE_TAG_AF_UNIX=0x80000023,
	IO_REPARSE_TAG_LX_FIFO=0x80000024,
	IO_REPARSE_TAG_LX_CHR=0x80000025,
	IO_REPARSE_TAG_LX_BLK=0x80000026,
	IO_REPARSE_TAG_WCI_LINK=0xA0000027,
	IO_REPARSE_TAG_WCI_LINK_1=0xA0001027
} IO_REPARSE_TAG;

typedef struct _FILE_ATTRIBUTE_REPARSE_POINT
{
    local uint64 dword_start <hidden=true>;
    dword_start = FTell();
    FSeek(dword_start + 3);
    BitfieldDisablePadding();
    BigEndian();
    UBYTE       microsoftOwnedTag: 1;
    UBYTE       microsoftReserved1: 1;
    UBYTE       nameSurrogateBit: 1;
    UBYTE       microsoftReserved2: 1;
    //there are 12 reserved bits that are all 0 for all current tags
    LittleEndian();
    BitfieldEnablePadding();
    FSeek(dword_start);
    USHORT      reparse_tag_value;
    FSeek(dword_start + 4);
} FILE_ATTRIBUTE_REPARSE_POINT;//todo: use flags instead

typedef struct _REPARSE_DATA {
    local uint64 reparse_tag_start <hidden=true>;
    reparse_tag_start = FTell();
    IO_REPARSE_TAG reparse_tag;
    FSeek(reparse_tag_start);
    FILE_ATTRIBUTE_REPARSE_POINT reparseTagAttributes;
    UINT16 reparse_data_length;
    UINT16 reserved;
    if(reparse_tag == IO_REPARSE_TAG_SYMLINK) {
        UINT16 substitute_name_offset;
        UINT16 substitute_name_length;
        UINT16 print_name_offset;
        UINT16 print_name_length;
        UINT32 flags_is_relative;
        wchar_t substitute_name[substitute_name_length/sizeof(wchar_t)];
        wchar_t print_name[print_name_length/sizeof(wchar_t)];
    } else if(reparse_tag == IO_REPARSE_TAG_MOUNT_POINT) {
        UINT16 substitute_name_offset;
        UINT16 substitute_name_length;
        UINT16 print_name_offset;
        UINT16 print_name_length;
        wchar_t substitute_name[substitute_name_length/sizeof(wchar_t)];
        wchar_t print_name[print_name_length/sizeof(wchar_t)];
    } else {
        UBYTE reparse_data[ reparse_data_length ];
    }
} REPARSE_DATA<read=ViewReparseData>;
string ViewReparseData(REPARSE_DATA& val) {
    return "<" + EnumToString(val.reparse_tag) + ">" +
        (val.reparse_tag == IO_REPARSE_TAG_SYMLINK ? " ==>" + val.print_name: "");
}
//-------------------------------- Alternative Data Stream
typedef struct _ADDITIONAL_DATA_HEADER {
    UINT32 unknown_4;
    UINT32 size_data;
    UINT32 offset_from_unknown3;
} ADDITIONAL_DATA_HEADER <read=ViewAdditionalDataHeader>;
string ViewAdditionalDataHeader(ADDITIONAL_DATA_HEADER& val) {return Str("size=0x%x", val.size_data);}

typedef struct _ALTERNATIVE_DATA_STREAM(uint64 len_ads_name) {
    wchar_t ads_name[len_ads_name/sizeof(wchar_t)];
    ADDITIONAL_DATA_HEADER header;
    struct {
        UINT32 length_kvp;
        UINT64 zeroed_1;
        UINT64 len_ads_stream_1;
        UINT64 len_ads_stream_2;
        UINT64 len_ads_stream_3;
        UINT64 zeroed_2;
        UINT32 flag;
    } kvp;
    if(kvp.len_ads_stream_1 > 0) {
        char stream_data[kvp.len_ads_stream_1];
    }
} ALTERNATIVE_DATA_STREAM<read=ViewAlternativeDataStream>;
string ViewAlternativeDataStream(ALTERNATIVE_DATA_STREAM& val) {return "ADS name=" + val.ads_name;}
//-------------------------------- Security Descriptor
// TODO: after 3.7
//-------------------------------- VBR
typedef struct _FILE_SYSTEM_RECOGNITION_STRUCTIURE {
    BYTE jmp[3];
    BYTE fs_name[8] <comment="='ReFS'">;
    BYTE zero[5];
    BYTE identifier[4] <comment="='FSRS'">;
    UINT16 length;
    UINT16 checksum;
} FILE_SYSTEM_RECOGNITION_STRUCTIURE<read=ViewFSRS>;
string ViewFSRS(FILE_SYSTEM_RECOGNITION_STRUCTIURE& val) {return val.fs_name;}

typedef struct _REFS_VBR {
    FILE_SYSTEM_RECOGNITION_STRUCTIURE fsrs;
    UINT64 sectors;
    UINT32 bytes_per_sector;
    UINT32 sectors_per_cluster;
    BYTE maj_ver;
    BYTE min_ver;
    BYTE unknown[14];
    UINT64 serial_number;
    UINT64 container_band_size;//3.4 ver
} REFS_VBR <size=0x200, read=ViewVBR>;
string ViewVBR(REFS_VBR& val) {return Str("%s %i.%i (cls=%i)", val.fsrs.fs_name, val.maj_ver, val.min_ver, val.bytes_per_sector*val.sectors_per_cluster);}
//-------------------------------- Metadata start/end
typedef struct _METADATA_BLOCK_HEADER_V1 {
    UINT64 number;
    UINT64 seq;
    UINT64 padding_1;
    UINT64 node_id;
    UINT64 maybe_flags;
    UINT64 padding_2;
} METADATA_BLOCK_HEADER_V1<read=ViewMetadataBlockHeader>;
string ViewMetadataBlockHeader(METADATA_BLOCK_HEADER_V1& val) {return Str("id=0x%LXh", val.number);}

typedef enum<BYTE> _CHECKSUM_TYPE {
    CRC32  = 0x1,
    CRC64  = 0x2,
} CHECKSUM_TYPE;

typedef struct _METADATA_BLOCK_REFERENCE_V1 {
    UINT64 number;
    BYTE empty[2];
    CHECKSUM_TYPE checksum_type;
    BYTE checksum_data_offset;
    UINT16 checksum_data_size; //TODO: find CRC32
    BYTE empty_2[2];
    UINT64 checksum_data; 
}  METADATA_BLOCK_REFERENCE_V1<read=ViewMetadataBlockReference>;
string ViewMetadataBlockReference(METADATA_BLOCK_REFERENCE_V1& val) {return Str("id=0x%LXh, %s", val.number, EnumToString(val.checksum_type));}

//-------------------------------- Node
typedef struct _UNKNOWN_VALUE(uint32 len)  {
    BYTE unknown[len];
} UNKNOWN_VALUE<read=ViewUnknownValue>;
string ViewUnknownValue(UNKNOWN_VALUE& val) {return Str("len=%i", sizeof(val.unknown));}

#define MIN_SIZE_NODE_DESC (36)
typedef struct _NODE_DESCRIPTOR_V1 {// Index Root
    local uint64 pos = FTell();
    
    UINT32 length;
    if (length >= MIN_SIZE_NODE_DESC) {
        //BYTE unknown_1[0x14];
        UINT16 size_fixed_component_index_root; //=0x28
        UINT16 unknown_1_1;
        UINT16 ckecksum_related_1;
        UINT16 unused_1;
        UINT16 scheme_table;//attribute_list
        UINT16 unused_2;
        UINT16 scheme_table_2;//attribute_list
        UINT16 unused_3;
        UINT16 ckecksum_related_2;
        UINT16 ckecksum_related_2;
        UINT16 num_extents;
        BYTE unknown_2[0x6];
        UINT32 num_records;
    } else if (length > 0) {
        byte unknown[length];
    }

    FSkip(length - (FTell() - pos));
} NODE_DESCRIPTOR_V1<read=ViewNodeDescriptorV1>;
string ViewNodeDescriptorV1(NODE_DESCRIPTOR_V1& val) {return val.length < MIN_SIZE_NODE_DESC ? "<empty>" : Str("count=%i, scheme: 0x%Xh", val.num_records, val.scheme_table_2);}

typedef enum <BYTE> _NODE_TYPE {
    NT_Leaf   = 0x0,
    NT_Branch  = 0x1,
    NT_Root    = 0x2,
    NT_RootBranch = 0x3,
} NODE_TYPE;

typedef struct _NODE_HEADER_V1 {// Index Header
    local uint64 pos = FTell();

    UINT32 length;//or start_data_area
    UINT32 offset_next_free_record;// or end_data_area
    UINT32 free_space;
    //UINT32 unknown;
    BYTE node_level;//0 = leaf
    NODE_TYPE node_type;// & 0x01 branch, 0x2 = root
    UINT16 unused;
    UINT32 offset_to_first_pointer;
    UINT32 num_pointers;
    UINT64 offset_to_end;
    
    FSkip(length - (FTell() - pos));
} NODE_HEADER_V1<read=ViewNodeHeaderV1>;
string ViewNodeHeaderV1(NODE_HEADER_V1& val) {return Str("type: %s, level: %i, childs: %i", EnumToString(val.node_type), val.node_level, val.num_pointers);}

typedef struct _NODE_INDEX_ENTRY_V1 {// Index Header
    local uint64 pos = FTell();

    UINT32 length;//or start_data_area
    UINT16 offset_start_key;// or end_data_area
    UINT16 length_key;
    UINT16 flags;/// 0x2 = rightmost, 0x4=deleted, 0x40 stream index, 0x8 embedded tree
    UINT16 offset_start_value;
    UINT16 length_value;
    
    if (length_key > 0) {
        FSeek(pos + offset_start_key);
        BYTE key[length_key];
    }
    if (length_value > 0) {
        FSeek(pos + offset_start_value);
        METADATA_BLOCK_REFERENCE_V1 block_ref;
    }
    FSkip(length - (FTell() - pos));
} NODE_INDEX_ENTRY_V1<read=ViewNodeIndexV1>;
string ViewNodeIndexV1(NODE_INDEX_ENTRY_V1& val) {return Str("page_child: 0x%Xh", val.block_ref.number);}

//------------- Base attribute
typedef struct _MAIN_BASE_ATTRIBUTE_HEADER_V1 {
    UINT32 attribute_size;
    UINT16 offset_to_next_part_header;
    UINT16 used_size_from_next_part;
    UINT16 flags;//comment: 0x4 = deleted
    UINT16 size_attribute_header;
    UINT32 size_attribute_value;
 } MAIN_BASE_ATTRIBUTE_HEADER_V1<read=ViewMainBaseAttributeHeaderV1>;
string ViewMainBaseAttributeHeaderV1(MAIN_BASE_ATTRIBUTE_HEADER_V1& val) {return Str("value_size: 0x%x", val.size_attribute_value);}
 
//------------- attribute with type
typedef enum<UINT16> _RECORD_TYPE {
    Base  = 0x10,
    Name  = 0x20,
    Entry = 0x30,
    Data  = 0x80,
} RECORD_TYPE;

typedef enum<UINT16> _ENTRY_TYPE {
    Metadata  = 0x10,
    File      = 0x1,
    Dir       = 0x2,
} ENTRY_TYPE;

typedef struct _ATTRIBUTE_WITH_TYPE_HEADER_V1 {
    MAIN_BASE_ATTRIBUTE_HEADER_V1 base;

    RECORD_TYPE attribute_type;
    ENTRY_TYPE entry_type;
 } ATTRIBUTE_WITH_TYPE_HEADER_V1<read=ViewBaseAttributeHeader>;
 string ViewBaseAttributeHeader(ATTRIBUTE_WITH_TYPE_HEADER_V1& v) {return EnumToString(v.attribute_type);}

//-------------- volume object
typedef struct _VOLUME_OBJECT_ATTRIBUTE_HEADER_V1 {
    local uint64 pos = FTell();
 
    ATTRIBUTE_WITH_TYPE_HEADER_V1 header;
    
    FSkip(header.base.size_attribute_header - (FTell() - pos));
} VOLUME_OBJECT_ATTRIBUTE_HEADER_V1<read=ViewVolumeObjectAttributeHeaderV1>;
string ViewVolumeObjectAttributeHeaderV1(VOLUME_OBJECT_ATTRIBUTE_HEADER_V1& val) {return Str("type: 0x%Xh", val.header.attribute_type);}

typedef struct _VOLUME_OBJECT_ATTRIBUTE_VALUE_V1 {
    BYTE unknown_1[0x80];
    BYTE majour_ver;
    BYTE minor_ver;
    BYTE majour_ver;
    BYTE minor_ver;
    BYTE unknown_2[0xC];
    FILETIME date_volume_created;
    UINT64 padding_3;
    FILETIME date_volume_last_mounted;
    UINT64 padding_4;   
} VOLUME_OBJECT_ATTRIBUTE_VALUE_V1<read=ViewVolumeAttributeValue>;
string ViewVolumeAttributeValue(VOLUME_OBJECT_ATTRIBUTE_VALUE_V1& val) {return FileTimeToString(val.date_volume_created);}
 
//------------------------
typedef struct _SIA_ATTRIBUTE_NODE_DESCRIPTOR_V1 {
    local uint64 pos = FTell();
    
    UINT32 length;
    UINT16 offset_to_first_timestamp;
    BYTE unknown_1[0x22];
    FILETIME created;
    FILETIME modified;
    FILETIME metadata_modified;
    FILETIME last_access;
    UINT64 attrib_flags;
    UINT64 parent_node_id;
    UINT64 child_id;
    UINT64 unknown_2;
    UINT64 logical_size;
    UINT64 physical_size;
    UINT64 unknown_3;
    FILETIME extra_timestamp;// FNA

    FSkip(length - (FTell() - pos));
} SIA_ATTRIBUTE_NODE_DESCRIPTOR_V1<read=ViewSiaAttributeV1>;
string ViewSiaAttributeV1(SIA_ATTRIBUTE_NODE_DESCRIPTOR_V1& val) {return Str("Created: %s", FileTimeToString(val.created));}


typedef struct _EXT_CHILD_ATTRIBUTE_HEADER_V1 {
    UINT32 unknown_2;
    UINT64 parent_node_id;
    UINT64 child_number;
} EXT_CHILD_ATTRIBUTE_HEADER_V1<read=ViewChildAttributeV1>;
string ViewChildAttributeV1(EXT_CHILD_ATTRIBUTE_HEADER_V1& val) {return Str("parent: 0x%Xh, child_id: 0x%Xh ", val.parent_node_id, val.child_number);}

typedef struct _CHILD_ATTRIBUTE_VALUE_V1 {
    UINT64 unknown_1;
    UINT16 offset_to_filename;
    UINT16 size_of_filename;
    if(size_of_filename > 0) {
        wchar_t filename[size_of_filename/sizeof(wchar_t)];
    } else {
        Printf("Warning! empty filename. Deleted?\n");
    }
} CHILD_ATTRIBUTE_VALUE_V1<read=ViewChildAttributeValue>;
string ViewChildAttributeValue(CHILD_ATTRIBUTE_VALUE_V1& val) {return val.size_of_filename > 0 ? val.filename : Str("<empty> Deleted? %i", val.unknown_1);}

typedef struct _EXT_FILENAME_ATTRIBUTE_HEADER_V1(uint32 attribute_header_size) {
    wchar_t filename[(attribute_header_size - sizeof(ATTRIBUTE_WITH_TYPE_HEADER_V1))/sizeof(wchar_t)]; 
} EXT_FILENAME_ATTRIBUTE_HEADER_V1<read=ViewFileName>;
string ViewFileName(EXT_FILENAME_ATTRIBUTE_HEADER_V1& f) {return f.filename;}

typedef struct _DIRECTORY_ATTRIBUTE_VALUE_V1 {
    UINT64 node_id;
    UINT64 unknown_1;
    FILETIME created;
    FILETIME modified;
    FILETIME metadata_modified;
    FILETIME last_access;
    BYTE unknown_2[0x10];
    UINT32 unknown_3;
    IO_REPARSE_TAG reparse_tag;

} DIRECTORY_ATTRIBUTE_VALUE_V1<read=ViewDirectoryAttributeValue>;
string ViewDirectoryAttributeValue(DIRECTORY_ATTRIBUTE_VALUE_V1& val) {return Uint64ToHexStr(val.node_id) + (val.reparse_tag == 0 ? "" : (" <"+ EnumToString(val.reparse_tag) + ">"));}

//------------------------
typedef struct _DATA_RUN_ATTRIBUTE_V1 {
    MAIN_BASE_ATTRIBUTE_HEADER_V1 base;
    
    UINT64 entry_block_pos;
    UINT64 number_entry_blocks;
    UINT64 entry_block_start;
    UINT64 unknown_2;
} DATA_RUN_ATTRIBUTE_V1 <read=ViewDataRunAttribute>;
string ViewDataRunAttribute(DATA_RUN_ATTRIBUTE_V1& val) {return Str("start page: 0x%LXh", val.entry_block_start);}
                    
typedef struct _CONTENTS_FILE_V1(uint64 count_blocks, uint64 block_index_size) {
    BYTE contents_file[count_blocks * block_index_size]; 
} CONTENTS_FILE_V1 <read=ViewContentsFile>;
string ViewContentsFile(CONTENTS_FILE_V1& val) {return Str("Size_part: %Lu", sizeof(val.contents_file));}

typedef struct _DATA_RUN_CONTENTS_V1(uint64 page_size) {
    DATA_RUN_ATTRIBUTE_V1 data_run;
          
    local uint64 pos = FTell();      
    FSeek(data_run.entry_block_start * page_size + data_run.entry_block_pos);
    CONTENTS_FILE_V1 contents_file(data_run.number_entry_blocks, page_size);
    FSeek(pos);
} DATA_RUN_CONTENTS_V1 <read=ViewDataRunContentsV1>;
string ViewDataRunContentsV1(DATA_RUN_CONTENTS_V1& val) {return ViewDataRunAttribute(val.data_run);}

typedef enum<UINT32> _ATTRIBUTE_TYPE {
    AT_DATA     = 0x80,
    AT_REPARSE  = 0xC0,
    AT_ADS      = 0xB0,
} ATTRIBUTE_TYPE;

typedef struct _DATA_RUN_ATTRIBUTE_VALUE_V1(uint64 page_size) {
    local uint64 pos_m = FTell();
    
    MAIN_BASE_ATTRIBUTE_HEADER_V1 base;
    
    UINT32 size_attribute_value2;
    UINT32 unknown_2;
    ATTRIBUTE_TYPE attribute_type;
    if(attribute_type == AT_DATA) {
        UINT32 unknown_3;
        
        NODE_DESCRIPTOR_V1 data_node_descriptor;
        NODE_HEADER_V1 node_header;
        
        local uint64 pos = FTell();
        FSeek(pos - sizeof(node_header) + node_header.offset_to_first_pointer);
        if(node_header.num_pointers > 0) {
            UINT32 records_offset[node_header.num_pointers];
            
            local uint32 i = 0;
            for(i = 0; i < node_header.num_pointers; ++i) {
                FSeek(pos - sizeof(node_header) + records_offset[i]);
                if (node_header.node_type & NT_Branch) {
                    NODE_INDEX_ENTRY_V1 index_entry_data_run;
                    FSeek(index_entry_data_run.block_ref.number * page_size);
                    struct _MSB_TREE_BLOCK_REF_V1 inner_data_run(page_size, SI_DUMMY_DATA_RUN_VALUE);
                } else {
                    DATA_RUN_CONTENTS_V1 data_run_with_data(page_size);
                }
            }
        }
    } else if (attribute_type == AT_REPARSE) {
        UINT32 unknown_3;
        ADDITIONAL_DATA_HEADER header;
        REPARSE_DATA reparse_data;
    } else if (attribute_type == AT_ADS) {
        ALTERNATIVE_DATA_STREAM alternative_data_stream(base.size_attribute_header - (FTell() - pos_m));
    } else {
        Printf("Attrbute_type %s (0x%X) does not support yet\n", EnumToString(attribute_type), attribute_type);
    }

    FSkip(base.attribute_size - (FTell() - pos_m));
} DATA_RUN_ATTRIBUTE_VALUE_V1 <read=ViewDataRunHeaderV1>;
string ViewDataRunHeaderV1(DATA_RUN_ATTRIBUTE_VALUE_V1& val) {
    if(val.attribute_type == AT_DATA) {return Str("data_runs: %Lu", sizeof(val.node_header.num_pointers));}
    if(val.attribute_type == AT_REPARSE) {return ViewReparseData(val.reparse_data);}
    if(val.attribute_type == AT_ADS) {return ViewAlternativeDataStream(val.alternative_data_stream);}
    return EnumToString(val.attribute_type);
}

//----------------- Root
typedef struct _FILE_RECORD_V1(uint64 page_size) {
    SIA_ATTRIBUTE_NODE_DESCRIPTOR_V1 sia;
    
    if (sia.offset_to_first_timestamp != 0) 
    {
       local uint64 pos = FTell();
       NODE_HEADER_V1 node_header;
  
       FSeek(pos + node_header.offset_to_first_pointer);
       if(node_header.num_pointers > 0) {
            UINT32 records_offset[node_header.num_pointers];
        
            local uint32 i = 0;
            for(i = 0; i < node_header.num_pointers; ++i) {
                FSeek(pos + records_offset[i]);
                if (node_header.node_type & NT_Branch) {
                    NODE_INDEX_ENTRY_V1 index_entry_file_record;
                    FSeek(index_entry_file_record.block_ref.number * page_size);
                    struct _MSB_TREE_BLOCK_REF_V1 inner_node(page_size, SI_DUMMY_DATA_RUN);
                } else {
                    DATA_RUN_ATTRIBUTE_VALUE_V1 node_data(page_size);
                }
            }
        }
               
        FSeek(pos);
    }
} FILE_RECORD_V1<read=ViewDataRunsV1>;
string ViewDataRunsV1(FILE_RECORD_V1& val) {return Str("data_runs: %Lu", sizeof(val.node_header.num_pointers));}

typedef struct _FILE_ENTRY_RECORD_V1(uint64 page_size) {
    ATTRIBUTE_WITH_TYPE_HEADER_V1 attribute_header;

    if (attribute_header.attribute_type == Entry) {
        if (attribute_header.entry_type == Dir) {
            EXT_FILENAME_ATTRIBUTE_HEADER_V1 directory_name(attribute_header.base.size_attribute_header);
            DIRECTORY_ATTRIBUTE_VALUE_V1 dir_value;
        }
        if (attribute_header.entry_type == File) {
           EXT_FILENAME_ATTRIBUTE_HEADER_V1 file_name(attribute_header.base.size_attribute_header);
           FILE_RECORD_V1 file_value(page_size);
        }
    } else if (attribute_header.attribute_type == Name) {
       EXT_CHILD_ATTRIBUTE_HEADER_V1 child_header;// Name record
       CHILD_ATTRIBUTE_VALUE_V1 child_value;
    } else if (attribute_header.attribute_type == Base) {
        FSkip(attribute_header.base.size_attribute_header - sizeof(attribute_header));
        SIA_ATTRIBUTE_NODE_DESCRIPTOR_V1 self_standart_info;
        BYTE unknown_attribute_value[attribute_header.base.attribute_size - sizeof(attribute_header) - sizeof(self_standart_info)];
     } else {
        if (attribute_header.base.size_attribute_header > sizeof(attribute_header)) {
            BYTE unknown_attribute_header[attribute_header.base.size_attribute_header - sizeof(attribute_header)];
        } else { ///NOTE some atributes header without attribute_type
            FSeek(FTell() - (sizeof(attribute_header) - attribute_header.base.size_attribute_header));
        }
        BYTE unknown_attribute_value[attribute_header.base.size_attribute_value];
     }
} FILE_ENTRY_RECORD_V1<read=ViewFileEntryV1>;
string ViewFileEntryV1(FILE_ENTRY_RECORD_V1& val) {return EnumToString(val.attribute_header.attribute_type);}
 
typedef enum<UINT32> _NODE_ID
{
    VolumeObject = 0x500,
    FileSystem   = 0x520,
    Root         = 0x600,
    Directory    = 0x700,
} NODE_ID;

typedef struct _OBJECT_RECORD_V1 {
    local uint64 pos = FTell();

    UINT32 length;
    BYTE unknown_1[0x6];
    UINT16 record_header_size;
    UINT16 record_value_size;
    UINT16 unknown_2;
    UINT64 unknown_3;
    NODE_ID node_id;
    UINT32 unknown_4;
    METADATA_BLOCK_REFERENCE_V1 metadata_block_ref;

    FSkip(length - (FTell() - pos));
} OBJECT_RECORD_V1<read=ViewObjectRecord1>;
string ViewObjectRecord1(OBJECT_RECORD_V1& val) {return Str("node_id: 0x%Xh, page: 0x%Xh", val.node_id, val.metadata_block_ref.number);}

//----------------------- Bitmap
typedef struct _BITMAP_ATTRIBUTE_V1 {
    UINT64 entry_block_start;
    UINT64 number_entry_blocks;
    UINT32 size_record_value_2;
    UINT32 total_number;
    UINT32 unknown_3;//0x2
    UINT32 free_blocks;
    UINT32 bit_offset_next_free_blocks;
    UINT32 num_free_blocks_after_first_free;
    UINT64 unknown_4;
    UINT32 offset_to_bitmap_start;/// from value
    UINT32 count_bytes;
    BYTE data[count_bytes];
} BITMAP_ATTRIBUTE_V1<read=ViewBitmapAttributeV1>;
string ViewBitmapAttributeV1(BITMAP_ATTRIBUTE_V1& val) {return Str("Bytes: %i", sizeof(val.count_bytes));}

//---------------------- SchemeTable(AttributeList)
typedef struct _SCHEME_TABLE_VALUE_V1(uint32 len) {
    UNKNOWN_VALUE unknown(len);//TODO: parse it
} SCHEME_TABLE_VALUE_V1<read=ViewSchemeTableV1>;
string ViewSchemeTableV1(SCHEME_TABLE_VALUE_V1& val) {return Str("Unknown len:%i", sizeof(val.unknown));}

//----------------------- Child Parent
typedef struct _CHILD_PARENT_ATTRIBUTE_VALUE_V1  {
    UINT64 unknown_1;
    UINT64 parent_id;
    UINT64 unknown_2;
    UINT64 child_id;
} CHILD_PARENT_ATTRIBUTE_VALUE_V1<read=ViewChildParentAttributeValue>;
string ViewChildParentAttributeValue(CHILD_PARENT_ATTRIBUTE_VALUE_V1& val) {return Uint64ToHexStr(val.child_id) + "-->" + Uint64ToHexStr(val.parent_id);}

//-------------------------------- MSBTree
// TODO: check schema_id
typedef enum<UINT32> _SCHEME_ID_V1 {
    SI_PATH_OBJECT   = 0x0130,
    SI_VOLUME_OBJECT = 0x0150,
    SI_OBJECT        = 0xE030,
    SI_BITMAP        = 0xE010,
    SI_SCHEME_TABLE  = 0xE060,
    SI_CHILD_PARENT  = 0xE040,
    
    ///NOTE: value does not really, but for reuse MSB+ tree
    SI_DUMMY_DATA_RUN        = 0xE0C1,
    SI_DUMMY_DATA_RUN_VALUE  = 0xE0C2,
    // ver 3.7
    SI_CONTAINER     = 0xE0C0,
    // ver 3.14
    SI_PATH_OBJECT_EXT = 0xE130,
} SCHEME_ID_V1;

void parseNode(uint16 scheme_table, uint64 page_size);
typedef struct _MSB_TREE_BLOCK_REF_V1(uint64 page_size, uint16 scheme_table) {
    local uint64 pos = 0;
    struct _MSB_TREE_BLOCK_REF_NODE
    {
        METADATA_BLOCK_HEADER_V1 header;
        NODE_DESCRIPTOR_V1 node_descriptor;
        
        pos = FTell();
        NODE_HEADER_V1 node_header;
        
        FSeek(pos + node_header.offset_to_first_pointer);
        UINT32 records_offset[node_header.num_pointers];
    } node;
    
    local uint16 child_scheme_table = scheme_table == 0 && node.node_descriptor.length > 0 ? node.node_descriptor.scheme_table : scheme_table;
    local uint32 i = 0;
    for(i = 0; i < node.node_header.num_pointers; ++i) {
        FSeek(pos + node.records_offset[i]);
        if (node.node_header.node_type & NT_Branch) {
            NODE_INDEX_ENTRY_V1 index_entry;
            FSeek(index_entry.block_ref.number * page_size);
            struct _MSB_TREE_BLOCK_REF_V1 inner_node(page_size, child_scheme_table);
        } else {
            parseNode(child_scheme_table, page_size);
        }
    }
    FSeek(pos);
} MSB_TREE_BLOCK_REF_V1<read=ViewMsbTreeBlockRefV1>;
string ViewMsbTreeBlockRefV1(MSB_TREE_BLOCK_REF_V1& val) {return Str("records: %i", val.node.node_descriptor.num_records);}

void parseVolumeObject()
{
   VOLUME_OBJECT_ATTRIBUTE_HEADER_V1 attribute_header;
   switch (attribute_header.header.attribute_type)
   {
      case 0x510: wchar_t volume_label[attribute_header.header.base.size_attribute_value/sizeof(wchar_t)]; break;
      case 0x520: VOLUME_OBJECT_ATTRIBUTE_VALUE_V1 general_volume_info; break;
      default:
           if(attribute_header.header.base.size_attribute_value > 0) {
                UNKNOWN_VALUE unknown_attribute_value(attribute_header.header.base.size_attribute_value);
           }
           break;
   }
}

void parseObject(uint64 page_size)
{
    OBJECT_RECORD_V1 object_ref;
    
    FSeek(object_ref.metadata_block_ref.number * page_size);
    switch (object_ref.node_id) {
        case VolumeObject:
            MSB_TREE_BLOCK_REF_V1 volume_object_record(page_size, 0);
            break;
        case Root:
            MSB_TREE_BLOCK_REF_V1 root(page_size, 0)<open=true>;
            break;
        default:
            if(object_ref.node_id > Root) {
                MSB_TREE_BLOCK_REF_V1 folder(page_size, 0);
            } else {
                MSB_TREE_BLOCK_REF_V1 unknown_object(page_size, 0);
            }
            break;
    }
}
    
void parseNode(uint16 scheme_table, uint64 page_size)
{
    switch(scheme_table) {
    case SI_PATH_OBJECT:
        FILE_ENTRY_RECORD_V1 file_entry(page_size);
        break;
    case SI_VOLUME_OBJECT:
        parseVolumeObject();
        break;
    case SI_OBJECT:
        parseObject(page_size);
        break;
    case SI_BITMAP:
        MAIN_BASE_ATTRIBUTE_HEADER_V1 attribute_header;
        BITMAP_ATTRIBUTE_V1 bm;
        break;
    case SI_SCHEME_TABLE:
        MAIN_BASE_ATTRIBUTE_HEADER_V1 attribute_header;
        SCHEME_TABLE_VALUE_V1 attribute_value(attribute_header.size_attribute_value); 
        break;
    case SI_CHILD_PARENT:
        MAIN_BASE_ATTRIBUTE_HEADER_V1 attribute_header;
        CHILD_PARENT_ATTRIBUTE_VALUE_V1 attribute_value;
        break;
    case SI_DUMMY_DATA_RUN:
        DATA_RUN_ATTRIBUTE_VALUE_V1 file_data(page_size);
        break;
    case SI_DUMMY_DATA_RUN_VALUE:
        DATA_RUN_CONTENTS_V1 data(page_size);
        break;
    default:
        MAIN_BASE_ATTRIBUTE_HEADER_V1 attribute_header;
        if(attribute_header.size_attribute_value > 0) {
            UNKNOWN_VALUE attribute_value(attribute_header.size_attribute_value);
        }  
    }
}
//-------------------------------- TreeControl
typedef struct _TREE_CONTROL_CHECKPOINT_V1 {
    uint32 unknown_1;
    uint16 major_version;
    uint16 minor_version;
    uint32 size_of_checkpoint;
    uint32 size_of_record;
    byte unknown_2[16];
    byte unknown_3[8];
    uint32 count_control_objects;
    uint32 offsets_control_object[count_control_objects];
} TREE_CONTROL_CHECKPOINT_V1<read=ViewTreeControlCheckpointV1>;
string ViewTreeControlCheckpointV1(TREE_CONTROL_CHECKPOINT_V1& val) {return Str("control_objects: %i", val.count_control_objects);}

typedef enum <BYTE> _CONTROL_OBJECT_TYPE {
    CT_OBJECT_TREE        = 0x0,
    CT_ALLOC_LARGE_TREE   = 0x1,
    CT_ALLOC_MEDIUM_TREE  = 0x2,
    CT_ALLOC_SMALL_TREE   = 0x3,
    CT_SCHEMA_TREE        = 0x4,
    CT_CHILD_PARENT_TREE  = 0x5,
} CONTROL_OBJECT_TYPE;

typedef struct _TREE_CONTROL_V1 {
    local uint64 pos = FTell();
    
    METADATA_BLOCK_HEADER_V1 treecontrol_header;
    TREE_CONTROL_CHECKPOINT_V1 tree_control;
    
    FSeek(pos + tree_control.size_of_checkpoint);
    METADATA_BLOCK_REFERENCE_V1 self_metadata_reference;
    
    Assert(tree_control.count_control_objects >= 6);
  
    FSeek(pos + tree_control.offsets_control_object[CT_OBJECT_TREE]);
    METADATA_BLOCK_REFERENCE_V1 objects_tree;
    
    FSeek(pos + tree_control.offsets_control_object[CT_ALLOC_LARGE_TREE]);
    METADATA_BLOCK_REFERENCE_V1 alloc_large_tree;
    
    FSeek(pos + tree_control.offsets_control_object[CT_ALLOC_MEDIUM_TREE]);
    METADATA_BLOCK_REFERENCE_V1 alloc_medium_tree;
    
    FSeek(pos + tree_control.offsets_control_object[CT_ALLOC_SMALL_TREE]);
    METADATA_BLOCK_REFERENCE_V1 alloc_small_tree;
    
    FSeek(pos + tree_control.offsets_control_object[CT_SCHEMA_TREE]);
    METADATA_BLOCK_REFERENCE_V1 attribute_list_tree;
    
    FSeek(pos + tree_control.offsets_control_object[CT_CHILD_PARENT_TREE]);
    METADATA_BLOCK_REFERENCE_V1 child_parent_tree;
} TREE_CONTROL_V1<read=ViewTreeControlV1>;
string ViewTreeControlV1(TREE_CONTROL_V1& val) {return Str("control_objects: %i", val.tree_control.count_control_objects);}

typedef struct _TREE_CONTROL_PARSE_V1(uint64 page_size) {
    TREE_CONTROL_V1 tree_control_data;
    
    local uint64 pos = FTell();
    
    FSeek(tree_control_data.objects_tree.number * page_size);
    MSB_TREE_BLOCK_REF_V1 object_tree(page_size, 0) <open=true>; 
    
    FSeek(tree_control_data.alloc_large_tree.number * page_size);
    MSB_TREE_BLOCK_REF_V1 bitmap_large(page_size, 0); 
    
    FSeek(tree_control_data.alloc_medium_tree.number * page_size);
    MSB_TREE_BLOCK_REF_V1 bitmap_medium(page_size, 0);
    
    FSeek(tree_control_data.alloc_small_tree.number * page_size);
    MSB_TREE_BLOCK_REF_V1 bitmap_small(page_size, 0);   

    FSeek(tree_control_data.attribute_list_tree.number * page_size);
    MSB_TREE_BLOCK_REF_V1 scheme_table(page_size, 0);
    
    FSeek(tree_control_data.child_parent_tree.number * page_size);
    MSB_TREE_BLOCK_REF_V1 child_parent(page_size, 0);
    
    FSeek(pos);
} TREE_CONTROL_PARSE_V1<open=true, read=ViewTreeControlParseV1>;
string ViewTreeControlParseV1(TREE_CONTROL_PARSE_V1& val) {return Str("control_objects: %i", val.tree_control_data.tree_control.count_control_objects);}
//-------------------------------- Superblock
typedef struct _REFS_SUPERBLOCK_DATA {
    GUID id;
    BYTE unknown[16];
    UINT32 offset_to_first_checkpoint_number;
    UINT32 count_checkpoints;
    UINT32 offset_to_first_record;
    UINT32 length_of_record;
} REFS_SUPERBLOCK_DATA<read=ViewReFsSuperBlockData>;
string ViewReFsSuperBlockData(REFS_SUPERBLOCK_DATA& val) {return Str("checkpoints: %i", val.count_checkpoints);}

typedef struct _REFS_SUPERBLOCK_V1 {
    local uint64 pos = FTell();
    
    METADATA_BLOCK_HEADER_V1 header_meta;
    REFS_SUPERBLOCK_DATA spb;
    
    FSeek(pos + spb.offset_to_first_checkpoint_number);
    UINT64 checkpoints[spb.count_checkpoints];
    
    METADATA_BLOCK_REFERENCE_V1 self_metadata_reference;
} REFS_SUPERBLOCK_V1<read=ViewReFsSuperBlock>;
string ViewReFsSuperBlock(REFS_SUPERBLOCK_V1& val) {return Str("checkpoints: %i", val.spb.count_checkpoints);}

typedef struct _REFS_SUPERBLOCK_PARSE_V1(uint64 page_size) {
    REFS_SUPERBLOCK_V1 superblock_data;
    
    ///NOTE:checkpoints[1] for backup TreeControlBlock
    FSeek(superblock_data.checkpoints[0] * page_size);
    TREE_CONTROL_PARSE_V1 tree_control(page_size);
} REFS_SUPERBLOCK_PARSE_V1<open=true, read=ViewReFsSuperBlockParse>;
string ViewReFsSuperBlockParse(REFS_SUPERBLOCK_PARSE_V1& val) {return Str("checkpoints: %i", val.superblock_data.spb.count_checkpoints);}
//------------------------
//                     ReFS 3.7
//------------------------
//-------------------------------- Addres Translator
typedef struct _AddressTranslator(uint64 size) {
    uint64 band_size;
    uint64 page_size;
    uint64 table[size];
} AddressTranslator;

uint64 translateAddress(AddressTranslator& translator, uint64 addr) {
    if(translator.band_size == 0) {
        return addr;
    }
    local uint64 entry_index = ((addr / translator.band_size) >>1);
    if(entry_index < 2 || entry_index -2 > 63) {
        Printf("Unexpected entry_index 0x%x for add 0x%x\n", entry_index, addr);
        return addr;
    }
    local uint64 res = translator.table[entry_index -2] + (addr % translator.band_size);
    // Printf("0x%LX --> 0x%LX (%Lu 0x%LX)\n", addr, res, entry_index, translator.table[((addr / translator.band_size) >>1) -2]);
    return res;
}

//-------------------------------- Metadata start/end
typedef struct _METADATA_BLOCK_HEADER_V3 {
    BYTE signature[4] <comment="SUPB|CHKP|MSB+">;
    UINT32 unknown_1  <comment="=0x2">;
    UINT32 empty_1;
    UINT32 volume_signature;
    UINT64 virtual_alloc_clock;
    UINT64 tree_update_clock;
    UINT64 first_block_number;
    UINT64 second_block_number;
    UINT64 third_block_number;    
    UINT64 fourth_block_number;
    UINT64 table_id_high;
    UINT64 table_id_low;
} METADATA_BLOCK_HEADER_V3<read=ViewMetadataBlockHeaderV3>;
string ViewMetadataBlockHeaderV3(METADATA_BLOCK_HEADER_V3& val) {return Str("id=0x%LXh", val.first_block_number);}

typedef struct _METADATA_BLOCK_REFERENCE_V3 {
    UINT64 first_block_number;
    UINT64 second_block_number;
    UINT64 third_block_number;    
    UINT64 fourth_block_number;
    
    BYTE empty[2];
    CHECKSUM_TYPE checksum_type;
    BYTE checksum_data_offset;
    UINT16 checksum_data_size; //TODO: find CRC32
    BYTE empty_2[2];
    UINT64 checksum_data; 
}  METADATA_BLOCK_REFERENCE_V3<read=ViewMetadataBlockReferenceV3>;
string ViewMetadataBlockReferenceV3(METADATA_BLOCK_REFERENCE_V3& val) {return Str("id=0x%LXh, %s", val.first_block_number, EnumToString(val.checksum_type));}

void jumpToBlock(AddressTranslator& translator, METADATA_BLOCK_REFERENCE_V3& block) {
    FSeek(translateAddress(translator, block.first_block_number * translator.page_size));///TODO: on 4K
}
//-------------------------------- MSB+
typedef struct _NODE_INDEX_ENTRY_V3 {// Index Header
    local uint64 pos = FTell();

    UINT32 length;//or start_data_area
    UINT16 offset_start_key;// or end_data_area
    UINT16 length_key;
    UINT16 flags;/// 0x2 = rightmost, 0x4=deleted, 0x40 stream index, 0x8 embedded tree
    UINT16 offset_start_value;
    UINT16 length_value;
    
    if (length_key > 0) {
        FSeek(pos + offset_start_key);
        BYTE key[length_key];
    }
    if (length_value > 0) {
        FSeek(pos + offset_start_value);
        METADATA_BLOCK_REFERENCE_V3 block_ref;
    } 
    FSkip(length - (FTell() - pos));
} NODE_INDEX_ENTRY_V3<read=ViewNodeIndexV3>;
string ViewNodeIndexV3(NODE_INDEX_ENTRY_V3& val) {return val.length_value > 0 ? Str("page_child: 0x%Xh", val.block_ref.first_block_number) : "<empty_val>";}


void parseNodeV3(UINT16 scheme_table, AddressTranslator& translator);
typedef struct _MSB_TREE_BLOCK_REF_V3(AddressTranslator& translator, UINT16 scheme_table) {
    local uint64 pos = 0;
    struct _MSB_TREE_BLOCK_REF_NODE_V3
    {
        METADATA_BLOCK_HEADER_V3 header;
        NODE_DESCRIPTOR_V1 node_descriptor;
        
        pos = FTell();
        NODE_HEADER_V1 node_header;
        
        if(node_header.num_pointers > 0) {
            FSeek(pos + node_header.offset_to_first_pointer);
            UINT32 records_offset[node_header.num_pointers];
        }
    } node;
    
    local uint16 child_scheme_table = scheme_table == 0 && node.node_descriptor.length > 0 ? node.node_descriptor.scheme_table : scheme_table;
    local uint32 i = 0;
    for(i = 0; i < node.node_header.num_pointers; ++i) {
        FSeek(pos + (node.records_offset[i] & 0xffff));
        if (node.node_header.node_type & NT_Branch) {
            NODE_INDEX_ENTRY_V3 index_entry;
            jumpToBlock(translator, index_entry.block_ref);
            struct _MSB_TREE_BLOCK_REF_V3 inner_node(translator, child_scheme_table);
        } else {
            parseNodeV3(child_scheme_table, translator);
        }
    }
    FSeek(pos);
} MSB_TREE_BLOCK_REF_V3<read=ViewMsbTreeBlockRefV3>;
string ViewMsbTreeBlockRefV3(MSB_TREE_BLOCK_REF_V3& val) {return Str("records: %i", val.node.node_descriptor.num_records);}
//-------------------------------- Bitmap V3
typedef struct _BITMAP_ATTRIBUTE_V3 {
    UINT64 first_clusters;
    UINT64 count_of_clusters;
    UINT16 free_clusters;
    UINT16 flags <comment="0x2 - Sparse">;
    UINT16 unknown_1;
    UINT16 bitmap_flags;
    BYTE data[(count_of_clusters + 7)/8];
} BITMAP_ATTRIBUTE_V3<read=ViewBitmapAttributeV3>;
string ViewBitmapAttributeV3(BITMAP_ATTRIBUTE_V3& val) {return Str("Bytes: %i", sizeof(val.data));}

//-------------------------------- Container
typedef struct _CONTAINER_VALUE_V3(uint32 size_value) {
    local uint64 pos = FTell();
    UINT64 band_id;
    UINT32 unknown_1;
    UINT32 unknown_2;
    UINT32 flags;
    UINT32 unknown_3;
    UINT64 unknown_4;
    UINT64 number_unused_clusters;
    UINT64 unknown_5;
    BYTE empty_1[28];
    UINT32 unknown_6;
    BYTE empty[64];
    
    FSeek(pos + size_value - 2*sizeof(UINT64));
    UINT64 cluster_block_number;
    UINT64 cluster_size;// count_of_blocks
} CONTAINER_VALUE_V3<read=ViewContainerV3>;
string ViewContainerV3(CONTAINER_VALUE_V3& val) {return Str("id: 0x%LXh base:0x%LXh", val.band_id, val.cluster_block_number);}

//-------------------------------- File Entry
typedef struct _SIA_ATTRIBUTE_NODE_DESCRIPTOR_V3 {
    local uint64 pos = FTell();
    
    UINT32 length;
    UINT16 offset_to_first_timestamp;
    BYTE unknown_1[0x22];
    FILETIME created;
    FILETIME modified;
    FILETIME metadata_modified;
    FILETIME last_access;
    UINT64 attrib_flags;
    UINT64 security_desc;
    UINT64 logical_size;
    UINT64 physical_size;
    UINT64 offset_usn;
    UINT64 id_usn;
    UINT64 reparse_tag;
    UINT64 max_childs;
    UINT64 old_file_id;
    UINT64 old_dir_id;

    FSkip(length - (FTell() - pos));
} SIA_ATTRIBUTE_NODE_DESCRIPTOR_V3<read=ViewSiaAttributeV3>;
string ViewSiaAttributeV3(SIA_ATTRIBUTE_NODE_DESCRIPTOR_V3& val) {return Str("Created: %s", FileTimeToString(val.created)) + (val.reparse_tag ? Str(" (Reparse <0x%LX>)", val.reparse_tag) : "");}

typedef struct _DATA_RUN_ATTRIBUTE_VALUE_ROW_V3 {
    UINT64 starting_lcn;
    UINT16 flags;
    UINT16 len;
    UINT64 start_cluster_relarive;
    UINT32 number_clusters;
} DATA_RUN_ATTRIBUTE_VALUE_ROW_V3<read=ViewDataRunAttributeValueV3>;
string ViewDataRunAttributeValueV3(DATA_RUN_ATTRIBUTE_VALUE_ROW_V3& val) {return Str("start: 0x%LXh, count: 0x%LXh", val.starting_lcn, val.number_clusters);}

typedef struct _DATA_RUN_CONTENTS_V3(AddressTranslator& translator) {
    DATA_RUN_ATTRIBUTE_VALUE_ROW_V3 data_run;
    
    local uint64 pos = FTell();                    
    if (data_run.starting_lcn > 0) {FSeek(translateAddress(translator, data_run.starting_lcn * translator.page_size));}
    CONTENTS_FILE_V1 contents_file(data_run.number_clusters, translator.page_size);
    FSeek(pos);
} DATA_RUN_CONTENTS_V3<read=ViewDataRunContentsV3>;
string ViewDataRunContentsV3(DATA_RUN_CONTENTS_V3& val) {return ViewDataRunAttributeValueV3(val.data_run);}
               

typedef struct _DATA_RUN_ATTRIBUTE_NODE_DESCRIPTOR_V3 {
    local uint64 pos = FTell();
    UINT32 size;
    BYTE unknown[0x2C];
    UINT64 physical_size;
    UINT64 logical_size;
    UINT64 logical_size_2;
    UINT64 physical_size_2;
    FSkip(size - (FTell() - pos));
} DATA_RUN_ATTRIBUTE_NODE_DESCRIPTOR_V3<read=ViewDataRunAttributeNodeDescV3>;
string ViewDataRunAttributeNodeDescV3(DATA_RUN_ATTRIBUTE_NODE_DESCRIPTOR_V3& val) {return Str("logic_size: %Lu, phy_size: %Lu", val.logical_size, val.physical_size);}

typedef struct _DATA_RUN_RECORD_HEADER_V3 { ///Note: before ver 3.7
    UINT64 size_attribute_value;
    ATTRIBUTE_TYPE attribute_type;
} DATA_RUN_RECORD_HEADER_V3<read=ViewDataRunRecordHeaderV3>;
string ViewDataRunRecordHeaderV3(DATA_RUN_RECORD_HEADER_V3& val) {return EnumToString(val.attribute_type);}

typedef struct _DATA_RUN_RECORD_HEADER_V3_7 {
    UINT32 schema_type;
    BYTE unknown[0x14];
} DATA_RUN_RECORD_HEADER_V3_7<read=ViewDataRunRecordHeaderV3_7>;
string ViewDataRunRecordHeaderV3_7(DATA_RUN_RECORD_HEADER_V3_7& val) {return Str("schema_type: 0x%LXh", val.schema_type);}

typedef struct _RESIDENT_CONTENTS_FILE_V3_14 {
    local uint64 pos = FTell();
    UINT32 offset_to_contents_file;
    UINT64 zeroed;
    UINT64 physical_size_1;
    UINT64 logical_size_1;
    UINT64 logical_size_2;
    UINT64 physical_size_2;
    UINT32 flags;
    FSkip(offset_to_contents_file - (FTell() - pos));
    
    if(logical_size_1 > 0) {
        BYTE contents_file[logical_size_1];
    }
} RESIDENT_CONTENTS_FILE_V3_14<read=ViewContentsFileV3_14>;
string ViewContentsFileV3_14(RESIDENT_CONTENTS_FILE_V3_14& val) {return Str("resident file size=0x%x", val.logical_size_1);}

typedef struct _DATA_RUN_ATTRIBUTE_VALUE_V3(AddressTranslator& translator) { 
    local uint64 pos_m = FTell();
   
    MAIN_BASE_ATTRIBUTE_HEADER_V1 base;
	
    ///TODO: refactory this
	local int is_at_data = false;
	DATA_RUN_RECORD_HEADER_V3 data_run_header;
    if(data_run_header.attribute_type == AT_ADS) {
        ALTERNATIVE_DATA_STREAM alternative_data_stream(base.size_attribute_header - (FTell() - pos_m));
    } else if(base.size_attribute_header == 0x20) {
        UINT32 unknown_3;
		is_at_data = data_run_header.attribute_type == AT_DATA;
        if(data_run_header.attribute_type == 0x80000001 && unknown_3 == AT_DATA) { ///NOTE: ver 3,14 supported resident files
            ADDITIONAL_DATA_HEADER header;
            RESIDENT_CONTENTS_FILE_V3_14 resident_file;
        } else if(data_run_header.attribute_type == AT_REPARSE ||
           (data_run_header.attribute_type == 0x80000001 && unknown_3 == AT_REPARSE)) {
            ADDITIONAL_DATA_HEADER header;
            REPARSE_DATA reparse_data;
		} else if(!is_at_data) {   
	        Printf("Attrbute_type %s (0x%X,  0x%X) does not support yet\n", EnumToString(data_run_header.attribute_type), data_run_header.attribute_type, unknown_3);
		    BYTE unsupported [data_run_header.size_attribute_value];
        }
    } else if(base.size_attribute_header == 0x28) {
        UINT32 schema_id;
        if(schema_id == 0x0500B0) {
             ALTERNATIVE_DATA_STREAM alternative_data_stream(base.size_attribute_header - (FTell() - pos_m));
        }
	} else if(base.size_attribute_header == 0x38) {
        UINT32 schema_id;
        if(schema_id == 0x0500B0) {
             ALTERNATIVE_DATA_STREAM alternative_data_stream(base.size_attribute_header - (FTell() - pos_m));
        } else {
	        DATA_RUN_RECORD_HEADER_V3_7 data_run_header_v3_7;
	        is_at_data = schema_id == 0xE0080 && data_run_header_v3_7.schema_type == 0x1000;
            if(schema_id == 0xE0080 && data_run_header_v3_7.schema_type == 0x08) {
                BYTE unknown_on_3_7[base.size_attribute_value]  <comment="=0x01 0x10 0x00 0x00  0x00 0x00 0x00 0x00   0x01 0x00 0x00 0x00">;
            } else if(!is_at_data) {
		        Printf("Attrbute with schema_id 0x%X, schema_type == 0x%X does not support yet\n", schema_id, data_run_header_v3_7.schema_type);
		    }
        }
	} else {
		Printf("Unsupported data_run_header length: 0x%x\n", base.size_attribute_header);
	}
	
    if(is_at_data) {
        DATA_RUN_ATTRIBUTE_NODE_DESCRIPTOR_V3 data_run_node_desc;
            
        local uint64 pos = FTell();
        NODE_HEADER_V1 node_header;
            
        if(node_header.num_pointers > 0) {
            FSeek(pos + node_header.offset_to_first_pointer);
            UINT32 records_offset[node_header.num_pointers];
                
            local uint32 i = 0;
            for(i = 0; i < node_header.num_pointers; ++i) {
                FSeek(pos + (records_offset[i] & 0xFFFF));
                if (node_header.node_type & NT_Branch) {
                    NODE_INDEX_ENTRY_V3 index_entry_data_run;
                    jumpToBlock(translator, index_entry_data_run.block_ref);
                    struct _MSB_TREE_BLOCK_REF_V3 inner_data_run_record(translator, SI_DUMMY_DATA_RUN_VALUE);
                } else {
                    DATA_RUN_CONTENTS_V3 data_run_with_data(translator);
                }
            }
        }
    }

    FSkip(base.attribute_size - (FTell() - pos_m));
} DATA_RUN_ATTRIBUTE_VALUE_V3 <read=ViewDataRunHeaderV3>;
string ViewDataRunHeaderV3(DATA_RUN_ATTRIBUTE_VALUE_V3& val) {return Str("data_run_header size: 0x%x", val.base.size_attribute_header);}

typedef struct _FILE_RECORD_V3(AddressTranslator& translator) { // NOTE: as V1, except for translator
    SIA_ATTRIBUTE_NODE_DESCRIPTOR_V3 sia;
    
    local uint64 pos = FTell();
    NODE_HEADER_V1 node_header;
  
    if(node_header.num_pointers > 0)  {
        FSeek(pos + node_header.offset_to_first_pointer);
        UINT32 records_offset[node_header.num_pointers];
        
        local uint32 i = 0;
        for(i = 0; i < node_header.num_pointers; ++i) {
           FSeek(pos + (records_offset[i] & 0xFFFF));
           if (node_header.node_type & NT_Branch) {
                NODE_INDEX_ENTRY_V3 index_entry_file_record;
                jumpToBlock(translator, index_entry_file_record.block_ref);
                struct _MSB_TREE_BLOCK_REF_V3 inner_file_record(translator, SI_DUMMY_DATA_RUN);
           } else {
                DATA_RUN_ATTRIBUTE_VALUE_V3 node_data(translator);
           }
        }
    }
    FSeek(pos);
} FILE_RECORD_V3<read=ViewDataRunsV3>;
string ViewDataRunsV3(FILE_RECORD_V3& val) {return Str("data_runs: %Lu", sizeof(val.node_header.num_pointers));}

typedef struct _DIRECTORY_ATTRIBUTE_VALUE_V3 {
    UINT64 is_deleted;
    UINT64 node_id;
    FILETIME created;
    FILETIME modified;
    FILETIME metadata_modified;
    FILETIME last_access;
    UINT64 rounded_up_size;
    UINT64 actual_size;
    UINT32 flags;
    UINT32 reparse_tag;
} DIRECTORY_ATTRIBUTE_VALUE_V3<read=ViewDirectoryAttributeValueV3>;
string ViewDirectoryAttributeValueV3(DIRECTORY_ATTRIBUTE_VALUE_V3& val) {return Uint64ToHexStr(val.node_id) + (val.is_deleted ? " <Deleted?>" : "");}


typedef struct _FILE_ENTRY_RECORD_V3(AddressTranslator& translator) { // NOTE: as V1, except for FileRecord
    ATTRIBUTE_WITH_TYPE_HEADER_V1 attribute_header;

    if (attribute_header.attribute_type == Entry) {
        if (attribute_header.entry_type == Dir) {
            EXT_FILENAME_ATTRIBUTE_HEADER_V1 directory_name(attribute_header.base.size_attribute_header);
            DIRECTORY_ATTRIBUTE_VALUE_V3 dir_value;
        }
        if (attribute_header.entry_type == File) {
           EXT_FILENAME_ATTRIBUTE_HEADER_V1 file_name(attribute_header.base.size_attribute_header);
           FILE_RECORD_V3 file_value(translator);
        }
    } else if (attribute_header.attribute_type == Name) {
       EXT_CHILD_ATTRIBUTE_HEADER_V1 child_header;// Name record
       CHILD_ATTRIBUTE_VALUE_V1 child_value;
    } else if (attribute_header.attribute_type == Base) {
        FSkip(attribute_header.base.size_attribute_header - sizeof(attribute_header));
        SIA_ATTRIBUTE_NODE_DESCRIPTOR_V1 self_standart_info;
        BYTE unknown_attribute_value[attribute_header.base.attribute_size - sizeof(attribute_header) - sizeof(self_standart_info)];
     } else {
        if (attribute_header.base.size_attribute_header > sizeof(attribute_header)) {
            BYTE unknown_attribute_header[attribute_header.base.size_attribute_header - sizeof(attribute_header)];
        } else { ///NOTE some atributes header without attribute_type
            FSeek(FTell() - (sizeof(attribute_header) - attribute_header.base.size_attribute_header));
        }
        BYTE unknown_attribute_value[attribute_header.base.size_attribute_value];
     }
} FILE_ENTRY_RECORD_V3<read=ViewFileEntryV3>;
string ViewFileEntryV3(FILE_ENTRY_RECORD_V3& val) {
    local string res = EnumToString(val.attribute_header.attribute_type) + ": ";
    
    if (val.attribute_header.attribute_type == Entry) {
        if (val.attribute_header.entry_type == Dir) {
            res += val.directory_name.filename + " (" + ViewDirectoryAttributeValueV3(val.dir_value) + ")";
        } else if (val.attribute_header.entry_type == File) {
            res += val.file_name.filename;
        }
    } else if (val.attribute_header.attribute_type == Name) {
       res += ViewChildAttributeValue(val.child_value);
    } else if (val.attribute_header.attribute_type == Base) {
       res += FileTimeToString(val.self_standart_info.created);
     }
     
    return res;
}

//NOTE: added in ver 3.14
typedef struct _FILE_ENTRY_RECORD_V3_14(AddressTranslator& translator) { // NOTE: as V1, except for FileRecord
    MAIN_BASE_ATTRIBUTE_HEADER_V1 attribute_header;
    BYTE unknown_entry_record_3_14[attribute_header.size_attribute_value];
} FILE_ENTRY_RECORD_V3_14<read=ViewFileEntryV3_14>;
string ViewFileEntryV3_14(FILE_ENTRY_RECORD_V3_14& val) { return Str("entry_record_3_14 size=0x%x", sizeof(val.unknown_entry_record_3_14));}
//-------------------------------- Parse MSB
typedef struct _OBJECT_RECORD_V3 {
    MAIN_BASE_ATTRIBUTE_HEADER_V1 attribute_header;

    UINT64 table_id;
    UINT64 node_id;
    BYTE unknown_1[32];
  
    METADATA_BLOCK_REFERENCE_V3 metadata_block_ref;
} OBJECT_RECORD_V3<read=ViewObjectRecordV3>;
string ViewObjectRecordV3(OBJECT_RECORD_V3& val) {return Str("node_id: 0x%Xh, page: 0x%Xh", val.node_id, val.metadata_block_ref.first_block_number);}

void parseObjectV3(AddressTranslator& translator)
{
    OBJECT_RECORD_V3 object_ref;
    
    jumpToBlock(translator, object_ref.metadata_block_ref);
    switch (object_ref.node_id) {
        case VolumeObject:
            MSB_TREE_BLOCK_REF_V3 volume_object_record(translator, 0);
            break;
        case Root:
            MSB_TREE_BLOCK_REF_V3 root(translator, 0)<open=true>;
            break;
        default:
            if(object_ref.node_id > Root) {
                MSB_TREE_BLOCK_REF_V3 folder(translator, 0);
            } else {
                MSB_TREE_BLOCK_REF_V3 unknown_object(translator, 0);
            }
            break;
    }
}

void parseNodeV3(UINT16 scheme_table, AddressTranslator& translator)
{ ///NOTE: may be as V1
    switch(scheme_table) {
    case SI_PATH_OBJECT:
        FILE_ENTRY_RECORD_V3 file_entry(translator);
        break;
    case SI_CHILD_PARENT:
        MAIN_BASE_ATTRIBUTE_HEADER_V1 attribute_header;
        CHILD_PARENT_ATTRIBUTE_VALUE_V1 attribute_value_child;
        break;
    case SI_VOLUME_OBJECT:
        parseVolumeObject();
        break;
    case SI_OBJECT:
        parseObjectV3(translator);
        break;
    case SI_CONTAINER:
        MAIN_BASE_ATTRIBUTE_HEADER_V1 attribute_header;
        CONTAINER_VALUE_V3 container(attribute_header.size_attribute_value);
        translator.table[container.band_id - 2] = container.cluster_block_number;
        break;
    case SI_BITMAP:
        MAIN_BASE_ATTRIBUTE_HEADER_V1 attribute_header;
        BITMAP_ATTRIBUTE_V3 bm;
        break;
    case SI_SCHEME_TABLE:
        MAIN_BASE_ATTRIBUTE_HEADER_V1 attribute_header;
        SCHEME_TABLE_VALUE_V1 attribute_value_sc(attribute_header.size_attribute_value); 
        break;
    case SI_CHILD_PARENT:
        MAIN_BASE_ATTRIBUTE_HEADER_V1 attribute_header;
        CHILD_PARENT_ATTRIBUTE_VALUE_V1 attribute_value_pa;
        break;
    case SI_DUMMY_DATA_RUN:
        DATA_RUN_ATTRIBUTE_VALUE_V3 file_data(translator);
        break;
    case SI_DUMMY_DATA_RUN_VALUE:
        DATA_RUN_CONTENTS_V3 data(translator);
        break;
    case SI_PATH_OBJECT_EXT:
        FILE_ENTRY_RECORD_V3_14 file_entry(translator);
        break;
    default:
        //Printf("Unrecognized node schema: 0x%x\n", scheme_table);
        MAIN_BASE_ATTRIBUTE_HEADER_V1 attribute_header;
        if(attribute_header.size_attribute_value > 0) {
            UNKNOWN_VALUE attribute_value(attribute_header.size_attribute_value); 
        }
        break;
     }
}
//-------------------------------- TreeControl
typedef struct _TREE_CONTROL_CHECKPOINT_V3 {
    UINT32 unknown_1;
    UINT16 major_version;
    UINT16 minor_version;
    UINT32 offset_to_block_ref;
    UINT32 size_of_checkpoint;
    
    UINT64 checkpoint_virtual_clock;
    UINT64 allocator_virtual_clock;
    UINT32 oldest_log_record;
    UINT32 unknown_1;
    UINT64 unknown_2;
    UINT64 unknown_3;
    UINT32 checkpoint_data_size;
    UINT32 unknown_4;
    UINT32 count_control_objects;
    if(major_version ==3 && minor_version >= 14) { //ver3.14
        UINT32 unknown_5;
        UINT32 unknown_6;
        UINT32 unknown_7[3];
    }
    UINT32 offsets_control_object[count_control_objects];
} TREE_CONTROL_CHECKPOINT_V3<read=ViewTreeControlCheckpointV3>;
string ViewTreeControlCheckpointV3(TREE_CONTROL_CHECKPOINT_V3& val) {return Str("control_objects: %i", val.count_control_objects);}

typedef enum <BYTE> _CONTROL_OBJECT_TYPE_V3 {
    CT3_OBJECT_TREE          = 0x0,
    CT3_ALLOC_MEDIUM_TREE    = 0x1,
    CT3_ALLOC_CONTAINER_TREE = 0x2,
    CT3_SCHEMA_TREE          = 0x3,
    CT3_CHILD_PARENT_TREE    = 0x4,
    CT3_OBJECT_TREE_COPY     = 0x5,
    CT3_BLOCK_REF_TREE       = 0x6,
    CT3_CONTAINER_TREE       = 0x7,
    CT3_CONTAINER_TREE_COPY  = 0x8,
    CT3_SCHEMA_TREE_COPY     = 0x9,
    CT3_CONTAINER_INDEX_TREE = 0xA,
    CT3_INTEGRITY_CHECK      = 0xB,
    CT3_ALLOC_SMALL_TREE     = 0xC,
} CONTROL_OBJECT_TYPE_V3;

typedef struct _TREE_CONTROL_V3 {
    local uint64 pos = FTell();
    
    METADATA_BLOCK_HEADER_V3 treecontrol_header;
    TREE_CONTROL_CHECKPOINT_V3 tree_control;
    
    FSeek(pos + tree_control.offset_to_block_ref);
    METADATA_BLOCK_REFERENCE_V3 self_metadata_reference;
    
    Assert(tree_control.count_control_objects >= 13);
  
    FSeek(pos + tree_control.offsets_control_object[CT3_OBJECT_TREE]);
    METADATA_BLOCK_REFERENCE_V3 objects_tree;
    
    FSeek(pos + tree_control.offsets_control_object[CT3_ALLOC_MEDIUM_TREE]);
    METADATA_BLOCK_REFERENCE_V3 alloc_medium_tree;
    
    FSeek(pos + tree_control.offsets_control_object[CT3_ALLOC_CONTAINER_TREE]);
    METADATA_BLOCK_REFERENCE_V3 alloc_container;
    
    FSeek(pos + tree_control.offsets_control_object[CT3_SCHEMA_TREE]);
    METADATA_BLOCK_REFERENCE_V3 schema_tree;
    
    FSeek(pos + tree_control.offsets_control_object[CT3_CHILD_PARENT_TREE]);
    METADATA_BLOCK_REFERENCE_V3 child_parent_tree;
    
    FSeek(pos + tree_control.offsets_control_object[CT3_OBJECT_TREE_COPY]);
    METADATA_BLOCK_REFERENCE_V3 object_tree_copy;
    
    FSeek(pos + tree_control.offsets_control_object[CT3_BLOCK_REF_TREE]);
    METADATA_BLOCK_REFERENCE_V3 block_ref_tree;
    
    FSeek(pos + tree_control.offsets_control_object[CT3_CONTAINER_TREE]);
    METADATA_BLOCK_REFERENCE_V3 container_tree;
    
    FSeek(pos + tree_control.offsets_control_object[CT3_CONTAINER_TREE_COPY]);
    METADATA_BLOCK_REFERENCE_V3 container_tree_copy;
    
    FSeek(pos + tree_control.offsets_control_object[CT3_SCHEMA_TREE_COPY]);
    METADATA_BLOCK_REFERENCE_V3 schema_tree_copy;
    
    FSeek(pos + tree_control.offsets_control_object[CT3_CONTAINER_INDEX_TREE]);
    METADATA_BLOCK_REFERENCE_V3 container_index_tree;
    
    FSeek(pos + tree_control.offsets_control_object[CT3_INTEGRITY_CHECK]);
    METADATA_BLOCK_REFERENCE_V3 integrity_check_tree;
    
    FSeek(pos + tree_control.offsets_control_object[CT3_ALLOC_SMALL_TREE]);
    METADATA_BLOCK_REFERENCE_V3 alloc_small_tree;    
} TREE_CONTROL_V3<read=ViewTreeControlV3>;
string ViewTreeControlV3(TREE_CONTROL_V3& val) {return Str("control_objects: %i", val.tree_control.count_control_objects);}

typedef struct _TREE_CONTROL_PARSE_V3(uint64 page_size, uint64 band_size, uint64 volume_size) {
    TREE_CONTROL_V3 tree_control_data;
    
    local uint64 pos = FTell();
    
    FSeek(tree_control_data.container_tree.first_block_number * page_size);
    METADATA_BLOCK_HEADER_V3 header_container;
    NODE_DESCRIPTOR_V1 node_descriptor_container; ///NOTE: need to calc count of table of Translator
        
    local AddressTranslator translator_nop(node_descriptor_container.num_records);
    translator_nop.band_size = 0;
    translator_nop.page_size = page_size;
    
    FSeek(tree_control_data.container_tree.first_block_number * page_size);
    MSB_TREE_BLOCK_REF_V3 container(translator_nop, 0);
    
    local uint64 table_size = container.node.node_descriptor.num_records;
    local AddressTranslator translator(table_size);
    translator.band_size = band_size > 0 ? band_size : (volume_size / table_size); ///NOTE: ReeFS 3.1 has band_size=0, so need to manually calculate
    translator.page_size = page_size;
    local uint64 i = 0;
    for (i = 0; i < table_size; ++i) {
        translator.table[i] = translator_nop.table[i] * page_size;
    }
  
    FSeek(tree_control_data.container_tree_copy.first_block_number * page_size);
    MSB_TREE_BLOCK_REF_V3 container_copy(translator_nop, 0);
    
    FSeek(tree_control_data.alloc_small_tree.first_block_number * page_size);
    MSB_TREE_BLOCK_REF_V3 alloc_small_tree(translator_nop, 0);

    jumpToBlock(translator, tree_control_data.alloc_medium_tree);
    MSB_TREE_BLOCK_REF_V3 alloc_medium_tree(translator, 0);
 
    jumpToBlock(translator, tree_control_data.schema_tree);
    MSB_TREE_BLOCK_REF_V3 scheme_table(translator, 0);
 
    jumpToBlock(translator, tree_control_data.schema_tree_copy);
    MSB_TREE_BLOCK_REF_V3 scheme_table_copy(translator, 0);
    
    jumpToBlock(translator, tree_control_data.child_parent_tree);
    MSB_TREE_BLOCK_REF_V3 child_parent(translator, 0);
 
    jumpToBlock(translator, tree_control_data.objects_tree);
    MSB_TREE_BLOCK_REF_V3 objects_tree(translator, 0) <open=true>;
    
    FSeek(pos);
} TREE_CONTROL_PARSE_V3<open=true, read=ViewTreeControlParseV3>;
string ViewTreeControlParseV3(TREE_CONTROL_PARSE_V3& val) {return Str("control_objects: %i", val.tree_control_data.tree_control.count_control_objects);}
//-------------------------------- Superblock
typedef struct _REFS_SUPERBLOCK_DATA_V3 {  ///NOTE: as _REFS_SUPERBLOCK_DATA_V1
    GUID id;
    UINT64 empty_1;
    UINT64 superblock_version;
    UINT32 offset_to_first_checkpoint_number;
    UINT32 count_checkpoints  <comment="=0x2">;
    UINT32 offset_to_first_record;
    UINT32 length_of_record;
} REFS_SUPERBLOCK_DATA_V3<read=ViewReFsSuperBlockDataV3>;
string ViewReFsSuperBlockDataV3(REFS_SUPERBLOCK_DATA_V3& val) {return Str("checkpoints: %i", val.count_checkpoints);}

typedef struct _REFS_SUPERBLOCK_V3 {
    local uint64 pos = FTell();
    
    METADATA_BLOCK_HEADER_V3 header_meta;
    REFS_SUPERBLOCK_DATA_V3 spb;
    
    FSeek(pos + spb.offset_to_first_checkpoint_number);
    UINT64 checkpoints[spb.count_checkpoints];
    
    METADATA_BLOCK_REFERENCE_V3 self_metadata_reference;
} REFS_SUPERBLOCK_V3<read=ViewReFsSuperBlockV3>;
string ViewReFsSuperBlockV3(REFS_SUPERBLOCK_V3& val) {return Str("checkpoints: %i", val.spb.count_checkpoints);}

typedef struct _REFS_SUPERBLOCK_PARSE_V3(uint64 page_size, uint64 band_size, uint64 volume_size) {
    REFS_SUPERBLOCK_V3 superblock_data;
    
    ///NOTE:checkpoints[1] for backup TreeControlBlock
    FSeek(superblock_data.checkpoints[0] * page_size);
    TREE_CONTROL_PARSE_V3 tree_control(page_size, band_size, volume_size);
} REFS_SUPERBLOCK_PARSE_V3<open=true, read=ViewReFsSuperBlockParseV3>;
string ViewReFsSuperBlockParseV3(REFS_SUPERBLOCK_PARSE_V3& val) {return Str("checkpoints: %i", val.superblock_data.spb.count_checkpoints);}
//------------------------
int main()
{
    REFS_VBR vbr;

    const local uint64 start_superblock = 0x1E;

    if (vbr.maj_ver == 1) {        
        local uint64 page_size =  16 * 1024;
        FSeek(start_superblock * page_size);
        REFS_SUPERBLOCK_PARSE_V1 superblock(page_size);
    } else {
        local uint64 cluster_size = vbr.bytes_per_sector * vbr.sectors_per_cluster;
        local uint64 page_size =  cluster_size;
        FSeek(start_superblock * page_size);
        REFS_SUPERBLOCK_PARSE_V3 superblock(page_size, vbr.container_band_size, vbr.bytes_per_sector * vbr.sectors );
    }
   
    FSeek(vbr.bytes_per_sector * vbr.sectors - vbr.fsrs.length);
    REFS_VBR backup_vbr;
    //TODO: get view of directories
    return 0;
}

return main();