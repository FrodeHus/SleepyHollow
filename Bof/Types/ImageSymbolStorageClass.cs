namespace SleepyHollow.Bof.Types;

public enum ImageSymbolStorageClass : byte
{
    IMAGE_SYM_CLASS_END_OF_FUNCTION = 0xFF, // End of function
    IMAGE_SYM_CLASS_NULL = 0x00, // No class
    IMAGE_SYM_CLASS_AUTOMATIC = 0x01, // Automatic variable
    IMAGE_SYM_CLASS_EXTERNAL = 0x02, // External symbol
    IMAGE_SYM_CLASS_STATIC = 0x03, // Static symbol
    IMAGE_SYM_CLASS_REGISTER = 0x04, // Register variable
    IMAGE_SYM_CLASS_EXTERNAL_DEF = 0x05, // External definition
    IMAGE_SYM_CLASS_LABEL = 0x06, // Label
    IMAGE_SYM_CLASS_UNDEFINED_LABEL = 0x07, // Undefined label
    IMAGE_SYM_CLASS_MEMBER_OF_STRUCT = 0x08, // Member of structure
    IMAGE_SYM_CLASS_ARGUMENT = 0x09, // Function argument
    IMAGE_SYM_CLASS_STRUCT_TAG = 0x0A, // Structure tag
    IMAGE_SYM_CLASS_MEMBER_OF_UNION = 0x0B, // Member of union
    IMAGE_SYM_CLASS_UNION_TAG = 0x0C, // Union tag
    IMAGE_SYM_CLASS_TYPE_DEFINITION = 0x0D, // Type definition
    IMAGE_SYM_CLASS_UNDEFINED_STATIC = 0x0E, // Undefined static symbol
    IMAGE_SYM_CLASS_ENUM_TAG = 0x0F, // Enumeration tag
    IMAGE_SYM_CLASS_MEMBER_OF_ENUM = 0x10, // Member of enumeration
}
