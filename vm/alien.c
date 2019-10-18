#include "master.h"

/* test if alien is no longer valid (it survived an image save/load) */
void primitive_expired(void)
{
	CELL object = dpeek();

	if(type_of(object) == ALIEN_TYPE)
	{
		F_ALIEN *alien = untag_alien_fast(object);
		drepl(tag_boolean(alien->expired));
	}
	else
		drepl(object == F ? T : F);
}

/* gets the address of an object representing a C pointer */
void *alien_offset(CELL object)
{
	F_ALIEN *alien;
	F_BYTE_ARRAY *byte_array;
	F_BIT_ARRAY *bit_array;

	switch(type_of(object))
	{
	case BYTE_ARRAY_TYPE:
		byte_array = untag_byte_array_fast(object);
		return byte_array + 1;
	case BIT_ARRAY_TYPE:
		bit_array = untag_bit_array_fast(object);
		return bit_array + 1;
	case ALIEN_TYPE:
		alien = untag_alien_fast(object);
		if(alien->expired)
			simple_error(ERROR_EXPIRED,object,F);
		return alien_offset(alien->alien) + alien->displacement;
	case F_TYPE:
		return NULL;
	default:
		type_error(ALIEN_TYPE,object);
		return NULL; /* can't happen */
	}
}

/* pop an object representing a C pointer */
void *unbox_alien(void)
{
	return alien_offset(dpop());
}

/* make an alien */
CELL allot_alien(CELL delegate, CELL displacement)
{
	REGISTER_ROOT(delegate);
	F_ALIEN *alien = allot_object(ALIEN_TYPE,sizeof(F_ALIEN));
	UNREGISTER_ROOT(delegate);
	alien->alien = delegate;
	alien->displacement = displacement;
	alien->expired = false;
	return tag_object(alien);
}

/* make an alien and push */
void box_alien(void *ptr)
{
	if(ptr == NULL)
		dpush(F);
	else
		dpush(allot_alien(F,(CELL)ptr));
}

/* make an alien pointing at an offset of another alien */
void primitive_displaced_alien(void)
{
	CELL alien = dpop();
	CELL displacement = to_cell(dpop());
	if(alien == F && displacement == 0)
		dpush(F);
	else
		dpush(allot_alien(alien,displacement));
}

/* address of an object representing a C pointer. Explicitly throw an error
if the object is a byte array, as a sanity check. */
void primitive_alien_address(void)
{
	CELL object = dpop();
	switch(type_of(object))
	{
	case ALIEN_TYPE:
	case F_TYPE:
		box_unsigned_cell((CELL)alien_offset(object));
		break;
	default:
		type_error(ALIEN_TYPE,object);
		break;
	}
}

/* image loading */
void fixup_alien(F_ALIEN *d)
{
	d->expired = true;
}

/* pop ( alien n ) from datastack, return alien's address plus n */
INLINE void *alien_pointer(void)
{
	F_FIXNUM offset = to_fixnum(dpop());
	return unbox_alien() + offset;
}

/* define words to read/write values at an alien address */
#define DEF_ALIEN_SLOT(name,type,boxer,to) \
void primitive_alien_##name (void) \
{ \
	boxer (*(type*)alien_pointer()); \
} \
void primitive_set_alien_##name (void) \
{ \
	type* ptr = alien_pointer(); \
	type value = to(dpop()); \
	*ptr = value; \
}

DEF_ALIEN_SLOT(signed_cell,F_FIXNUM,box_signed_cell,to_fixnum)
DEF_ALIEN_SLOT(unsigned_cell,CELL,box_unsigned_cell,to_cell)
DEF_ALIEN_SLOT(signed_8,s64,box_signed_8,to_signed_8)
DEF_ALIEN_SLOT(unsigned_8,u64,box_unsigned_8,to_unsigned_8)
DEF_ALIEN_SLOT(signed_4,s32,box_signed_cell,to_fixnum)
DEF_ALIEN_SLOT(unsigned_4,u32,box_unsigned_cell,to_cell)
DEF_ALIEN_SLOT(signed_2,s16,box_signed_cell,to_fixnum)
DEF_ALIEN_SLOT(unsigned_2,u16,box_unsigned_cell,to_cell)
DEF_ALIEN_SLOT(signed_1,u8,box_signed_cell,to_fixnum)
DEF_ALIEN_SLOT(unsigned_1,u8,box_unsigned_cell,to_cell)
DEF_ALIEN_SLOT(float,float,box_float,untag_float)
DEF_ALIEN_SLOT(double,double,box_float,untag_float)

/* for FFI calls passing structs by value */
void to_value_struct(CELL src, void *dest, CELL size)
{
	memcpy(dest,alien_offset(src),size);
}

/* for FFI callbacks receiving structs by value */
void box_value_struct(void *src, CELL size)
{
	F_BYTE_ARRAY *array = allot_byte_array(size);
	memcpy(array + 1,src,size);
	dpush(tag_object(array));
}

/* On OS X, structs <= 8 bytes are returned in registers. */
void box_struct_1(CELL x)
{
	F_BYTE_ARRAY *array = allot_byte_array(2 * CELLS);
	put(AREF(array,0),x);
	dpush(tag_object(array));
}

void box_struct_2(CELL x, CELL y)
{
	F_BYTE_ARRAY *array = allot_byte_array(2 * CELLS);
	put(AREF(array,0),x);
	put(AREF(array,1),y);
	dpush(tag_object(array));
}

/* open a native library and push a handle */
void primitive_dlopen(void)
{
	CELL path = tag_object(string_to_native_alien(
		untag_string(dpop())));
	REGISTER_ROOT(path);
	F_DLL* dll = allot_object(DLL_TYPE,sizeof(F_DLL));
	UNREGISTER_ROOT(path);
	dll->path = path;
	ffi_dlopen(dll,true);
	dpush(tag_object(dll));
}

/* look up a symbol in a native library */
void primitive_dlsym(void)
{
	CELL dll = dpop();
	REGISTER_ROOT(dll);
	F_SYMBOL *sym = unbox_symbol_string();
	UNREGISTER_ROOT(dll);

	F_DLL *d;

	if(dll == F)
		d = NULL;
	else
	{
		d = untag_dll(dll);
		if(d->dll == NULL)
			simple_error(ERROR_EXPIRED,dll,F);
	}

	box_alien(ffi_dlsym(d,sym));
}

/* close a native library handle */
void primitive_dlclose(void)
{
	ffi_dlclose(untag_dll(dpop()));
}