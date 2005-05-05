typedef struct {
	/* always tag_header(SBUF_TYPE) */
	CELL header;
	/* untagged */
	CELL top;
	/* tagged */
	CELL string;
} F_SBUF;

INLINE F_SBUF* untag_sbuf(CELL tagged)
{
	type_check(SBUF_TYPE,tagged);
	return (F_SBUF*)UNTAG(tagged);
}

F_SBUF* sbuf(F_FIXNUM capacity);

void primitive_sbuf(void);
void primitive_sbuf_length(void);
void primitive_set_sbuf_length(void);
void primitive_sbuf_nth(void);
void sbuf_ensure_capacity(F_SBUF* sbuf, F_FIXNUM top);
void set_sbuf_nth(F_SBUF* sbuf, CELL index, u16 value);
void primitive_set_sbuf_nth(void);
void sbuf_append_string(F_SBUF* sbuf, F_STRING* string);
void primitive_sbuf_append(void);
void primitive_sbuf_clone(void);
void fixup_sbuf(F_SBUF* sbuf);
void collect_sbuf(F_SBUF* sbuf);
