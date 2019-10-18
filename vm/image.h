#define IMAGE_MAGIC 0x0f0e0d0c
#define IMAGE_VERSION 3

typedef struct {
	CELL magic;
	CELL version;
	/* all pointers in the image file are relocated from
	   relocation_base to here when the image is loaded */
	CELL data_relocation_base;
	/* tagged pointer to bootstrap quotation */
	CELL boot;
	/* tagged pointer to global namespace */
	CELL global;
	/* tagged pointer to t singleton */
	CELL t;
	/* tagged pointer to bignum 0 */
	CELL bignum_zero;
	/* tagged pointer to bignum 1 */
	CELL bignum_pos_one;
	/* tagged pointer to bignum -1 */
	CELL bignum_neg_one;
	/* size of heap */
	CELL data_size;
	/* size of code heap */
	CELL code_size;
	/* code relocation base */
	CELL code_relocation_base;
} F_HEADER;

typedef struct {
	const F_CHAR* image;
	CELL ds_size, rs_size, cs_size;
	CELL gen_count, young_size, aging_size;
	CELL code_size;
	bool secure_gc;
} F_PARAMETERS;

void load_image(F_PARAMETERS *p);
void init_objects(F_HEADER *h);
bool save_image(const F_CHAR *file);
void primitive_save_image(void);

/* relocation base of currently loaded image's data heap */
CELL data_relocation_base;

INLINE void data_fixup(CELL *cell)
{
	if(TAG(*cell) != FIXNUM_TYPE && *cell != F)
		*cell += (tenured.start - data_relocation_base);
}

CELL code_relocation_base;

INLINE void code_fixup(XT *cell)
{
	CELL value = (CELL)*cell;
	value += (code_heap.segment->start - code_relocation_base);
	*cell = (XT)value;
}

void relocate_data();
void relocate_code();