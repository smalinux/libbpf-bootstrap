// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static const char * const btf_kind_str_mapping[] = {
	[BTF_KIND_UNKN]		= "UNKNOWN",
	[BTF_KIND_INT]		= "INT",
	[BTF_KIND_PTR]		= "PTR",
	[BTF_KIND_ARRAY]	= "ARRAY",
	[BTF_KIND_STRUCT]	= "STRUCT",
	[BTF_KIND_UNION]	= "UNION",
	[BTF_KIND_ENUM]		= "ENUM",
	[BTF_KIND_FWD]		= "FWD",
	[BTF_KIND_TYPEDEF]	= "TYPEDEF",
	[BTF_KIND_VOLATILE]	= "VOLATILE",
	[BTF_KIND_CONST]	= "CONST",
	[BTF_KIND_RESTRICT]	= "RESTRICT",
	[BTF_KIND_FUNC]		= "FUNC",
	[BTF_KIND_FUNC_PROTO]	= "FUNC_PROTO",
	[BTF_KIND_VAR]		= "VAR",
	[BTF_KIND_DATASEC]	= "DATASEC",
	[BTF_KIND_TYPE_TAG]	= "TYPE_TAG",
	[BTF_KIND_DECL_TAG]	= "DECL_TAG",
	[BTF_KIND_ENUM64]	= "ENUM64",
};

static const char *btf_kind_str(__u16 kind)
{
	if (kind > BTF_KIND_DATASEC)
		return "UNKNOWN";
	return btf_kind_str_mapping[kind];
}

static const char *btf_int_enc_str(__u8 encoding)
{
	switch (encoding) {
	case 0:
		return "(none)";
	case BTF_INT_SIGNED:
		return "SIGNED";
	case BTF_INT_CHAR:
		return "CHAR";
	case BTF_INT_BOOL:
		return "BOOL";
	default:
		return "UNKN";
	}
}

static const char *btf_var_linkage_str(__u32 linkage)
{
	switch (linkage) {
	case BTF_VAR_STATIC:
		return "static";
	case BTF_VAR_GLOBAL_ALLOCATED:
		return "global-alloc";
	default:
		return "(unknown)";
	}
}

static const char *btf_func_linkage_str(const struct btf_type *t)
{
	switch (btf_vlen(t)) {
	case BTF_FUNC_STATIC:
		return "static";
	case BTF_FUNC_GLOBAL:
		return "global";
	case BTF_FUNC_EXTERN:
		return "extern";
	default:
		return "(unknown)";
	}
}

static const char *btf_str(const struct btf *btf, __u32 off)
{
	if (!off)
		return "(anon)";
	return btf__str_by_offset(btf, off) ?: "(invalid)";
}

__attribute__((unused))
static int btf_dump__dump_type_raw(const struct btf *btf, __u32 id)
{
	const struct btf_type *t;
	int kind, i;
	__u32 vlen;

	t = btf__type_by_id(btf, id);
	if (!t)
		return -EINVAL;

	vlen = btf_vlen(t);
	kind = btf_kind(t);

	printf("[%u] %s '%s'", id, btf_kind_str(kind), btf_str(btf, t->name_off));

	switch (kind) {
	case BTF_KIND_INT:
		printf(" size=%u bits_offset=%u nr_bits=%u encoding=%s",
				t->size, btf_int_offset(t), btf_int_bits(t),
				btf_int_enc_str(btf_int_encoding(t)));
		break;
	case BTF_KIND_PTR:
	case BTF_KIND_CONST:
	case BTF_KIND_VOLATILE:
	case BTF_KIND_RESTRICT:
	case BTF_KIND_TYPEDEF:
		printf(" type_id=%u", t->type);
		break;
	case BTF_KIND_ARRAY: {
		const struct btf_array *arr = btf_array(t);

		printf(" type_id=%u index_type_id=%u nr_elems=%u",
				arr->type, arr->index_type, arr->nelems);
		break;
	}
	case BTF_KIND_STRUCT:
	case BTF_KIND_UNION: {
		const struct btf_member *m = btf_members(t);

		printf(" size=%u vlen=%u", t->size, vlen);
		for (i = 0; i < vlen; i++, m++) {
			__u32 bit_off, bit_sz;

			bit_off = btf_member_bit_offset(t, i);
			bit_sz = btf_member_bitfield_size(t, i);
			printf("\n\t'%s' type_id=%u bits_offset=%u",
					btf_str(btf, m->name_off), m->type, bit_off);
			if (bit_sz)
				printf(" bitfield_size=%u", bit_sz);
		}
		break;
	}
	case BTF_KIND_ENUM: {
		const struct btf_enum *v = btf_enum(t);

		printf(" size=%u vlen=%u", t->size, vlen);
		for (i = 0; i < vlen; i++, v++) {
			printf("\n\t'%s' val=%u",
					btf_str(btf, v->name_off), v->val);
		}
		break;
	}
	case BTF_KIND_FWD:
		printf(" fwd_kind=%s", btf_kflag(t) ? "union" : "struct");
		break;
	case BTF_KIND_FUNC:
		printf(" type_id=%u linkage=%s", t->type, btf_func_linkage_str(t));
		break;
	case BTF_KIND_FUNC_PROTO: {
		const struct btf_param *p = btf_params(t);

		printf(" ret_type_id=%u vlen=%u", t->type, vlen);
		for (i = 0; i < vlen; i++, p++) {
			printf("\n\t'%s' type_id=%u",
					btf_str(btf, p->name_off), p->type);
		}
		break;
	}
	case BTF_KIND_VAR:
		printf(" type_id=%u, linkage=%s",
				t->type, btf_var_linkage_str(btf_var(t)->linkage));
		break;
	case BTF_KIND_DATASEC: {
		const struct btf_var_secinfo *v = btf_var_secinfos(t);

		printf(" size=%u vlen=%u", t->size, vlen);
		for (i = 0; i < vlen; i++, v++) {
			printf("\n\ttype_id=%u offset=%u size=%u",
					v->type, v->offset, v->size);
		}
		break;
	}
	default:
		break;
	}

	return 0;
}

static int *vis;

static int depth = 0;
static bool hide_type_id_diffs = false;

static void indent() {
	int i;

	printf("[%03d]", depth);
	for (i = 0; i < depth; i++) {
		printf(" ");
	}
}

#define print(fmt, args...) ({ indent(); \
	printf("[%d:%d %s '%s']: " fmt, id1, id2, btf_kind_str(kind1), name1, ##args); })

static int btfdiff(struct btf *btf, int id1, int id2)
{
	const struct btf_type *t1, *t2;
	int kind1, kind2, i;
	int vlen1, vlen2;
	const char *name1, *name2;
	bool diff = false;

	if (vis[id1] && vis[id2])
		return 0;

	vis[id1] = vis[id2] = 1;
	depth++;

	t1 = btf__type_by_id(btf, id1);
	t2 = btf__type_by_id(btf, id2);
	kind1 = btf_kind(t1);
	kind2 = btf_kind(t2);
	vlen1 = btf_vlen(t1);
	vlen2 = btf_vlen(t2);
	name1 = btf__str_by_offset(btf, t1->name_off);
	name2 = btf__str_by_offset(btf, t2->name_off);

	if (strcmp(name1, name2) != 0) {
		print("NAME '%s' != NAME '%s'\n", name1, name2);
		diff = true;
		goto out;
	}
	if (kind1 != kind2) {
		print("KIND %s != KIND %s\n", btf_kind_str(kind1), btf_kind_str(kind2));
		diff = true;
		goto out;
	}
	if (vlen1 != vlen2) {
		print("VLEN %d != VLEN %d\n", vlen1, vlen2);
		diff = true;
		goto out;
	}

	switch (kind1) {
	case BTF_KIND_INT:
		if (memcmp(t1 + 1, t2 + 1, sizeof(int)) != 0) {
			print("INTS DIFFER");
			diff = true;
			goto out;
		}
		break;
	case BTF_KIND_PTR:
	case BTF_KIND_CONST:
	case BTF_KIND_VOLATILE:
	case BTF_KIND_RESTRICT:
		if (t1->type != t2->type) {
			btfdiff(btf, t1->type, t2->type);
			diff = true;
			goto out;
		}
		break;
	case BTF_KIND_TYPEDEF:
		if (t1->type != t2->type) {
			if (!hide_type_id_diffs)
				print("TYPEDEF TYPE %d != POINTEE TYPE %d\n", t1->type, t2->type);
			btfdiff(btf, t1->type, t2->type);
			diff = true;
			goto out;
		}
		break;
	case BTF_KIND_ARRAY: {
		const struct btf_array *a1 = btf_array(t1);
		const struct btf_array *a2 = btf_array(t2);
		bool diff = false;

		if (a1->nelems != a2->nelems) {
			print("NELEMS %d != NELEMS %d\n", a1->nelems, a2->nelems);
			btfdiff(btf, a1->type, a2->type);
			diff = true;
		}
		if (a1->type != a2->type) {
			if (!hide_type_id_diffs)
				print("ELEM TYPE %d != ELEM TYPE %d\n", a1->type, a2->type);
			btfdiff(btf, a1->type, a2->type);
			diff = true;
		}
		if (a1->index_type != a2->index_type) {
			print("IDX TYPE %d != IDX TYPE %d\n", a1->index_type, a2->index_type);
			btfdiff(btf, a1->index_type, a2->index_type);
			diff = true;
		}
		if (diff)
			goto out;
		break;
	}
	case BTF_KIND_STRUCT:
	case BTF_KIND_UNION: {
		const struct btf_member *m1 = btf_members(t1);
		const struct btf_member *m2 = btf_members(t2);

		if (t1->size != t2->size) {
			print("SZ %d != SZ %d\n", t1->size, t2->size);
			diff = true;
		}
		for (i = 0; i < vlen1; i++, m1++, m2++) {
			__u32 bit_off1, bit_sz1, bit_off2, bit_sz2;
			const char *fn1, *fn2;

			bit_off1 = btf_member_bit_offset(t1, i);
			bit_sz1 = btf_member_bitfield_size(t1, i);
			bit_off2 = btf_member_bit_offset(t2, i);
			bit_sz2 = btf_member_bitfield_size(t2, i);
			fn1 = btf__str_by_offset(btf, m1->name_off);
			fn2 = btf__str_by_offset(btf, m2->name_off);

			if (strcmp(fn1, fn2) != 0) {
				print("F#%d: FNAME '%s' TYPE %d != FNAME '%s' TYPE %d\n",
					i, fn1, m1->type, fn2, m2->type);
				diff = true;
			} else if (m1->type != m2->type) {
				if (!hide_type_id_diffs)
					print("F#%d FNAME '%s': TYPE %d != TYPE %d\n", i, fn1, m1->type, m2->type);
				btfdiff(btf, m1->type, m2->type);
				diff = true;
			} else if (bit_off1 != bit_off2 || bit_sz1 != bit_sz2) {
				print("F#%d FNAME '%s': BITOFF %d BITSZ %d != BITOFF %d BITSZ %d\n",
					i, fn1, bit_off1, bit_sz1, bit_off2, bit_sz2);
				diff = true;
			}
		}
		break;
	}
	case BTF_KIND_ENUM: {
				    /*
		const struct btf_enum *v = btf_enum(t);

		printf(" size=%u vlen=%u", t->size, vlen);
		for (i = 0; i < vlen; i++, v++) {
			printf("\n\t'%s' val=%u",
					btf_str(btf, v->name_off), v->val);
		}
		*/
		break;
	}
	case BTF_KIND_FWD:
		//printf(" fwd_kind=%s", btf_kflag(t) ? "union" : "struct");
		break;
	case BTF_KIND_FUNC:
		//printf(" type_id=%u linkage=%s", t->type, btf_func_linkage_str(t));
		break;
	case BTF_KIND_FUNC_PROTO: {
					  /*
		const struct btf_param *p = btf_params(t);

		printf(" ret_type_id=%u vlen=%u", t->type, vlen);
		for (i = 0; i < vlen; i++, p++) {
			printf("\n\t'%s' type_id=%u",
					btf_str(btf, p->name_off), p->type);
		}
		*/
		break;
	}
	case BTF_KIND_VAR:
				  /*
		printf(" type_id=%u, linkage=%s",
				t->type, btf_var_linkage_str(btf_var(t)->linkage));
				*/
		break;
	case BTF_KIND_DATASEC: {
				       /*
		const struct btf_var_secinfo *v = btf_var_secinfos(t);

		printf(" size=%u vlen=%u", t->size, vlen);
		for (i = 0; i < vlen; i++, v++) {
			printf("\n\ttype_id=%u offset=%u size=%u",
					v->type, v->offset, v->size);
		}
		*/
		break;
	}
	default:
		printf("UNKN KIND: IDS %d %d NAME '%s': KIND %d\n",
			id1, id2, name1, kind1);
		break;
	}

out:
	depth--;
	if (diff)
		return -EINVAL;
	return 0;
}


int main(int argc, char **argv)
{
	struct btf *btf;
	const char *btf_path;
	int id1, id2;

	libbpf_set_print(libbpf_print_fn);

	btf_path = argv[1];
	id1 = strtol(argv[2], NULL, 0);
	id2 = strtol(argv[3], NULL, 0);

	printf("path %s id1 %d id2 %d\n", btf_path, id1, id2);

	btf = btf__parse(btf_path, NULL);

	vis = calloc(btf__type_cnt(btf) + 10, sizeof(*vis));

	btfdiff(btf, id1, id2);


	return 0;
}
