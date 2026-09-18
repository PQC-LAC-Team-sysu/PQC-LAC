/*
 * This library provides encoding/decoding of binary
 * Bose-Chaudhuri-Hocquenghem (BCH) codes.
 *
 * Call init_bch to get a pointer to a newly allocated bch_control structure for
 * the given m (Galois field order), t (error correction capability) and
 * (optional) primitive polynomial parameters.
 *
 * Call encode_bch to compute and store ecc parity bytes to a given buffer.
 * Call decode_bch to detect and locate errors in received data.
 * Algorithmic details:
 *
 * Encoding is performed by processing 32 input bits in parallel, using 4
 * remainder lookup tables.
 *
 * The final stage of decoding involves the following internal steps:
 * a. Syndrome computation
 * b. Error locator polynomial computation using Berlekamp-Massey algorithm
 * c. Error locator root finding (by far the most expensive step)
 *
 
 */

# include <errno.h>
# include <stdint.h>
# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include "bch.h"
# include "ecc.h"
#if defined(LAC_LIGHT)
#include "bch-light.h"
#elif defined(LAC128)
#include "bch128.h"
#elif defined(LAC192)
#include "bch192.h"
#elif defined(LAC256)
#include "bch256.h"
#endif
static inline uint32_t cpu_to_be32(uint32_t x)
{
	return ((x & 0x000000ffu) << 24)
		 | ((x & 0x0000ff00u) <<  8)
		 | ((x & 0x00ff0000u) >>  8)
		 | ((x & 0xff000000u) >> 24);
}

/*
 * same as encode_bch(), but process input data one byte at a time
 */
static void encode_bch_unaligned(struct bch_control *bch,
				 const unsigned char *data, unsigned int len,
				 uint32_t *ecc)
{
	int i;
	const uint32_t *p;
	const int l = BCH_ECC_WORDS(bch)-1;

	while (len--) {
		p = bch->mod8_tab + (l+1)*(((ecc[0] >> 24)^(*data++)) & 0xff);

		for (i = 0; i < l; i++)
			ecc[i] = ((ecc[i] << 8)|(ecc[i+1] >> 24))^(*p++);

		ecc[l] = (ecc[l] << 8)^(*p);
	}
}

/*
 * convert ecc bytes to aligned, zero-padded 32-bit ecc words
 */
static void load_ecc8(struct bch_control *bch, uint32_t *dst,
		      const uint8_t *src)
{
	uint8_t pad[4] = {0, 0, 0, 0};
	unsigned int i, nwords = BCH_ECC_WORDS(bch)-1;

	for (i = 0; i < nwords; i++, src += 4)
		dst[i] = (src[0] << 24)|(src[1] << 16)|(src[2] << 8)|src[3];

	memcpy(pad, src, BCH_ECC_BYTES(bch)-4*nwords);
	dst[nwords] = (pad[0] << 24)|(pad[1] << 16)|(pad[2] << 8)|pad[3];
}

/*
 * convert 32-bit ecc words to ecc bytes
 */
static void store_ecc8(struct bch_control *bch, uint8_t *dst,
		       const uint32_t *src)
{
	uint8_t pad[4];
	unsigned int i, nwords = BCH_ECC_WORDS(bch)-1;

	for (i = 0; i < nwords; i++) {
		*dst++ = (src[i] >> 24);
		*dst++ = (src[i] >> 16) & 0xff;
		*dst++ = (src[i] >>  8) & 0xff;
		*dst++ = (src[i] >>  0) & 0xff;
	}
	pad[0] = (src[nwords] >> 24);
	pad[1] = (src[nwords] >> 16) & 0xff;
	pad[2] = (src[nwords] >>  8) & 0xff;
	pad[3] = (src[nwords] >>  0) & 0xff;
	memcpy(dst, pad, BCH_ECC_BYTES(bch)-4*nwords);
}

/**
 * encode_bch - calculate BCH ecc parity of data
 * @bch:   BCH control structure
 * @data:  data to encode
 * @len:   data length in bytes
 * @ecc:   ecc parity data, must be initialized by caller
 *
 * The @ecc parity array is used both as input and output parameter, in order to
 * allow incremental computations. It should be of the size indicated by member
 * @ecc_bytes of @bch, and should be initialized to 0 before the first call.
 *
 * The exact number of computed ecc parity bits is given by member @ecc_bits of
 * @bch; it may be less than m*t for large values of t.
 */
void encode_bch(struct bch_control *bch, const uint8_t *data,
		unsigned int len, uint8_t *ecc)
{
	const unsigned int l = BCH_ECC_WORDS(bch)-1;
	unsigned int i, mlen;
	unsigned long m;
	uint32_t w, r[ECC_LEN/4+1];
	const uint32_t * const tab0 = bch->mod8_tab;
	const uint32_t * const tab1 = tab0 + 256*(l+1);
	const uint32_t * const tab2 = tab1 + 256*(l+1);
	const uint32_t * const tab3 = tab2 + 256*(l+1);
	const uint32_t *pdata, *p0, *p1, *p2, *p3;

	if (ecc) {
		/* load ecc parity bytes into internal 32-bit buffer */
		load_ecc8(bch, bch->ecc_buf, ecc);
	} else {
		memset(bch->ecc_buf, 0, sizeof(r));
	}

	/* process first unaligned data bytes */
	m = ((uintptr_t)data) & 3;
	if (m) {
		mlen = (len < (4-m)) ? len : 4-m;
		encode_bch_unaligned(bch, data, mlen, bch->ecc_buf);
		data += mlen;
		len  -= mlen;
	}

	/* process 32-bit aligned data words */
	pdata = (uint32_t *)data;
	mlen  = len/4;
	data += 4*mlen;
	len  -= 4*mlen;
	memcpy(r, bch->ecc_buf, sizeof(r));

	/*
	 * split each 32-bit word into 4 polynomials of weight 8 as follows:
	 *
	 * 31 ...24  23 ...16  15 ... 8  7 ... 0
	 * xxxxxxxx  yyyyyyyy  zzzzzzzz  tttttttt
	 *                               tttttttt  mod g = r0 (precomputed)
	 *                     zzzzzzzz  00000000  mod g = r1 (precomputed)
	 *           yyyyyyyy  00000000  00000000  mod g = r2 (precomputed)
	 * xxxxxxxx  00000000  00000000  00000000  mod g = r3 (precomputed)
	 * xxxxxxxx  yyyyyyyy  zzzzzzzz  tttttttt  mod g = r0^r1^r2^r3
	 */
	while (mlen--) {
		/* input data is read in big-endian format */
		w = r[0]^cpu_to_be32(*pdata++);
		p0 = tab0 + (l+1)*((w >>  0) & 0xff);
		p1 = tab1 + (l+1)*((w >>  8) & 0xff);
		p2 = tab2 + (l+1)*((w >> 16) & 0xff);
		p3 = tab3 + (l+1)*((w >> 24) & 0xff);

		for (i = 0; i < l; i++)
			r[i] = r[i+1]^p0[i]^p1[i]^p2[i]^p3[i];

		r[l] = p0[l]^p1[l]^p2[l]^p3[l];
	}
	memcpy(bch->ecc_buf, r, sizeof(r));

	/* process last unaligned bytes */
	if (len)
		encode_bch_unaligned(bch, data, len, bch->ecc_buf);

	/* store ecc parity bytes into original parity buffer */
	if (ecc)
		store_ecc8(bch, ecc, bch->ecc_buf);
}



/*
 * shorter and faster modulo function, only works when v < 2N.
 */
static inline int mod_s(struct bch_control *bch, unsigned int v)
{
	
	const unsigned int n = GF_N(bch);
	unsigned int tmp;
	tmp=(v<n)?0x0:0xffffffff;
	
	return v-(n&tmp);
}

/* Galois field basic operations: multiply, divide, inverse, etc. */

static inline unsigned int gf_mul(struct bch_control *bch, unsigned int a,
				  unsigned int b)
{
	unsigned int tmp,mask;
	
	tmp=bch->a_pow_tab[mod_s(bch, bch->a_log_tab[a]+bch->a_log_tab[b])];
	mask=(a && b)? 0xffffffff:0x0;
	
	return  tmp&mask;
}

static inline unsigned int gf_sqr(struct bch_control *bch, unsigned int a)
{
	unsigned int tmp,mask;
	
	tmp=bch->a_pow_tab[mod_s(bch, 2*bch->a_log_tab[a])];
	mask=(a)? 0xffffffff:0x0;
	
	return tmp&mask;
}

static inline int a_log(struct bch_control *bch, unsigned int x)
{
	return bch->a_log_tab[x];
}


/*
 * compute 2t syndromes of ecc polynomial, i.e. ecc(a^j) for j=1..2t
 */
static void compute_syndromes(struct bch_control *bch, uint32_t *ecc,
			      unsigned int *syn)
{
	int i, j, s;
	unsigned int m;
	uint32_t poly,mask_syn,syn_tmp;
	const int t = GF_T(bch);
	unsigned int w,w2,mask_w;

	s = bch->ecc_bits;
	/* make sure extra bits in last ecc word are cleared */
	m = ((unsigned int)s) & 31;
	if (m)
		ecc[s/32] &= ~((1u << (32-m))-1);
	memset(syn, 0, 2*t*sizeof(*syn));

	/* compute v(a^j) for j=1 .. 2t-1 */
	do {
		poly = *ecc++;
		s -= 32;
		
		for(i=31;i>=0 && i+s>=0;i--)
		{
			mask_syn=((poly>>i)&0x1)?0xffffffff:0x0;
			w=i+s;
			w2=w*2;
			for (j = 0; j < 2*t; j += 2)
			{
				syn_tmp=bch->a_pow_tab[w];
				syn[j] ^= (syn_tmp&mask_syn);
				w+=w2;
				mask_w=(w<bch->n)?0x0 : 0xffffffff;
				w-=(bch->n & mask_w);
			}
		}
	} while (s > 0);

	/* v(a^(2j)) = v(a^j)^2 */
	for (j = 0; j < t; j++)
		syn[2*j+1] = gf_sqr(bch, syn[j]);
}

static void gf_poly_copy(struct gf_poly *dst, struct gf_poly *src, int t)
{
	memcpy(dst, src, GF_POLY_SZ(t));
}

static int compute_error_locator_polynomial(struct bch_control *bch,
					    const unsigned int *syn)
{
	const unsigned int t = GF_T(bch);
	const unsigned int n = GF_N(bch);
	unsigned int i, j, tmp, l, pd = 1, d = syn[0];
	struct gf_poly *elp = bch->elp;
	struct gf_poly *pelp = bch->poly_2t[0];
	struct gf_poly *elp_copy = bch->poly_2t[1];
	int k, pp = -1;
	uint16_t mask_d,mask_pelp;
	unsigned int mask_tmp,mask_deg,tmp_c,mask_tmp2;

	memset(pelp, 0, GF_POLY_SZ(2*t));
	memset(elp, 0, GF_POLY_SZ(2*t));

	pelp->deg = 0;
	pelp->c[0] = 1;
	elp->deg = 0;
	elp->c[0] = 1;

	/* use simplified binary Berlekamp-Massey algorithm */
	for (i = 0; i < t ; i++) 
	{
		mask_d=(d?0xffff:0x0);
		k = 2*i-pp;
			
		gf_poly_copy(elp_copy, elp,i);
			// e[i+1](X) = e[i](X)+di*dp^-1*X^2(i-p)*e[p](X) 
		tmp = mod_s(bch,a_log(bch, d)+n-a_log(bch, pd));

		for (j = 0; j <=i ; j++) 
		{
			mask_deg=((j <= pelp->deg)?0xffffffff:0x0);
			mask_pelp=(pelp->c[j]? 0xffff:0x0);
			l = mod_s(bch,tmp+a_log(bch, pelp->c[j]));
			tmp_c=bch->a_pow_tab[l];
			elp->c[j+k] ^= (tmp_c&mask_d&mask_pelp&mask_deg);
		}
		// compute l[i+1] = max(l[i]->c[l[p]+2*(i-p]) 
		tmp = pelp->deg+(k&mask_d);
		mask_tmp =((tmp > elp->deg)?0xffffffff:0x0);
		mask_tmp2=((tmp > elp->deg)?0x0:0xffffffff);
		//memcpy cause 70 cycles gap
		if (tmp > elp->deg) 
		{
			gf_poly_copy(pelp, elp_copy,i);
			elp->deg = tmp;
		
		}
		else //just for constant time
		{
			gf_poly_copy(elp_copy, elp,i);
			tmp =  elp->deg;
		}
		//update according to mask_tmp	
		pd = (d & mask_tmp)^(pd &mask_tmp2);
		pp = ((2*i) & mask_tmp)^(pp &mask_tmp2);
			
		// di+1 = S(2i+3)+elp[i+1].1*S(2i+2)+...+elp[i+1].lS(2i+3-l) 
		unsigned int mask_j,tmp_d;
		if (i < t-1) 
		{
			d = syn[2*i+2];
			
			for (j = 1; j <=i+1 ; j++)
			{
				mask_j=(j <= elp->deg)?0xffffffff:0x00;
				tmp_d=gf_mul(bch, elp->c[j], syn[2*i+2-j]);
				d ^= (tmp_d&mask_j);
			}
		}
		
		
	}

	return (elp->deg > t) ? -1 : (int)elp->deg;
}

/*
 * build monic, log-based representation of a polynomial
 */
static void init_rep(struct bch_control *bch,
			   const struct gf_poly *a, uint16_t *rep, uint16_t *syn_mask, unsigned int pow_start)
{
	int i,w;
	w=pow_start;
	for (i = 1; i <= bch->t; i++)
	{
		rep[i] =  mod_s(bch, a_log(bch, a->c[i])+ w);
		w=mod_s(bch,w+pow_start);
	    syn_mask[i]=(a->c[i] ? 0xFFFF : 0x0);
	}
}

/*
 * exhaustive root search (Chien) implementation - not used, included only for
 * reference/comparison tests
 */
static int chien_search(struct bch_control *bch, unsigned int len,
			struct gf_poly *p, unsigned int *roots)
{
	
	unsigned int i, j, syn, count = 0;
	unsigned int k = 8*len+bch->ecc_bits;
	unsigned int bound=GF_N(bch)-bch->ecc_bits;
	uint16_t     syn_mask[MAX_ERROR+1],syn_rep[MAX_ERROR+1];
	unsigned int syn_tmp;
	
	//use a log-based representation of polynomial 
	init_rep(bch,p,syn_rep,syn_mask,GF_N(bch)-k);
	
	for (i = GF_N(bch)-k+1; i <= bound; i++) 
	{
		// compute elp(a^i) 
		syn = p->c[0];
		for (j = 1 ; j <= bch->t; j++) 
		{
			syn_rep[j]=mod_s(bch,syn_rep[j]+j);
			syn_tmp=bch->a_pow_tab[syn_rep[j]];
			syn ^= (syn_tmp&syn_mask[j]);
		}
		roots[count] = GF_N(bch)-i;
		count+=(syn==0);
	}
	
	return count;
}

/**
 * decode_bch - decode received codeword and find bit error locations
 * @bch:      BCH control structure
 * @data:     received data, ignored if @calc_ecc is provided
 * @len:      data length in bytes, must always be provided
 * @recv_ecc: received ecc, if NULL then assume it was XORed in @calc_ecc
 *
 * Returns:
 *  The number of errors found, or -EBADMSG if decoding failed, or -EINVAL if
 *  invalid parameters were provided
 */
int decode_bch(struct bch_control *bch, const uint8_t *data, unsigned int len,
	       const uint8_t *recv_ecc, const uint8_t *calc_ecc,
	       const unsigned int *syn, unsigned int *errloc)
{
	const unsigned int ecc_words = BCH_ECC_WORDS(bch);
	unsigned int nbits;
	int i, err ,t=bch->t;

	/* sanity check: make sure data length can be handled */
	if (8*len > (bch->n-bch->ecc_bits))
		return -EINVAL;
	//check data and ecc pointer
    if (!data || !recv_ecc)
		return -EINVAL;
		
	/* compute received data ecc into an internal buffer */
	encode_bch(bch, data, len, NULL);
	/* load received ecc  */
	load_ecc8(bch, bch->ecc_buf2, recv_ecc);
	/* XOR received and calculated ecc */
	for (i = 0; i < (int)ecc_words; i++) 
	{
		bch->ecc_buf[i] ^= bch->ecc_buf2[i];
	}
	
	//compute syndromes
	compute_syndromes(bch, bch->ecc_buf, bch->syn);
    //compute error locator polynomial
	compute_error_locator_polynomial(bch, bch->syn);
	//find roots
	err=chien_search(bch, len, bch->elp, errloc);

	//post process error location
	nbits = (len*8)+bch->ecc_bits;
	
	unsigned char mask_err;
	
	for (i = 0; i < t; i++) 
	{
		mask_err  = (i<err)? 0xff: 0x00;
		errloc[i] = (nbits-1-errloc[i])&mask_err;
		errloc[i] = ((errloc[i] & ~7)|(7-(errloc[i] & 7)))&mask_err;
	}

	return err;
}


