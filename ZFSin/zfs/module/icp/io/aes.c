/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * AES provider for the Kernel Cryptographic Framework (KCF)
 */

#include <sys/zfs_context.h>
#include <sys/crypto/common.h>
#include <sys/crypto/impl.h>
#include <sys/crypto/spi.h>
#include <sys/crypto/icp.h>
#include <modes/modes.h>
#include <sys/modctl.h>
#define	_AES_IMPL
#include <aes/aes_impl.h>
#include <immintrin.h>
#ifdef _WIN32
#include <sys/kstat_windows.h>
#endif

#define	CRYPTO_PROVIDER_NAME "aes"

extern struct mod_ops mod_cryptoops;
int cpu_avx_supported = 0;

/*
 * Module linkage information for the kernel.
 */
static struct modlcrypto modlcrypto = {
	&mod_cryptoops,
	"AES Kernel SW Provider"
};

static struct modlinkage modlinkage = {
	MODREV_1, { (void *)&modlcrypto, NULL }
};


/*
 * The following definitions are to keep EXPORT_SRC happy.
 */
#ifndef AES_MIN_KEY_BYTES
#define	AES_MIN_KEY_BYTES		0
#endif

#ifndef AES_MAX_KEY_BYTES
#define	AES_MAX_KEY_BYTES		0
#endif

/*
 * Mechanism info structure passed to KCF during registration.
 */
static crypto_mech_info_t aes_mech_info_tab[] = {
	/* AES_ECB */
	{SUN_CKM_AES_ECB, AES_ECB_MECH_INFO_TYPE,
	    CRYPTO_FG_ENCRYPT | CRYPTO_FG_ENCRYPT_ATOMIC |
	    CRYPTO_FG_DECRYPT | CRYPTO_FG_DECRYPT_ATOMIC,
	    AES_MIN_KEY_BYTES, AES_MAX_KEY_BYTES, CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	/* AES_CBC */
	{SUN_CKM_AES_CBC, AES_CBC_MECH_INFO_TYPE,
	    CRYPTO_FG_ENCRYPT | CRYPTO_FG_ENCRYPT_ATOMIC |
	    CRYPTO_FG_DECRYPT | CRYPTO_FG_DECRYPT_ATOMIC,
	    AES_MIN_KEY_BYTES, AES_MAX_KEY_BYTES, CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	/* AES_CTR */
	{SUN_CKM_AES_CTR, AES_CTR_MECH_INFO_TYPE,
	    CRYPTO_FG_ENCRYPT | CRYPTO_FG_ENCRYPT_ATOMIC |
	    CRYPTO_FG_DECRYPT | CRYPTO_FG_DECRYPT_ATOMIC,
	    AES_MIN_KEY_BYTES, AES_MAX_KEY_BYTES, CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	/* AES_CCM */
	{SUN_CKM_AES_CCM, AES_CCM_MECH_INFO_TYPE,
	    CRYPTO_FG_ENCRYPT | CRYPTO_FG_ENCRYPT_ATOMIC |
	    CRYPTO_FG_DECRYPT | CRYPTO_FG_DECRYPT_ATOMIC,
	    AES_MIN_KEY_BYTES, AES_MAX_KEY_BYTES, CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	/* AES_GCM */
	{SUN_CKM_AES_GCM, AES_GCM_MECH_INFO_TYPE,
	    CRYPTO_FG_ENCRYPT | CRYPTO_FG_ENCRYPT_ATOMIC |
	    CRYPTO_FG_DECRYPT | CRYPTO_FG_DECRYPT_ATOMIC,
	    AES_MIN_KEY_BYTES, AES_MAX_KEY_BYTES, CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	/* AES_GMAC */
	{SUN_CKM_AES_GMAC, AES_GMAC_MECH_INFO_TYPE,
	    CRYPTO_FG_ENCRYPT | CRYPTO_FG_ENCRYPT_ATOMIC |
	    CRYPTO_FG_DECRYPT | CRYPTO_FG_DECRYPT_ATOMIC |
	    CRYPTO_FG_MAC | CRYPTO_FG_MAC_ATOMIC |
	    CRYPTO_FG_SIGN | CRYPTO_FG_SIGN_ATOMIC |
	    CRYPTO_FG_VERIFY | CRYPTO_FG_VERIFY_ATOMIC,
	    AES_MIN_KEY_BYTES, AES_MAX_KEY_BYTES, CRYPTO_KEYSIZE_UNIT_IN_BYTES}
};

/* operations are in-place if the output buffer is NULL */
#define	AES_ARG_INPLACE(input, output)				\
	if ((output) == NULL)					\
		(output) = (input);

static void aes_provider_status(crypto_provider_handle_t, uint_t *);

static crypto_control_ops_t aes_control_ops = {
	aes_provider_status
};

static int aes_encrypt_init(crypto_ctx_t *, crypto_mechanism_t *,
    crypto_key_t *, crypto_spi_ctx_template_t, crypto_req_handle_t);
static int aes_decrypt_init(crypto_ctx_t *, crypto_mechanism_t *,
    crypto_key_t *, crypto_spi_ctx_template_t, crypto_req_handle_t);
static int aes_common_init(crypto_ctx_t *, crypto_mechanism_t *,
    crypto_key_t *, crypto_spi_ctx_template_t, crypto_req_handle_t, boolean_t);
static int aes_common_init_ctx(aes_ctx_t *, crypto_spi_ctx_template_t *,
    crypto_mechanism_t *, crypto_key_t *, int, boolean_t);
static int aes_encrypt_final(crypto_ctx_t *, crypto_data_t *,
    crypto_req_handle_t);
static int aes_decrypt_final(crypto_ctx_t *, crypto_data_t *,
    crypto_req_handle_t);

static int aes_encrypt(crypto_ctx_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t);
static int aes_encrypt_update(crypto_ctx_t *, crypto_data_t *,
    crypto_data_t *, crypto_req_handle_t);
static int aes_encrypt_atomic(crypto_provider_handle_t, crypto_session_id_t,
    crypto_mechanism_t *, crypto_key_t *, crypto_data_t *,
    crypto_data_t *, crypto_spi_ctx_template_t, crypto_req_handle_t);

static int aes_decrypt(crypto_ctx_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t);
static int aes_decrypt_update(crypto_ctx_t *, crypto_data_t *,
    crypto_data_t *, crypto_req_handle_t);
static int aes_decrypt_atomic(crypto_provider_handle_t, crypto_session_id_t,
    crypto_mechanism_t *, crypto_key_t *, crypto_data_t *,
    crypto_data_t *, crypto_spi_ctx_template_t, crypto_req_handle_t);


static int aes_create_ctx_template(crypto_provider_handle_t,
    crypto_mechanism_t *, crypto_key_t *, crypto_spi_ctx_template_t *,
    size_t *, crypto_req_handle_t);
static int aes_free_context(crypto_ctx_t *);

int crypto_update_uio_avx(boolean_t encrypt, void *ctx, crypto_data_t *input, crypto_data_t *output);

static int aes_init_ctx_avx(aes_ctx_t *aes_ctx, crypto_mechanism_t *mechanism,
	crypto_key_t *key);
int
gcm_crypt_final_avx(boolean_t encrypt, gcm_ctx_avx_t *gcm_ctx, crypto_data_t *out);
static int
aes_decrypt_atomic_avx(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_data_t *ciphertext, crypto_data_t *plaintext,
    crypto_spi_ctx_template_t template, crypto_req_handle_t req);
static int
aes_encrypt_atomic_avx(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_data_t *plaintext, crypto_data_t *ciphertext,
    crypto_spi_ctx_template_t template, crypto_req_handle_t req);
extern void aes_keyexp_256(uint8_t* key, uint8_t *ekey, uint8_t *tkey);
extern void aes_gcm_precomp_256(struct gcm_key_data *data);
int cpu_supports_avx();


static crypto_cipher_ops_t aes_cipher_ops = {
	aes_encrypt_init,
	aes_encrypt,
	aes_encrypt_update,
	aes_encrypt_final,
	aes_encrypt_atomic,
	aes_decrypt_init,
	aes_decrypt,
	aes_decrypt_update,
	aes_decrypt_final,
	aes_decrypt_atomic
};

static int aes_mac_atomic(crypto_provider_handle_t, crypto_session_id_t,
    crypto_mechanism_t *, crypto_key_t *, crypto_data_t *, crypto_data_t *,
    crypto_spi_ctx_template_t, crypto_req_handle_t);
static int aes_mac_verify_atomic(crypto_provider_handle_t, crypto_session_id_t,
    crypto_mechanism_t *, crypto_key_t *, crypto_data_t *, crypto_data_t *,
    crypto_spi_ctx_template_t, crypto_req_handle_t);

static crypto_mac_ops_t aes_mac_ops = {
	NULL,
	NULL,
	NULL,
	NULL,
	aes_mac_atomic,
	aes_mac_verify_atomic
};

static int aes_create_ctx_template(crypto_provider_handle_t,
    crypto_mechanism_t *, crypto_key_t *, crypto_spi_ctx_template_t *,
    size_t *, crypto_req_handle_t);
static int aes_free_context(crypto_ctx_t *);

static crypto_ctx_ops_t aes_ctx_ops = {
	aes_create_ctx_template,
	aes_free_context
};

static crypto_ops_t aes_crypto_ops = {{{{{
	&aes_control_ops,
	NULL,
	&aes_cipher_ops,
	&aes_mac_ops,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	&aes_ctx_ops
}}}}};

static crypto_provider_info_t aes_prov_info = {{{{
	CRYPTO_SPI_VERSION_1,
	"AES Software Provider",
	CRYPTO_SW_PROVIDER,
	NULL,
	&aes_crypto_ops,
	sizeof (aes_mech_info_tab)/sizeof (crypto_mech_info_t),
	aes_mech_info_tab
}}}};

static crypto_kcf_provider_handle_t aes_prov_handle = 0;
static crypto_data_t null_crypto_data = { CRYPTO_DATA_RAW };

int
aes_mod_init(void)
{
	int ret;

	if ((ret = mod_install(&modlinkage)) != 0)
		return (ret);

	/* Register with KCF.  If the registration fails, remove the module. */
	if (crypto_register_provider(&aes_prov_info, &aes_prov_handle)) {
		(void) mod_remove(&modlinkage);
		return (EACCES);
	}
	cpu_avx_supported = cpu_supports_avx();
	return (0);
}

int
aes_mod_fini(void)
{
	/* Unregister from KCF if module is registered */
	if (aes_prov_handle != 0) {
		if (crypto_unregister_provider(aes_prov_handle))
			return (EBUSY);

		aes_prov_handle = 0;
	}

	return (mod_remove(&modlinkage));
}

static int
aes_check_mech_param(crypto_mechanism_t *mechanism, aes_ctx_t **ctx, int kmflag)
{
	void *p = NULL;
	boolean_t param_required = B_TRUE;
	size_t param_len;
	void *(*alloc_fun)(int);
	int rv = CRYPTO_SUCCESS;

	switch (mechanism->cm_type) {
	case AES_ECB_MECH_INFO_TYPE:
		param_required = B_FALSE;
		alloc_fun = ecb_alloc_ctx;
		break;
	case AES_CBC_MECH_INFO_TYPE:
		param_len = AES_BLOCK_LEN;
		alloc_fun = cbc_alloc_ctx;
		break;
	case AES_CTR_MECH_INFO_TYPE:
		param_len = sizeof (CK_AES_CTR_PARAMS);
		alloc_fun = ctr_alloc_ctx;
		break;
	case AES_CCM_MECH_INFO_TYPE:
		param_len = sizeof (CK_AES_CCM_PARAMS);
		alloc_fun = ccm_alloc_ctx;
		break;
	case AES_GCM_MECH_INFO_TYPE:
		param_len = sizeof (CK_AES_GCM_PARAMS);
		alloc_fun = gcm_alloc_ctx;
		break;
	case AES_GMAC_MECH_INFO_TYPE:
		param_len = sizeof (CK_AES_GMAC_PARAMS);
		alloc_fun = gmac_alloc_ctx;
		break;
	default:
		rv = CRYPTO_MECHANISM_INVALID;
		return (rv);
	}
	if (param_required && mechanism->cm_param != NULL &&
	    mechanism->cm_param_len != param_len) {
		rv = CRYPTO_MECHANISM_PARAM_INVALID;
	}
	if (ctx != NULL) {
		p = (alloc_fun)(kmflag);
		*ctx = p;
	}
	return (rv);
}

/*
 * Initialize key schedules for AES
 */
static int
init_keysched(crypto_key_t *key, void *newbie)
{
	/*
	 * Only keys by value are supported by this module.
	 */
	switch (key->ck_format) {
	case CRYPTO_KEY_RAW:
		if (key->ck_length < AES_MINBITS ||
		    key->ck_length > AES_MAXBITS) {
			return (CRYPTO_KEY_SIZE_RANGE);
		}

		/* key length must be either 128, 192, or 256 */
		if ((key->ck_length & 63) != 0)
			return (CRYPTO_KEY_SIZE_RANGE);
		break;
	default:
		return (CRYPTO_KEY_TYPE_INCONSISTENT);
	}

	aes_init_keysched(key->ck_data, key->ck_length, newbie);
	return (CRYPTO_SUCCESS);
}

/*
 * KCF software provider control entry points.
 */
/* ARGSUSED */
static void
aes_provider_status(crypto_provider_handle_t provider, uint_t *status)
{
	*status = CRYPTO_PROVIDER_READY;
}

static int
aes_encrypt_init(crypto_ctx_t *ctx, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_spi_ctx_template_t template,
    crypto_req_handle_t req) {
	return (aes_common_init(ctx, mechanism, key, template, req, B_TRUE));
}

static int
aes_decrypt_init(crypto_ctx_t *ctx, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_spi_ctx_template_t template,
    crypto_req_handle_t req) {
	return (aes_common_init(ctx, mechanism, key, template, req, B_FALSE));
}



/*
 * KCF software provider encrypt entry points.
 */
static int
aes_common_init(crypto_ctx_t *ctx, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_spi_ctx_template_t template,
    crypto_req_handle_t req, boolean_t is_encrypt_init)
{
	aes_ctx_t *aes_ctx;
	int rv;
	int kmflag;

	/*
	 * Only keys by value are supported by this module.
	 */
	if (key->ck_format != CRYPTO_KEY_RAW) {
		return (CRYPTO_KEY_TYPE_INCONSISTENT);
	}

	kmflag = crypto_kmflag(req);
	if ((rv = aes_check_mech_param(mechanism, &aes_ctx, kmflag))
	    != CRYPTO_SUCCESS)
		return (rv);

	rv = aes_common_init_ctx(aes_ctx, template, mechanism, key, kmflag,
	    is_encrypt_init);
	if (rv != CRYPTO_SUCCESS) {
		crypto_free_mode_ctx(aes_ctx);
		return (rv);
	}

	ctx->cc_provider_private = aes_ctx;

	return (CRYPTO_SUCCESS);
}

static void
aes_copy_block64(uint8_t *in, uint64_t *out)
{
	if (IS_P2ALIGNED(in, sizeof (uint64_t))) {
		/* LINTED: pointer alignment */
		out[0] = *(uint64_t *)&in[0];
		/* LINTED: pointer alignment */
		out[1] = *(uint64_t *)&in[8];
	} else {
		uint8_t *iv8 = (uint8_t *)&out[0];

		AES_COPY_BLOCK(in, iv8);
	}
}


static int
aes_encrypt(crypto_ctx_t *ctx, crypto_data_t *plaintext,
    crypto_data_t *ciphertext, crypto_req_handle_t req)
{
	int ret = CRYPTO_FAILED;

	aes_ctx_t *aes_ctx;
	size_t saved_length, saved_offset, length_needed;

	ASSERT(ctx->cc_provider_private != NULL);
	aes_ctx = ctx->cc_provider_private;

	/*
	 * For block ciphers, plaintext must be a multiple of AES block size.
	 * This test is only valid for ciphers whose blocksize is a power of 2.
	 */
	if (((aes_ctx->ac_flags & (CTR_MODE|CCM_MODE|GCM_MODE|GMAC_MODE))
	    == 0) && (plaintext->cd_length & (AES_BLOCK_LEN - 1)) != 0)
		return (CRYPTO_DATA_LEN_RANGE);

	AES_ARG_INPLACE(plaintext, ciphertext);

	/*
	 * We need to just return the length needed to store the output.
	 * We should not destroy the context for the following case.
	 */
	switch (aes_ctx->ac_flags & (CCM_MODE|GCM_MODE|GMAC_MODE)) {
	case CCM_MODE:
		length_needed = plaintext->cd_length + aes_ctx->ac_mac_len;
		break;
	case GCM_MODE:
		length_needed = plaintext->cd_length + aes_ctx->ac_tag_len;
		break;
	case GMAC_MODE:
		if (plaintext->cd_length != 0)
			return (CRYPTO_ARGUMENTS_BAD);

		length_needed = aes_ctx->ac_tag_len;
		break;
	default:
		length_needed = plaintext->cd_length;
	}

	if (ciphertext->cd_length < length_needed) {
		ciphertext->cd_length = length_needed;
		return (CRYPTO_BUFFER_TOO_SMALL);
	}

	saved_length = ciphertext->cd_length;
	saved_offset = ciphertext->cd_offset;

	/*
	 * Do an update on the specified input data.
	 */
	ret = aes_encrypt_update(ctx, plaintext, ciphertext, req);
	if (ret != CRYPTO_SUCCESS) {
		return (ret);
	}

	/*
	 * For CCM mode, aes_ccm_encrypt_final() will take care of any
	 * left-over unprocessed data, and compute the MAC
	 */
	if (aes_ctx->ac_flags & CCM_MODE) {
		/*
		 * ccm_encrypt_final() will compute the MAC and append
		 * it to existing ciphertext. So, need to adjust the left over
		 * length value accordingly
		 */

		/* order of following 2 lines MUST not be reversed */
		ciphertext->cd_offset = ciphertext->cd_length;
		ciphertext->cd_length = saved_length - ciphertext->cd_length;
		ret = ccm_encrypt_final((ccm_ctx_t *)aes_ctx, ciphertext,
		    AES_BLOCK_LEN, aes_encrypt_block, aes_xor_block);
		if (ret != CRYPTO_SUCCESS) {
			return (ret);
		}

		if (plaintext != ciphertext) {
			ciphertext->cd_length =
			    ciphertext->cd_offset - saved_offset;
		}
		ciphertext->cd_offset = saved_offset;
	} else if (aes_ctx->ac_flags & (GCM_MODE|GMAC_MODE)) {
		/*
		 * gcm_encrypt_final() will compute the MAC and append
		 * it to existing ciphertext. So, need to adjust the left over
		 * length value accordingly
		 */

		/* order of following 2 lines MUST not be reversed */
		ciphertext->cd_offset = ciphertext->cd_length;
		ciphertext->cd_length = saved_length - ciphertext->cd_length;
		ret = gcm_encrypt_final((gcm_ctx_t *)aes_ctx, ciphertext,
		    AES_BLOCK_LEN, aes_encrypt_block, aes_copy_block,
		    aes_xor_block);
		if (ret != CRYPTO_SUCCESS) {
			return (ret);
		}

		if (plaintext != ciphertext) {
			ciphertext->cd_length =
			    ciphertext->cd_offset - saved_offset;
		}
		ciphertext->cd_offset = saved_offset;
	}

	ASSERT(aes_ctx->ac_remainder_len == 0);
	(void) aes_free_context(ctx);

	return (ret);
}


static int
aes_decrypt(crypto_ctx_t *ctx, crypto_data_t *ciphertext,
    crypto_data_t *plaintext, crypto_req_handle_t req)
{
	int ret = CRYPTO_FAILED;

	aes_ctx_t *aes_ctx;
	off_t saved_offset;
	size_t saved_length, length_needed;

	ASSERT(ctx->cc_provider_private != NULL);
	aes_ctx = ctx->cc_provider_private;

	/*
	 * For block ciphers, plaintext must be a multiple of AES block size.
	 * This test is only valid for ciphers whose blocksize is a power of 2.
	 */
	if (((aes_ctx->ac_flags & (CTR_MODE|CCM_MODE|GCM_MODE|GMAC_MODE))
	    == 0) && (ciphertext->cd_length & (AES_BLOCK_LEN - 1)) != 0) {
		return (CRYPTO_ENCRYPTED_DATA_LEN_RANGE);
	}

	AES_ARG_INPLACE(ciphertext, plaintext);

	/*
	 * Return length needed to store the output.
	 * Do not destroy context when plaintext buffer is too small.
	 *
	 * CCM:  plaintext is MAC len smaller than cipher text
	 * GCM:  plaintext is TAG len smaller than cipher text
	 * GMAC: plaintext length must be zero
	 */
	switch (aes_ctx->ac_flags & (CCM_MODE|GCM_MODE|GMAC_MODE)) {
	case CCM_MODE:
		length_needed = aes_ctx->ac_processed_data_len;
		break;
	case GCM_MODE:
		length_needed = ciphertext->cd_length - aes_ctx->ac_tag_len;
		break;
	case GMAC_MODE:
		if (plaintext->cd_length != 0)
			return (CRYPTO_ARGUMENTS_BAD);

		length_needed = 0;
		break;
	default:
		length_needed = ciphertext->cd_length;
	}

	if (plaintext->cd_length < length_needed) {
		plaintext->cd_length = length_needed;
		return (CRYPTO_BUFFER_TOO_SMALL);
	}

	saved_offset = plaintext->cd_offset;
	saved_length = plaintext->cd_length;

	/*
	 * Do an update on the specified input data.
	 */
	ret = aes_decrypt_update(ctx, ciphertext, plaintext, req);
	if (ret != CRYPTO_SUCCESS) {
		goto cleanup;
	}

	if (aes_ctx->ac_flags & CCM_MODE) {
		ASSERT(aes_ctx->ac_processed_data_len == aes_ctx->ac_data_len);
		ASSERT(aes_ctx->ac_processed_mac_len == aes_ctx->ac_mac_len);

		/* order of following 2 lines MUST not be reversed */
		plaintext->cd_offset = plaintext->cd_length;
		plaintext->cd_length = saved_length - plaintext->cd_length;

		ret = ccm_decrypt_final((ccm_ctx_t *)aes_ctx, plaintext,
		    AES_BLOCK_LEN, aes_encrypt_block, aes_copy_block,
		    aes_xor_block);
		if (ret == CRYPTO_SUCCESS) {
			if (plaintext != ciphertext) {
				plaintext->cd_length =
				    plaintext->cd_offset - saved_offset;
			}
		} else {
			plaintext->cd_length = saved_length;
		}

		plaintext->cd_offset = saved_offset;
	} else if (aes_ctx->ac_flags & (GCM_MODE|GMAC_MODE)) {
		/* order of following 2 lines MUST not be reversed */
		plaintext->cd_offset = plaintext->cd_length;
		plaintext->cd_length = saved_length - plaintext->cd_length;

		ret = gcm_decrypt_final((gcm_ctx_t *)aes_ctx, plaintext,
		    AES_BLOCK_LEN, aes_encrypt_block, aes_xor_block);
		if (ret == CRYPTO_SUCCESS) {
			if (plaintext != ciphertext) {
				plaintext->cd_length =
				    plaintext->cd_offset - saved_offset;
			}
		} else {
			plaintext->cd_length = saved_length;
		}

		plaintext->cd_offset = saved_offset;
	}

	ASSERT(aes_ctx->ac_remainder_len == 0);

cleanup:
	(void) aes_free_context(ctx);

	return (ret);
}


/* ARGSUSED */
static int
aes_encrypt_update(crypto_ctx_t *ctx, crypto_data_t *plaintext,
    crypto_data_t *ciphertext, crypto_req_handle_t req)
{
	off_t saved_offset;
	size_t saved_length, out_len;
	int ret = CRYPTO_SUCCESS;
	aes_ctx_t *aes_ctx;

	ASSERT(ctx->cc_provider_private != NULL);
	aes_ctx = ctx->cc_provider_private;

	AES_ARG_INPLACE(plaintext, ciphertext);

	/* compute number of bytes that will hold the ciphertext */
	out_len = aes_ctx->ac_remainder_len;
	out_len += plaintext->cd_length;
	out_len &= ~(AES_BLOCK_LEN - 1);

	/* return length needed to store the output */
	if (ciphertext->cd_length < out_len) {
		ciphertext->cd_length = out_len;
		return (CRYPTO_BUFFER_TOO_SMALL);
	}

	saved_offset = ciphertext->cd_offset;
	saved_length = ciphertext->cd_length;

	/*
	 * Do the AES update on the specified input data.
	 */
	switch (plaintext->cd_format) {
	case CRYPTO_DATA_RAW:
		ret = crypto_update_iov(ctx->cc_provider_private,
		    (crypto_data_t *)plaintext, 
			ciphertext, 
			aes_encrypt_contiguous_blocks,
		    aes_copy_block64);
		break;
	case CRYPTO_DATA_UIO:
		ret = crypto_update_uio(ctx->cc_provider_private,
		    plaintext, ciphertext, aes_encrypt_contiguous_blocks,
		    aes_copy_block64);
		break;
	default:
		ret = CRYPTO_ARGUMENTS_BAD;
	}

	/*
	 * Since AES counter mode is a stream cipher, we call
	 * ctr_mode_final() to pick up any remaining bytes.
	 * It is an internal function that does not destroy
	 * the context like *normal* final routines.
	 */
	if ((aes_ctx->ac_flags & CTR_MODE) && (aes_ctx->ac_remainder_len > 0)) {
		ret = ctr_mode_final((ctr_ctx_t *)aes_ctx,
		    ciphertext, aes_encrypt_block);
	}

	if (ret == CRYPTO_SUCCESS) {
		if (plaintext != ciphertext)
			ciphertext->cd_length =
			    ciphertext->cd_offset - saved_offset;
	} else {
		ciphertext->cd_length = saved_length;
	}
	ciphertext->cd_offset = saved_offset;

	return (ret);
}


static int
aes_decrypt_update(crypto_ctx_t *ctx, crypto_data_t *ciphertext,
    crypto_data_t *plaintext, crypto_req_handle_t req)
{
	off_t saved_offset;
	size_t saved_length, out_len;
	int ret = CRYPTO_SUCCESS;
	aes_ctx_t *aes_ctx;

	ASSERT(ctx->cc_provider_private != NULL);
	aes_ctx = ctx->cc_provider_private;

	AES_ARG_INPLACE(ciphertext, plaintext);

	/*
	 * Compute number of bytes that will hold the plaintext.
	 * This is not necessary for CCM, GCM, and GMAC since these
	 * mechanisms never return plaintext for update operations.
	 */
	if ((aes_ctx->ac_flags & (CCM_MODE|GCM_MODE|GMAC_MODE)) == 0) {
		out_len = aes_ctx->ac_remainder_len;
		out_len += ciphertext->cd_length;
		out_len &= ~(AES_BLOCK_LEN - 1);

		/* return length needed to store the output */
		if (plaintext->cd_length < out_len) {
			plaintext->cd_length = out_len;
			return (CRYPTO_BUFFER_TOO_SMALL);
		}
	}

	saved_offset = plaintext->cd_offset;
	saved_length = plaintext->cd_length;

	if (aes_ctx->ac_flags & (GCM_MODE|GMAC_MODE))
		gcm_set_kmflag((gcm_ctx_t *)aes_ctx, crypto_kmflag(req));

	/*
	 * Do the AES update on the specified input data.
	 */
	switch (ciphertext->cd_format) {
	case CRYPTO_DATA_RAW:
		ret = crypto_update_iov(ctx->cc_provider_private,
		    ciphertext, plaintext, aes_decrypt_contiguous_blocks,
		    aes_copy_block64);
		break;
	case CRYPTO_DATA_UIO:
		ret = crypto_update_uio(ctx->cc_provider_private,
		    ciphertext, plaintext, aes_decrypt_contiguous_blocks,
		    aes_copy_block64);
		break;
	default:
		ret = CRYPTO_ARGUMENTS_BAD;
	}

	/*
	 * Since AES counter mode is a stream cipher, we call
	 * ctr_mode_final() to pick up any remaining bytes.
	 * It is an internal function that does not destroy
	 * the context like *normal* final routines.
	 */
	if ((aes_ctx->ac_flags & CTR_MODE) && (aes_ctx->ac_remainder_len > 0)) {
		ret = ctr_mode_final((ctr_ctx_t *)aes_ctx, plaintext,
		    aes_encrypt_block);
		if (ret == CRYPTO_DATA_LEN_RANGE)
			ret = CRYPTO_ENCRYPTED_DATA_LEN_RANGE;
	}

	if (ret == CRYPTO_SUCCESS) {
		if (ciphertext != plaintext)
			plaintext->cd_length =
			    plaintext->cd_offset - saved_offset;
	} else {
		plaintext->cd_length = saved_length;
	}
	plaintext->cd_offset = saved_offset;


	return (ret);
}

/* ARGSUSED */
static int
aes_encrypt_final(crypto_ctx_t *ctx, crypto_data_t *data,
    crypto_req_handle_t req)
{
	aes_ctx_t *aes_ctx;
	int ret;

	ASSERT(ctx->cc_provider_private != NULL);
	aes_ctx = ctx->cc_provider_private;

	if (data->cd_format != CRYPTO_DATA_RAW &&
	    data->cd_format != CRYPTO_DATA_UIO) {
		return (CRYPTO_ARGUMENTS_BAD);
	}

	if (aes_ctx->ac_flags & CTR_MODE) {
		if (aes_ctx->ac_remainder_len > 0) {
			ret = ctr_mode_final((ctr_ctx_t *)aes_ctx, data,
			    aes_encrypt_block);
			if (ret != CRYPTO_SUCCESS)
				return (ret);
		}
	} else if (aes_ctx->ac_flags & CCM_MODE) {
		ret = ccm_encrypt_final((ccm_ctx_t *)aes_ctx, data,
		    AES_BLOCK_LEN, aes_encrypt_block, aes_xor_block);
		if (ret != CRYPTO_SUCCESS) {
			return (ret);
		}
	} else if (aes_ctx->ac_flags & (GCM_MODE|GMAC_MODE)) {
		size_t saved_offset = data->cd_offset;

		ret = gcm_encrypt_final((gcm_ctx_t *)aes_ctx, data,
		    AES_BLOCK_LEN, aes_encrypt_block, aes_copy_block,
		    aes_xor_block);
		if (ret != CRYPTO_SUCCESS) {
			return (ret);
		}
		data->cd_length = data->cd_offset - saved_offset;
		data->cd_offset = saved_offset;
	} else {
		/*
		 * There must be no unprocessed plaintext.
		 * This happens if the length of the last data is
		 * not a multiple of the AES block length.
		 */
		if (aes_ctx->ac_remainder_len > 0) {
			return (CRYPTO_DATA_LEN_RANGE);
		}
		data->cd_length = 0;
	}

	(void) aes_free_context(ctx);

	return (CRYPTO_SUCCESS);
}

/* ARGSUSED */
static int
aes_decrypt_final(crypto_ctx_t *ctx, crypto_data_t *data,
    crypto_req_handle_t req)
{
	aes_ctx_t *aes_ctx;
	int ret;
	off_t saved_offset;
	size_t saved_length;

	ASSERT(ctx->cc_provider_private != NULL);
	aes_ctx = ctx->cc_provider_private;

	if (data->cd_format != CRYPTO_DATA_RAW &&
	    data->cd_format != CRYPTO_DATA_UIO) {
		return (CRYPTO_ARGUMENTS_BAD);
	}

	/*
	 * There must be no unprocessed ciphertext.
	 * This happens if the length of the last ciphertext is
	 * not a multiple of the AES block length.
	 */
	if (aes_ctx->ac_remainder_len > 0) {
		if ((aes_ctx->ac_flags & CTR_MODE) == 0)
			return (CRYPTO_ENCRYPTED_DATA_LEN_RANGE);
		else {
			ret = ctr_mode_final((ctr_ctx_t *)aes_ctx, data,
			    aes_encrypt_block);
			if (ret == CRYPTO_DATA_LEN_RANGE)
				ret = CRYPTO_ENCRYPTED_DATA_LEN_RANGE;
			if (ret != CRYPTO_SUCCESS)
				return (ret);
		}
	}

	if (aes_ctx->ac_flags & CCM_MODE) {
		/*
		 * This is where all the plaintext is returned, make sure
		 * the plaintext buffer is big enough
		 */
		size_t pt_len = aes_ctx->ac_data_len;
		if (data->cd_length < pt_len) {
			data->cd_length = pt_len;
			return (CRYPTO_BUFFER_TOO_SMALL);
		}

		ASSERT(aes_ctx->ac_processed_data_len == pt_len);
		ASSERT(aes_ctx->ac_processed_mac_len == aes_ctx->ac_mac_len);
		saved_offset = data->cd_offset;
		saved_length = data->cd_length;
		ret = ccm_decrypt_final((ccm_ctx_t *)aes_ctx, data,
		    AES_BLOCK_LEN, aes_encrypt_block, aes_copy_block,
		    aes_xor_block);
		if (ret == CRYPTO_SUCCESS) {
			data->cd_length = data->cd_offset - saved_offset;
		} else {
			data->cd_length = saved_length;
		}

		data->cd_offset = saved_offset;
		if (ret != CRYPTO_SUCCESS) {
			return (ret);
		}
	} else if (aes_ctx->ac_flags & (GCM_MODE|GMAC_MODE)) {
		/*
		 * This is where all the plaintext is returned, make sure
		 * the plaintext buffer is big enough
		 */
		gcm_ctx_t *ctx = (gcm_ctx_t *)aes_ctx;
		size_t pt_len = ctx->gcm_processed_data_len - ctx->gcm_tag_len;

		if (data->cd_length < pt_len) {
			data->cd_length = pt_len;
			return (CRYPTO_BUFFER_TOO_SMALL);
		}

		saved_offset = data->cd_offset;
		saved_length = data->cd_length;
		ret = gcm_decrypt_final((gcm_ctx_t *)aes_ctx, data,
		    AES_BLOCK_LEN, aes_encrypt_block, aes_xor_block);
		if (ret == CRYPTO_SUCCESS) {
			data->cd_length = data->cd_offset - saved_offset;
		} else {
			data->cd_length = saved_length;
		}

		data->cd_offset = saved_offset;
		if (ret != CRYPTO_SUCCESS) {
			return (ret);
		}
	}


	if ((aes_ctx->ac_flags & (CTR_MODE|CCM_MODE|GCM_MODE|GMAC_MODE)) == 0) {
		data->cd_length = 0;
	}

	(void) aes_free_context(ctx);

	return (CRYPTO_SUCCESS);
}

/* ARGSUSED */
static int
aes_encrypt_atomic(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_data_t *plaintext, crypto_data_t *ciphertext,
    crypto_spi_ctx_template_t template, crypto_req_handle_t req)
{
	if(cpu_avx_supported && mechanism->cm_type == AES_GCM_MECH_INFO_TYPE) {
		return(aes_encrypt_atomic_avx(provider, session_id, mechanism,
			key, plaintext, ciphertext, template, req));
	}
	aes_ctx_t aes_ctx;	/* on the stack */
	off_t saved_offset;
	size_t saved_length;
	size_t length_needed;
	int ret;

	AES_ARG_INPLACE(plaintext, ciphertext);

	/*
	 * CTR, CCM, GCM, and GMAC modes do not require that plaintext
	 * be a multiple of AES block size.
	 */
	switch (mechanism->cm_type) {
	case AES_CTR_MECH_INFO_TYPE:
	case AES_CCM_MECH_INFO_TYPE:
	case AES_GCM_MECH_INFO_TYPE:
	case AES_GMAC_MECH_INFO_TYPE:
		break;
	default:
		if ((plaintext->cd_length & (AES_BLOCK_LEN - 1)) != 0)
			return (CRYPTO_DATA_LEN_RANGE);
	}

	if ((ret = aes_check_mech_param(mechanism, NULL, 0)) != CRYPTO_SUCCESS)
		return (ret);

	bzero(&aes_ctx, sizeof (aes_ctx_t));

	ret = aes_common_init_ctx(&aes_ctx, template, mechanism, key,
	    crypto_kmflag(req), B_TRUE);
	if (ret != CRYPTO_SUCCESS)
		return (ret);
	switch (mechanism->cm_type) {
	case AES_CCM_MECH_INFO_TYPE:
		length_needed = plaintext->cd_length + aes_ctx.ac_mac_len;
		break;
	case AES_GMAC_MECH_INFO_TYPE:
		if (plaintext->cd_length != 0)
			return (CRYPTO_ARGUMENTS_BAD);
		/* FALLTHRU */
	case AES_GCM_MECH_INFO_TYPE:
		length_needed = plaintext->cd_length + aes_ctx.ac_tag_len;
		break;
	default:
		length_needed = plaintext->cd_length;
	}

	/* return size of buffer needed to store output */
	if (ciphertext->cd_length < length_needed) {
		ciphertext->cd_length = length_needed;
		ret = CRYPTO_BUFFER_TOO_SMALL;
		goto out;
	}

	saved_offset = ciphertext->cd_offset;
	saved_length = ciphertext->cd_length;

	/*
	 * Do an update on the specified input data.
	 */
	switch (plaintext->cd_format) {
	case CRYPTO_DATA_RAW:
		ret = crypto_update_iov(&aes_ctx, plaintext, ciphertext,
		    aes_encrypt_contiguous_blocks, aes_copy_block64);
		break;
	case CRYPTO_DATA_UIO:
		ret = crypto_update_uio(&aes_ctx, plaintext, ciphertext,
		    aes_encrypt_contiguous_blocks, aes_copy_block64);
		break;
	default:
		ret = CRYPTO_ARGUMENTS_BAD;
	}

	if (ret == CRYPTO_SUCCESS) {
		if (mechanism->cm_type == AES_CCM_MECH_INFO_TYPE) {
			ret = ccm_encrypt_final((ccm_ctx_t *)&aes_ctx,
			    ciphertext, AES_BLOCK_LEN, aes_encrypt_block,
			    aes_xor_block);
			if (ret != CRYPTO_SUCCESS)
				goto out;
			ASSERT(aes_ctx.ac_remainder_len == 0);
		} else if (mechanism->cm_type == AES_GCM_MECH_INFO_TYPE ||
		    mechanism->cm_type == AES_GMAC_MECH_INFO_TYPE) {
			ret = gcm_encrypt_final((gcm_ctx_t *)&aes_ctx,
			    ciphertext, AES_BLOCK_LEN, aes_encrypt_block,
			    aes_copy_block, aes_xor_block);
			if (ret != CRYPTO_SUCCESS)
				goto out;
			ASSERT(aes_ctx.ac_remainder_len == 0);
		} else if (mechanism->cm_type == AES_CTR_MECH_INFO_TYPE) {
			if (aes_ctx.ac_remainder_len > 0) {
				ret = ctr_mode_final((ctr_ctx_t *)&aes_ctx,
				    ciphertext, aes_encrypt_block);
				if (ret != CRYPTO_SUCCESS)
					goto out;
			}
		} else {
			ASSERT(aes_ctx.ac_remainder_len == 0);
		}

		if (plaintext != ciphertext) {
			ciphertext->cd_length =
			    ciphertext->cd_offset - saved_offset;
		}
	} else {
		ciphertext->cd_length = saved_length;
	}
	ciphertext->cd_offset = saved_offset;

out:
	if (aes_ctx.ac_flags & PROVIDER_OWNS_KEY_SCHEDULE) {
		bzero(aes_ctx.ac_keysched, aes_ctx.ac_keysched_len);
		kmem_free(aes_ctx.ac_keysched, aes_ctx.ac_keysched_len);
	}

	return (ret);
}

/* ARGSUSED */
static int
aes_decrypt_atomic(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_data_t *ciphertext, crypto_data_t *plaintext,
    crypto_spi_ctx_template_t template, crypto_req_handle_t req)
{
	if(cpu_avx_supported && mechanism->cm_type == AES_GCM_MECH_INFO_TYPE) {
		return(aes_decrypt_atomic_avx(provider, session_id, mechanism,
			key, ciphertext, plaintext, template, req));
	}
	aes_ctx_t aes_ctx;	/* on the stack */
	off_t saved_offset;
	size_t saved_length;
	size_t length_needed;
	int ret;

	AES_ARG_INPLACE(ciphertext, plaintext);

	/*
	 * CCM, GCM, CTR, and GMAC modes do not require that ciphertext
	 * be a multiple of AES block size.
	 */
	switch (mechanism->cm_type) {
	case AES_CTR_MECH_INFO_TYPE:
	case AES_CCM_MECH_INFO_TYPE:
	case AES_GCM_MECH_INFO_TYPE:
	case AES_GMAC_MECH_INFO_TYPE:
		break;
	default:
		if ((ciphertext->cd_length & (AES_BLOCK_LEN - 1)) != 0)
			return (CRYPTO_ENCRYPTED_DATA_LEN_RANGE);
	}

	if ((ret = aes_check_mech_param(mechanism, NULL, 0)) != CRYPTO_SUCCESS)
		return (ret);

	bzero(&aes_ctx, sizeof (aes_ctx_t));

	ret = aes_common_init_ctx(&aes_ctx, template, mechanism, key,
	    crypto_kmflag(req), B_FALSE);
	if (ret != CRYPTO_SUCCESS)
		return (ret);
	switch (mechanism->cm_type) {
	case AES_CCM_MECH_INFO_TYPE:
		length_needed = aes_ctx.ac_data_len;
		break;
	case AES_GCM_MECH_INFO_TYPE:
		length_needed = ciphertext->cd_length - aes_ctx.ac_tag_len;
		break;
	case AES_GMAC_MECH_INFO_TYPE:
		if (plaintext->cd_length != 0)
			return (CRYPTO_ARGUMENTS_BAD);
		length_needed = 0;
		break;
	default:
		length_needed = ciphertext->cd_length;
	}

	/* return size of buffer needed to store output */
	if (plaintext->cd_length < length_needed) {
		plaintext->cd_length = length_needed;
		ret = CRYPTO_BUFFER_TOO_SMALL;
		goto out;
	}

	saved_offset = plaintext->cd_offset;
	saved_length = plaintext->cd_length;

	if (mechanism->cm_type == AES_GCM_MECH_INFO_TYPE ||
	    mechanism->cm_type == AES_GMAC_MECH_INFO_TYPE)
		gcm_set_kmflag((gcm_ctx_t *)&aes_ctx, crypto_kmflag(req));

	/*
	 * Do an update on the specified input data.
	 */
	switch (ciphertext->cd_format) {
	case CRYPTO_DATA_RAW:
		ret = crypto_update_iov(&aes_ctx, ciphertext, plaintext,
		    aes_decrypt_contiguous_blocks, aes_copy_block64);
		break;
	case CRYPTO_DATA_UIO:
		ret = crypto_update_uio(&aes_ctx, ciphertext, plaintext,
		    aes_decrypt_contiguous_blocks, aes_copy_block64);
		break;
	default:
		ret = CRYPTO_ARGUMENTS_BAD;
	}

	if (ret == CRYPTO_SUCCESS) {
		if (mechanism->cm_type == AES_CCM_MECH_INFO_TYPE) {
			ASSERT(aes_ctx.ac_processed_data_len
			    == aes_ctx.ac_data_len);
			ASSERT(aes_ctx.ac_processed_mac_len
			    == aes_ctx.ac_mac_len);
			ret = ccm_decrypt_final((ccm_ctx_t *)&aes_ctx,
			    plaintext, AES_BLOCK_LEN, aes_encrypt_block,
			    aes_copy_block, aes_xor_block);
			ASSERT(aes_ctx.ac_remainder_len == 0);
			if ((ret == CRYPTO_SUCCESS) &&
			    (ciphertext != plaintext)) {
				plaintext->cd_length =
				    plaintext->cd_offset - saved_offset;
			} else {
				plaintext->cd_length = saved_length;
			}
		} else if (mechanism->cm_type == AES_GCM_MECH_INFO_TYPE ||
		    mechanism->cm_type == AES_GMAC_MECH_INFO_TYPE) {
			ret = gcm_decrypt_final((gcm_ctx_t *)&aes_ctx,
			    plaintext, AES_BLOCK_LEN, aes_encrypt_block,
			    aes_xor_block);
			ASSERT(aes_ctx.ac_remainder_len == 0);
			if ((ret == CRYPTO_SUCCESS) &&
			    (ciphertext != plaintext)) {
				plaintext->cd_length =
				    plaintext->cd_offset - saved_offset;
			} else {
				plaintext->cd_length = saved_length;
			}
		} else if (mechanism->cm_type != AES_CTR_MECH_INFO_TYPE) {
			ASSERT(aes_ctx.ac_remainder_len == 0);
			if (ciphertext != plaintext)
				plaintext->cd_length =
				    plaintext->cd_offset - saved_offset;
		} else {
			if (aes_ctx.ac_remainder_len > 0) {
				ret = ctr_mode_final((ctr_ctx_t *)&aes_ctx,
				    plaintext, aes_encrypt_block);
				if (ret == CRYPTO_DATA_LEN_RANGE)
					ret = CRYPTO_ENCRYPTED_DATA_LEN_RANGE;
				if (ret != CRYPTO_SUCCESS)
					goto out;
			}
			if (ciphertext != plaintext)
				plaintext->cd_length =
				    plaintext->cd_offset - saved_offset;
		}
	} else {
		plaintext->cd_length = saved_length;
	}
	plaintext->cd_offset = saved_offset;

out:
	if (aes_ctx.ac_flags & PROVIDER_OWNS_KEY_SCHEDULE) {
		bzero(aes_ctx.ac_keysched, aes_ctx.ac_keysched_len);
		kmem_free(aes_ctx.ac_keysched, aes_ctx.ac_keysched_len);
	}

	if (aes_ctx.ac_flags & CCM_MODE) {
		if (aes_ctx.ac_pt_buf != NULL) {
			kmem_free(aes_ctx.ac_pt_buf, aes_ctx.ac_data_len);
		}
	} else if (aes_ctx.ac_flags & (GCM_MODE|GMAC_MODE)) {
		if (((gcm_ctx_t *)&aes_ctx)->gcm_pt_buf != NULL) {
			kmem_free(((gcm_ctx_t *)&aes_ctx)->gcm_pt_buf,
			    ((gcm_ctx_t *)&aes_ctx)->gcm_pt_buf_len);
		}
	}

	return (ret);
}

/*
 * KCF software provider context template entry points.
 */
/* ARGSUSED */
static int
aes_create_ctx_template(crypto_provider_handle_t provider,
    crypto_mechanism_t *mechanism, crypto_key_t *key,
    crypto_spi_ctx_template_t *tmpl, size_t *tmpl_size, crypto_req_handle_t req)
{
	void *keysched;
	size_t size;
	int rv;

	if (mechanism->cm_type != AES_ECB_MECH_INFO_TYPE &&
	    mechanism->cm_type != AES_CBC_MECH_INFO_TYPE &&
	    mechanism->cm_type != AES_CTR_MECH_INFO_TYPE &&
	    mechanism->cm_type != AES_CCM_MECH_INFO_TYPE &&
	    mechanism->cm_type != AES_GCM_MECH_INFO_TYPE &&
	    mechanism->cm_type != AES_GMAC_MECH_INFO_TYPE)
		return (CRYPTO_MECHANISM_INVALID);

	if ((keysched = aes_alloc_keysched(&size,
	    crypto_kmflag(req))) == NULL) {
		return (CRYPTO_HOST_MEMORY);
	}

	/*
	 * Initialize key schedule.  Key length information is stored
	 * in the key.
	 */
	if ((rv = init_keysched(key, keysched)) != CRYPTO_SUCCESS) {
		bzero(keysched, size);
		kmem_free(keysched, size);
		return (rv);
	}

	*tmpl = keysched;
	*tmpl_size = size;

	return (CRYPTO_SUCCESS);
}


static int
aes_free_context(crypto_ctx_t *ctx)
{
	aes_ctx_t *aes_ctx = ctx->cc_provider_private;

	if (aes_ctx != NULL) {
		if (aes_ctx->ac_flags & PROVIDER_OWNS_KEY_SCHEDULE) {
			ASSERT(aes_ctx->ac_keysched_len != 0);
			bzero(aes_ctx->ac_keysched, aes_ctx->ac_keysched_len);
			kmem_free(aes_ctx->ac_keysched,
			    aes_ctx->ac_keysched_len);
		}
		crypto_free_mode_ctx(aes_ctx);
		ctx->cc_provider_private = NULL;
	}

	return (CRYPTO_SUCCESS);
}


static int
aes_common_init_ctx(aes_ctx_t *aes_ctx, crypto_spi_ctx_template_t *template,
    crypto_mechanism_t *mechanism, crypto_key_t *key, int kmflag,
    boolean_t is_encrypt_init)
{
	int rv = CRYPTO_SUCCESS;
	void *keysched;
	size_t size;

	if (template == NULL) {
		if ((keysched = aes_alloc_keysched(&size, kmflag)) == NULL)
			return (CRYPTO_HOST_MEMORY);
		/*
		 * Initialize key schedule.
		 * Key length is stored in the key.
		 */
		if ((rv = init_keysched(key, keysched)) != CRYPTO_SUCCESS) {
			kmem_free(keysched, size);
			return (rv);
		}

		aes_ctx->ac_flags |= PROVIDER_OWNS_KEY_SCHEDULE;
		aes_ctx->ac_keysched_len = size;
	} else {
		keysched = template;
	}
	aes_ctx->ac_keysched = keysched;

	switch (mechanism->cm_type) {
	case AES_CBC_MECH_INFO_TYPE:
		rv = cbc_init_ctx((cbc_ctx_t *)aes_ctx, mechanism->cm_param,
		    mechanism->cm_param_len, AES_BLOCK_LEN, aes_copy_block64);
		break;
	case AES_CTR_MECH_INFO_TYPE: {
		CK_AES_CTR_PARAMS *pp;

		if (mechanism->cm_param == NULL ||
		    mechanism->cm_param_len != sizeof (CK_AES_CTR_PARAMS)) {
			return (CRYPTO_MECHANISM_PARAM_INVALID);
		}
		pp = (CK_AES_CTR_PARAMS *)(void *)mechanism->cm_param;
		rv = ctr_init_ctx((ctr_ctx_t *)aes_ctx, pp->ulCounterBits,
		    pp->cb, aes_copy_block);
		break;
	}
	case AES_CCM_MECH_INFO_TYPE:
		if (mechanism->cm_param == NULL ||
		    mechanism->cm_param_len != sizeof (CK_AES_CCM_PARAMS)) {
			return (CRYPTO_MECHANISM_PARAM_INVALID);
		}
		rv = ccm_init_ctx((ccm_ctx_t *)aes_ctx, mechanism->cm_param,
		    kmflag, is_encrypt_init, AES_BLOCK_LEN, aes_encrypt_block,
		    aes_xor_block);
		break;
	case AES_GCM_MECH_INFO_TYPE:
		if (mechanism->cm_param == NULL ||
		    mechanism->cm_param_len != sizeof (CK_AES_GCM_PARAMS)) {
			return (CRYPTO_MECHANISM_PARAM_INVALID);
		}
		rv = gcm_init_ctx((gcm_ctx_t *)aes_ctx, mechanism->cm_param,
		    AES_BLOCK_LEN, aes_encrypt_block, aes_copy_block,
		    aes_xor_block);
		break;
	case AES_GMAC_MECH_INFO_TYPE:
		if (mechanism->cm_param == NULL ||
		    mechanism->cm_param_len != sizeof (CK_AES_GMAC_PARAMS)) {
			return (CRYPTO_MECHANISM_PARAM_INVALID);
		}
		rv = gmac_init_ctx((gcm_ctx_t *)aes_ctx, mechanism->cm_param,
		    AES_BLOCK_LEN, aes_encrypt_block, aes_copy_block,
		    aes_xor_block);
		break;
	case AES_ECB_MECH_INFO_TYPE:
		aes_ctx->ac_flags |= ECB_MODE;
	}

	if (rv != CRYPTO_SUCCESS) {
		if (aes_ctx->ac_flags & PROVIDER_OWNS_KEY_SCHEDULE) {
			bzero(keysched, size);
			kmem_free(keysched, size);
		}
	}

	return (rv);
}

static int
process_gmac_mech(crypto_mechanism_t *mech, crypto_data_t *data,
    CK_AES_GCM_PARAMS *gcm_params)
{
	/* LINTED: pointer alignment */
	CK_AES_GMAC_PARAMS *params = (CK_AES_GMAC_PARAMS *)mech->cm_param;

	if (mech->cm_type != AES_GMAC_MECH_INFO_TYPE)
		return (CRYPTO_MECHANISM_INVALID);

	if (mech->cm_param_len != sizeof (CK_AES_GMAC_PARAMS))
		return (CRYPTO_MECHANISM_PARAM_INVALID);

	if (params->pIv == NULL)
		return (CRYPTO_MECHANISM_PARAM_INVALID);

	gcm_params->pIv = params->pIv;
	gcm_params->ulIvLen = AES_GMAC_IV_LEN;
	gcm_params->ulTagBits = AES_GMAC_TAG_BITS;

	if (data == NULL)
		return (CRYPTO_SUCCESS);

	if (data->cd_format != CRYPTO_DATA_RAW)
		return (CRYPTO_ARGUMENTS_BAD);

	gcm_params->pAAD = (uchar_t *)data->cd_raw.iov_base;
	gcm_params->ulAADLen = data->cd_length;
	return (CRYPTO_SUCCESS);
}

static int
aes_mac_atomic(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_data_t *data, crypto_data_t *mac,
    crypto_spi_ctx_template_t template, crypto_req_handle_t req)
{
	CK_AES_GCM_PARAMS gcm_params;
	crypto_mechanism_t gcm_mech;
	int rv;

	if ((rv = process_gmac_mech(mechanism, data, &gcm_params))
	    != CRYPTO_SUCCESS)
		return (rv);

	gcm_mech.cm_type = AES_GCM_MECH_INFO_TYPE;
	gcm_mech.cm_param_len = sizeof (CK_AES_GCM_PARAMS);
	gcm_mech.cm_param = (char *)&gcm_params;

	return (aes_encrypt_atomic(provider, session_id, &gcm_mech,
	    key, &null_crypto_data, mac, template, req));
}

static int
aes_mac_verify_atomic(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_data_t *data, crypto_data_t *mac,
    crypto_spi_ctx_template_t template, crypto_req_handle_t req)
{
	CK_AES_GCM_PARAMS gcm_params;
	crypto_mechanism_t gcm_mech;
	int rv;

	if ((rv = process_gmac_mech(mechanism, data, &gcm_params))
	    != CRYPTO_SUCCESS)
		return (rv);

	gcm_mech.cm_type = AES_GCM_MECH_INFO_TYPE;
	gcm_mech.cm_param_len = sizeof (CK_AES_GCM_PARAMS);
	gcm_mech.cm_param = (char *)&gcm_params;

	return (aes_decrypt_atomic(provider, session_id, &gcm_mech,
	    key, mac, &null_crypto_data, template, req));
}

int
crypto_update_uio_avx(avx_crypt_type_t encrypt, void *ctx, crypto_data_t *input,
	crypto_data_t *output)
{
	common_ctx_t *common_ctx = ctx;
	uio_t *uiop = input->cd_uio;
	uio_t *ciop = output->cd_uio;
	off_t offset = input->cd_offset;
	size_t length = input->cd_length;
	uint_t vec_idx;
	size_t cur_len;
	user_addr_t iov_base = 0ULL, ciov_base = 0ULL;
	user_size_t iov_len, ciov_len;
	void *iov_or_mp;
	gcm_ctx_avx_t *gcm = (gcm_ctx_avx_t *)ctx;

	if (input->cd_miscdata != NULL) {
		aes_copy_block64((uint8_t *)input->cd_miscdata,
		    &common_ctx->cc_iv[0]);
	}

	if (uio_isuserspace(uiop)) {
		return (CRYPTO_ARGUMENTS_BAD);
	}

	/*
	 * Jump to the first iovec containing data to be
	 * processed.
	 */
	for (vec_idx = 0;
		 !uio_getiov(uiop, vec_idx, NULL, &iov_len) &&
			 vec_idx < uio_iovcnt(uiop) &&
			 offset >= iov_len;
		 offset -= iov_len, vec_idx++)
		;

	if (vec_idx == uio_iovcnt(uiop) && length > 0) {
		/*
		 * The caller specified an offset that is larger than
		 * the total size of the buffers it provided.
		 */
		return (CRYPTO_DATA_LEN_RANGE);
	}

	/*
	 * Now process the iovecs.
	 */

	while (vec_idx < uio_iovcnt(uiop) && length > 0) {

		VERIFY(uio_getiov(uiop, vec_idx, &iov_base, &iov_len) == 0);

		cur_len = MIN(iov_len - offset, length);

		if (encrypt) {
			VERIFY(uio_getiov(ciop, vec_idx, &ciov_base, &ciov_len) == 0);
			VERIFY(iov_len == ciov_len);
			aes_gcm_enc_256_update(&gcm->gkey, &gcm->gctx,
				(uint8_t *)((uint64_t)(ciov_base)+offset),
				(const uint8_t *)((uint64_t)(iov_base)+offset), cur_len);
		}
		else {
			if(uio_getiov(ciop, vec_idx, &ciov_base, &ciov_len) == 0) {
				VERIFY(iov_len == ciov_len);
				aes_gcm_dec_256_update(&gcm->gkey, &gcm->gctx,
					(uint8_t *)((uint64_t)(ciov_base)+offset),
					(const uint8_t *)((uint64_t)(iov_base)+offset),
					cur_len);
			}
		}

		length -= cur_len;
		vec_idx++;
		offset = 0;
	}

	if (vec_idx == uio_iovcnt(uiop) && length > 0) {
		/*
		 * The end of the specified iovec's was reached but
		 * the length requested could not be processed, i.e.
		 * The caller requested to digest more data than it provided.
		 */

		return (CRYPTO_DATA_LEN_RANGE);
	}

	return (CRYPTO_SUCCESS);


	return (0);
}

void aes_gcm_pre_256(const void* key, struct gcm_key_data* key_data)
{
	uint8_t tmp_exp_key[GCM_ENC_KEY_LEN * GCM_KEY_SETS];
	aes_keyexp_256((uint8_t*)key, (uint8_t*)key_data->expanded_keys, tmp_exp_key);
	aes_gcm_precomp_256(key_data);
}

static int
aes_init_ctx_avx(aes_ctx_t *aes_ctx, crypto_mechanism_t *mechanism,
		crypto_key_t *key)
{
	CK_AES_GCM_PARAMS *gcm_param;
	gcm_param = (CK_AES_GCM_PARAMS *)(void *)mechanism->cm_param;
	gcm_ctx_avx_t *gcm = (gcm_ctx_avx_t *)aes_ctx;
	aes_gcm_pre_256(key->ck_data, &gcm->gkey);
	aes_gcm_init_256(&gcm->gkey, &gcm->gctx, gcm_param->pIv, gcm_param->pAAD, gcm_param->ulAADLen);

	return (0);
}

int
gcm_crypt_final_avx(avx_crypt_type_t encrypt, gcm_ctx_avx_t *gcm_ctx, crypto_data_t *out)
{
	user_addr_t mac;
	uint8_t omac[TAG_SIZE];
	uint64_t maclen;
	uint8_t *tag;
	int ret = CRYPTO_SUCCESS;

	uio_t *cuio = out->cd_uio;
	uio_getiov(cuio, uio_iovcnt(cuio) - 1, &mac, &maclen);
	tag = (uint8_t *)mac;

	VERIFY(maclen <= TAG_SIZE);
	if(encrypt) {
		aes_gcm_enc_256_finalize(&gcm_ctx->gkey, &gcm_ctx->gctx, tag, maclen);
	} else {
		aes_gcm_dec_256_finalize(&gcm_ctx->gkey, &gcm_ctx->gctx, (uint8_t*) omac, maclen);
		if (memcmp(tag, omac, maclen)) {
			ret = CRYPTO_INVALID_MAC;
		}
	}

	return(ret);
}


static int
aes_encrypt_atomic_avx(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_data_t *plaintext, crypto_data_t *ciphertext,
    crypto_spi_ctx_template_t template, crypto_req_handle_t req)
{
	if(mechanism->cm_type != AES_GCM_MECH_INFO_TYPE)
		return(CRYPTO_NOT_SUPPORTED);

	aes_ctx_t aes_ctx = {0};	/* on the stack */
	int ret;

	AES_ARG_INPLACE(plaintext, ciphertext);

	if ((ret = aes_check_mech_param(mechanism, NULL, 0)) != CRYPTO_SUCCESS)
		return (ret);

	switch (mechanism->cm_type) {
	case AES_GCM_MECH_INFO_TYPE:
		ret = aes_init_ctx_avx(&aes_ctx, mechanism, key);
		break;
	}

	/*
	 * Do an update on the specified input data.
	 */
	switch (plaintext->cd_format) {
	case CRYPTO_DATA_UIO:
		ret = crypto_update_uio_avx(ENCRYPT, &aes_ctx, plaintext, ciphertext);
		break;
	default:
		ret = CRYPTO_ARGUMENTS_BAD;
	}

	if (ret == CRYPTO_SUCCESS) {
		if (mechanism->cm_type == AES_GCM_MECH_INFO_TYPE)
			ret = gcm_crypt_final_avx(ENCRYPT, (gcm_ctx_avx_t *)&aes_ctx, ciphertext);
	}

	return(ret);
}

static int
aes_decrypt_atomic_avx(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_data_t *ciphertext, crypto_data_t *plaintext,
    crypto_spi_ctx_template_t template, crypto_req_handle_t req)
{
	if(mechanism->cm_type != AES_GCM_MECH_INFO_TYPE)
		return(CRYPTO_NOT_SUPPORTED);

	aes_ctx_t aes_ctx = {0};	/* on the stack */
	int ret;

	AES_ARG_INPLACE(ciphertext, plaintext);

	if ((ret = aes_check_mech_param(mechanism, NULL, 0)) != CRYPTO_SUCCESS)
		return (ret);

	switch (mechanism->cm_type) {
	case AES_GCM_MECH_INFO_TYPE:
		ret = aes_init_ctx_avx(&aes_ctx, mechanism, key);
		break;
	}

	/*
	 * Do an update on the specified input data.
	 */
	switch (ciphertext->cd_format) {
	case CRYPTO_DATA_UIO:
		ret = crypto_update_uio_avx(DECRYPT, &aes_ctx, ciphertext, plaintext);
		break;
	default:
		ret = CRYPTO_ARGUMENTS_BAD;
	}

	if (ret == CRYPTO_SUCCESS) {
		if (mechanism->cm_type == AES_GCM_MECH_INFO_TYPE)
			ret = gcm_crypt_final_avx(DECRYPT, (gcm_ctx_avx_t *)&aes_ctx, ciphertext);
	}
	return (ret);
}

int
cpu_supports_avx() {
	int cpuInfo[4] = { 0 };
	__cpuid(cpuInfo, 1);
	int osUsesXSAVE_XRSTORE = cpuInfo[2] & (1 << 27);
	int cpuAVXSuport = cpuInfo[2] & (1 << 28);
	int avxSupported = 0;

	if (osUsesXSAVE_XRSTORE && cpuAVXSuport)
	{
		unsigned long long xcrFeatureMask = _xgetbv(_XCR_XFEATURE_ENABLED_MASK);
		avxSupported = ((xcrFeatureMask & 0x6) == 0x6) ? 1 : 0;
        }
	if (avxSupported)
		dprintf("Supports AVX instruction extensions\n");
	else
		dprintf("AVX instruction extensions not supported\n");

	return(avxSupported);
}
