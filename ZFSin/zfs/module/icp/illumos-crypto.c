/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 2016, Datto, Inc. All rights reserved.
 * Copyright (c) 2017, Jorgen Lundman <lundman@lundman.net>
 */

#ifdef LINUX
#ifdef _KERNEL
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#else
#define	__exit
#define	__init
#endif
#endif // LINUX

#include <sys/crypto/common.h>
#include <sys/crypto/api.h>
#include <sys/crypto/impl.h>
#include <sys/crypto/sched_impl.h>
#include <sys/modhash_impl.h>
#include <sys/crypto/icp.h>

/*
 * Changes made to the original Illumos Crypto Layer for the ICP:
 *
 * Several changes were needed to allow the Illumos Crypto Layer
 * to work in the Linux kernel. Almost all of the changes fall into
 * one of the following categories:
 *
 * 1) Moving the syntax to the C90: This was mostly a matter of
 * changing func() definitions to func(void). In a few cases,
 * initializations of structs with unions needed to have brackets
 * added.
 *
 * 2) Changes to allow userspace compilation: The ICP is meant to be
 * compiled and used in both userspace and kernel space (for ztest and
 * libzfs), so the _KERNEL macros did not make sense anymore. For the
 * same reason, many header includes were also changed to use
 * sys/zfs_context.h
 *
 * 3) Moving to a statically compiled architecture: At some point in
 * the future it may make sense to have encryption algorithms that are
 * loadable into the ICP at runtime via separate kernel modules.
 * However, considering that this code will probably not see much use
 * outside of zfs and zfs encryption only requires aes and sha256
 * algorithms it seemed like more trouble than it was worth to port over
 * Illumos's kernel module structure to a Linux kernel module. In
 * addition, The Illumos code related to keeping track of kernel modules
 * is very much tied to the Illumos OS and proved difficult to port to
 * Linux. Therefore, the structure of the ICP was simplified to work
 * statically and several pieces of code responsible for keeping track
 * of Illumos kernel modules were removed and simplified. All module
 * initialization and destruction is now called in this file during
 * Linux kernel module loading and unloading.
 *
 * 4) Adding destructors: The Illumos Crypto Layer is built into
 * the Illumos kernel and is not meant to be unloaded. Some destructors
 * were added to allow the ICP to be unloaded without leaking
 * structures.
 *
 * 5) Removing CRYPTO_DATA_MBLK related structures and code:
 * crypto_data_t can have 3 formats, CRYPTO_DATA_RAW, CRYPTO_DATA_UIO,
 * and CRYPTO_DATA_MBLK. ZFS only requires the first 2 formats, as the
 * last one is related to streamed data. To simplify the port, code
 * related to this format was removed.
 *
 * 6) Changes for architecture specific code: Some changes were needed
 * to make architecture specific assembly compile. The biggest change
 * here was to functions related to detecting CPU capabilities for amd64.
 * The Illumos Crypto Layer used called into the Illumos kernel's API
 * to discover these. They have been converted to instead use the
 * 'cpuid' instruction as per the Intel spec. In addition, references to
 * the sun4u' and sparc architectures have been removed so that these
 * will use the generic implementation.
 *
 * 7) Removing sha384 and sha512 code: The sha code was actually very
 * wasy to port. However, the generic sha384 and sha512 code actually
 * exceeds the stack size on arm and powerpc architectures. In an effort
 * to remove warnings, this code was removed.
 *
 * 8) Change large allocations from kmem_alloc() to vmem_alloc(): In
 * testing the ICP with the ZFS encryption code, a few allocations were
 * found that could potentially be very large. These caused the SPL to
 * throw warnings and so they were changed to use vmem_alloc().
 *
 * 9) Makefiles: Makefiles were added that would work with the existing
 * ZFS Makefiles.
 */


void
icp_fini(void)
{
	sha1_mod_fini();
	sha2_mod_fini();
	aes_mod_fini();
	kcf_sched_destroy();
	kcf_prov_tab_destroy();
	kcf_destroy_mech_tabs();
	mod_hash_fini();
}

/* roughly equivalent to kcf.c: _init() */
int
icp_init(void)
{
	/* initialize the mod hash module */
	mod_hash_init();

	/* initialize the mechanisms tables supported out-of-the-box */
	kcf_init_mech_tabs();
	/* initialize the providers tables */
	kcf_prov_tab_init();

	/*
	 * Initialize scheduling structures. Note that this does NOT
	 * start any threads since it might not be safe to do so.
	 */
	kcf_sched_init();

	/* initialize algorithms */
	aes_mod_init();
	sha2_mod_init();
	sha1_mod_init();

	/* Uncomment me if you want to warm up the cipher and check it is
	 * correct */
	//cipher_test();

	return (0);
}



unsigned char key[16] = {
    0x5c, 0x95, 0x64, 0x42, 0x00, 0x82, 0x1c, 0x9e,
    0xd4, 0xac, 0x01, 0x83, 0xc4, 0x9c, 0x14, 0x97
};

// Input data will be set to 00, 01, 02, ....., fe, ff, 00, 01, ...
// First iv is set to a8, a9, ...
int cipher_test(void)
{
    crypto_data_t plaintext, ciphertext;
    crypto_mechanism_t *mech;
    crypto_mechanism_t mech_holder;
    iovec_t /* *srciov = NULL,*/ *dstiov = NULL;
    //uio_t srcuio = { 0 }, dstuio = { 0 };
    uio_t *srcuio = NULL, *dstuio = NULL;
    unsigned char d = 0;
    uint64_t size;
    int i;
    int maclen;
    int err;
    crypto_key_t ckey;
    unsigned char *plaindata  = NULL;
    unsigned char *cipherdata = NULL;
    unsigned char *mac = NULL;
    unsigned char *out_mac = NULL;
    unsigned char *iv  = NULL;
    CK_AES_CCM_PARAMS *ccmp = NULL;
    unsigned char out[180];
    int ivsize = 12;

    cmn_err (CE_CONT, "cipher tester loading\n");

    plaindata  = kmem_alloc(512, KM_SLEEP);
    if (!plaindata) goto out;
    cipherdata = kmem_alloc(512, KM_SLEEP);
    if (!cipherdata) goto out;
    mac = kmem_alloc(16, KM_SLEEP);
    if (!mac) goto out;
    out_mac = kmem_alloc(16, KM_SLEEP);
    if (!out_mac) goto out;
    iv = kmem_alloc(ivsize, KM_SLEEP);
    if (!iv) goto out;

    for (i = 0, d = 0; i < sizeof(plaindata); i++, d++)
        plaindata[i] = d;

    ckey.ck_format = CRYPTO_KEY_RAW;
    ckey.cku_data.cku_key_value.cku_v_length = sizeof(key) * 8;
    ckey.cku_data.cku_key_value.cku_v_data   = (void *)&key;

    size = 512;

    // Clear all outputs
    memset(cipherdata, 0, size);
    memset(iv, 0, ivsize);
    memset(mac, 0, 16);
    memset(&mech_holder, 0, sizeof(mech_holder));
    mech = &mech_holder;

    cmn_err (CE_CONT, "init complete\n");

    // Call cipher
    plaintext.cd_format = CRYPTO_DATA_RAW;
    plaintext.cd_offset = 0;
    plaintext.cd_length = size;
    plaintext.cd_miscdata = NULL;
    plaintext.cd_raw.iov_base = (void *)plaindata;
    plaintext.cd_raw.iov_len = size;

    maclen = 16;

	dstuio = uio_create(2, 0, UIO_SYSSPACE, UIO_WRITE);
	if (!dstuio) goto out;
	uio_addiov(dstuio, (user_addr_t)cipherdata, size);
	uio_addiov(dstuio, (user_addr_t)mac, maclen);

    ciphertext.cd_format = CRYPTO_DATA_UIO;
    ciphertext.cd_offset = 0;
    ciphertext.cd_uio = dstuio;
    ciphertext.cd_miscdata = NULL;

    cmn_err (CE_CONT, "loaded CD structs\n");

    //mech = zio_crypt_setup_mech_gen_iv(crypt, type, dedup, key, txg,
    //                                   bookmark, src, plaintext.cd_length, iv);

    //mech = zio_crypt_setup_mech_common(crypt, type, datalen);
    mech->cm_type = crypto_mech2id(SUN_CKM_AES_CCM);

    cmn_err (CE_CONT, "mech2id is %d\n", mech->cm_type);

    ccmp = kmem_alloc(sizeof (CK_AES_CCM_PARAMS), KM_SLEEP);
    // ccmp = calloc(sizeof (CK_AES_CCM_PARAMS), 1);
    ccmp->ulNonceSize = ivsize;
    ccmp->ulAuthDataSize = 0;
    ccmp->authData = NULL;
    ccmp->ulDataSize = size;
    ccmp->ulMACSize = 16;
    mech->cm_param = (char *)ccmp;
    mech->cm_param_len = sizeof (CK_AES_CCM_PARAMS);


    //zio_crypt_gen_data_iv(crypt, type, dedup, data, datalen,
    //                     key, txg, bookmark, iv);
    cmn_err (CE_CONT, "Setting iv to: \n");
    for (i = 0, d=0xa8; i < ivsize; i++,d++) {
        iv[i] = d;
        cmn_err (CE_CONT, "0x%02x ", iv[i]);
    }
    cmn_err (CE_CONT, "\n");

    ccmp->nonce = (uchar_t *)iv;


    err = crypto_encrypt(mech, &plaintext, &ckey, NULL,
                         &ciphertext, NULL);

    cmn_err (CE_CONT, "crypt_encrypt returns 0x%02X\n", err);
    *out = 0;

    for (i = 0; i < 32/* size */; i++) {

        snprintf((char*)out, sizeof(out), "%s 0x%02x", out, cipherdata[i]);
        if ((i % 8)==7) {
            cmn_err (CE_CONT, "%s\n", out);
            *out = 0;
        }
    }
    cmn_err (CE_CONT, "%s\nMAC output:", out);
    *out = 0;
    for (i = 0; i < 16; i++) {
        snprintf((char *)out, sizeof(out), "%s 0x%02x", out, mac[i]);
    }
    cmn_err (CE_CONT, "%s\n", out);

    cmn_err (CE_CONT, "%s\nIV output:", out);
    *out = 0;
    for (i = 0; i < ivsize; i++) {
        snprintf((char *)out, sizeof(out), "%s 0x%02x", out, iv[i]);
    }
    cmn_err (CE_CONT, "%s\n", out);



 out:
    if (ccmp)       kmem_free(ccmp, sizeof (CK_AES_CCM_PARAMS));
    if (plaindata)  kmem_free(plaindata, 512);
    if (cipherdata) kmem_free(cipherdata, 512);
    if (mac)        kmem_free(mac, 16);
    if (out_mac)    kmem_free(out_mac, 16);
    if (iv)         kmem_free(iv, ivsize);
    if (dstiov)     kmem_free(dstiov, sizeof (iovec_t) * 2);
	if (dstuio)     uio_free(dstuio);
	if (srcuio)     uio_free(srcuio);
    return 0;
}

/*
 * output from encryption should be:
 0x03 0x54 0x08 0xa4 0x52 0xb8 0xde 0xc4
 0x68 0xfa 0xce 0x12 0xa0 0x0e 0xef 0x70
 0x3d 0x79 0x8f 0xda 0xdf 0x80 0xd4 0x1f
 0xf5 0x13 0x08 0xe0 0x55 0x07 0x31 0x1c
 *
 * MAC output:
 * 0xc4 0x3e 0x15 0x88 0xab 0x48 0x65 0x0d 0x7b 0x3b 0x2c
 * 0x10 0x57 0x01 0x68 0x11
 *
 */
