#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/export-internal.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

#ifdef CONFIG_UNWINDER_ORC
#include <asm/orc_header.h>
ORC_HEADER;
#endif

BUILD_SALT;
BUILD_LTO_INFO;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

MODULE_INFO(intree, "Y");

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

KSYMTAB_FUNC(tls_toe_register_device, "", "");
KSYMTAB_FUNC(tls_toe_unregister_device, "", "");
KSYMTAB_FUNC(tls_device_sk_destruct, "_gpl", "");
KSYMTAB_FUNC(tls_offload_tx_resync_request, "_gpl", "");
KSYMTAB_FUNC(tls_get_record, "", "");
KSYMTAB_FUNC(tls_validate_xmit_skb, "_gpl", "");
KSYMTAB_FUNC(tls_encrypt_skb, "_gpl", "");

MODULE_INFO(depends, "");

