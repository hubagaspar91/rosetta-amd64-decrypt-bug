//! A published ChaCha20-Poly1305 test vector from Google's Wycheproof suite,
//! file `testvectors_v1/chacha20_poly1305_test.json`, tcId 90 (result "valid").
//! 513-byte plaintext, empty associated data, 256-bit key, 128-bit tag.
//! Source: https://github.com/C2SP/wycheproof
//!
//! A correct ChaCha20-Poly1305 implementation MUST turn (KEY, NONCE, PLAINTEXT)
//! into exactly EXPECTED_CIPHERTEXT_AND_TAG. Any deviation is a wrong computation.

use hex_literal::hex;

pub const KEY: [u8; 32] = hex!("afd579aa1accc682aca54e142aa69df09802f020b24a42c41db58f6997edc678");
pub const NONCE: [u8; 12] = hex!("9f79d1da957491069d774496");
pub const ASSOCIATED_DATA: &[u8] = b"";

pub const PLAINTEXT: [u8; 513] = hex!(
    "bafc6e865c48bd34b7f9329e35cfb286cd4dc31f8316171218bf0471dffd35a3"
    "30a181697ca5178688dd87efe527924f90d1c78ba40de70952ff44c26efe2159"
    "e59358f3931573df9373a73b91ba9592e12140cc009feedd2595e5b6f066b5ef"
    "6de99d4c31552cecb0614f1dce990e46e7694382f3cf3ccfcd1ea62e563e5f0d"
    "c36cb5a84e0c0b3f1f8f3fa9100f487195ff2e3169ad08136aa8ad566548c983"
    "6aa00dbac74716c26e838c1486a0084d3dfd692585e2e5ae7c75caf0e7af6021"
    "9f96116ae963b4a5899cb30a120daaca7833776692c25ad7c185e6a2d70ce03f"
    "f156cd25d76153539d6855773e21142f9ba0313562875f105a2b770a15b533fb"
    "f5110dafb69329982ab44ed1b9f321d7b79ae15a19d9f3bd4c504c24b23b812d"
    "514c19ae2a347cc18c12ce915a0bad7cc89a8720d4ba5ee0964fe05e4cc59a13"
    "f92c670b8655071e216f19ad05f4bbcca6dc7feeb188d6269c58065c98fcbbac"
    "183a9abb3811d80cb476544bd74b26991f3df987f0ed0ea6238659ac09a2250f"
    "ecc0723ffc51647b74bdf454f26e11112c8bbd797f09a3be8251c6b5b319ed95"
    "37278cc1abedb32aa10840984b96e8636b289335846ae4fbd4a00f6600d98ebe"
    "25885c68d7043ce0dc5229d7e9bd51bea9b8fe0552f40688429c482629ced623"
    "f6074858147e73da3ff4ad2ae45c1a1c8a6c5b3b2c3d568a756608179f63b580"
    "fd"
);

// Ciphertext (513 bytes) followed immediately by the 16-byte authentication tag.
pub const EXPECTED_CIPHERTEXT_AND_TAG: [u8; 529] = hex!(
    "112f4ce552e41a1e8c93f6ed3e1273b9dab4c1eeb5c100c2c2732af27f016076"
    "4012af269a50f04d10ba24bb43598547b700cfc480ab123f6e5c7488d674a637"
    "552ca03eb298af4ca2879830ca25f273713bd5bde16a06b31254b412bf6a8ce2"
    "2efe73b15380fafe2ade9d5c57e6267d082b5adc06f55e8313b1d0753a46b988"
    "e7776b201a9d5896c349e8631f1b381c8f43247d0d9b171701fc94c5265ead84"
    "f3d44672bb799d3ddf8d63ae73d79104e48366f05d048df2ee54102d637b9c2d"
    "4d03200109be48b6d4c2fb9b0b45f7945c8c5468c97f36c9f4b9789a3a547348"
    "739dac3e7b1144884d501b4a073f04081de6287b66af2d0e3728cf2064be8897"
    "5e578581e1e8d7c7d9c956d558c2fa6816721518f1e1de493e83628a42cce40f"
    "85c55d5973b397ea1d58ee473bf5ea59f35510e1903d22673c3d289121f3fed8"
    "ee4253e299a52410bbbd39daf1b87e43b5c4be3e4698943e5578f0744c2b0a4d"
    "39922d6c4b205e8259166a46230d326442492763dba8a2cd9d62c7e8715e43c8"
    "91ce2f5333b02ea94ce6fa1c27e86e3488a9b7f26bb814d214b9d29eefa5a4a0"
    "4040cdcbb1a13ca2f436e302f767da3a7675bcf501cee45f774eb64c0fcb64f1"
    "d2e5cd8dd9f9600e0b5197125a35249a0da6f64cadca4a769984bab62438af11"
    "c323de33014f627e945cb90f5be88291af1e7e169d7695db6289302ad99fec05"
    "0ce2fcadc31ad755139d38ecbfb75d1ddc"
);
