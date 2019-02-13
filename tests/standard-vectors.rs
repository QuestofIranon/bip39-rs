use bip39::{Language, Mnemonic, Seed};

fn test_mnemonic(entropy_hex: &str, expected_phrase: &str, language: Language) {
    let entropy_bytes = hex::decode(entropy_hex).unwrap();
    let mnemonic = Mnemonic::from_entropy(entropy_bytes.as_slice(), language);

    assert!(mnemonic.is_ok());
    assert_eq!(mnemonic.unwrap().phrase(), expected_phrase);
}

fn test_seed(phrase: &str, password: &str, expected_seed_hex: &str, language: Language) {
    let mnemonic = Mnemonic::from_phrase(phrase, language);

    assert!(mnemonic.is_ok());

    let seed = Seed::new(&mnemonic.unwrap(), password);
    let actual_seed_bytes: &[u8] = seed.as_bytes();
    let expected_seed_bytes = hex::decode(expected_seed_hex).unwrap();

    assert!(
        actual_seed_bytes.eq(expected_seed_bytes.as_slice()),
        "Wrong seed for '{}'\nexp: {:?}\nact: {:?}\n",
        phrase,
        expected_seed_hex,
        hex::encode(actual_seed_bytes)
    );
}

macro_rules! tests {
    (
    [$language:ident, $password:expr]:
    $([$entropy_hex:expr, $phrase:expr, $seed_hex:expr]),*) => {
    	paste::item!{

		#[test]
		#[allow(non_snake_case)]
		fn [<test_all_mnemonic_ $language>]() {
			$(
				test_mnemonic($entropy_hex, $phrase, crate::Language::$language);
			)*
		}

		#[test]
		#[allow(non_snake_case)]
		fn [<test_all_seed_ $language>]() {
			$(
				test_seed($phrase, $password, $seed_hex, crate::Language:: $language);
			)*
		}

    	}
	};
}

tests! {
    // https://github.com/trezor/python-mnemonic/blob/master/vectors.json
    [English, "TREZOR"]:
    [
        "00000000000000000000000000000000",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
    ],
    [
        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
        "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607"
    ],
    [
        "80808080808080808080808080808080",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
        "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8"
    ],
    [
        "ffffffffffffffffffffffffffffffff",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069"
    ],
    [
        "000000000000000000000000000000000000000000000000",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
        "035895f2f481b1b0f01fcf8c289c794660b289981a78f8106447707fdd9666ca06da5a9a565181599b79f53b844d8a71dd9f439c52a3d7b3e8a79c906ac845fa"
    ],
    [
        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
        "f2b94508732bcbacbcc020faefecfc89feafa6649a5491b8c952cede496c214a0c7b3c392d168748f2d4a612bada0753b52a1c7ac53c1e93abd5c6320b9e95dd"
    ],
    [
        "808080808080808080808080808080808080808080808080",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
        "107d7c02a5aa6f38c58083ff74f04c607c2d2c0ecc55501dadd72d025b751bc27fe913ffb796f841c49b1d33b610cf0e91d3aa239027f5e99fe4ce9e5088cd65"
    ],
    [
        "ffffffffffffffffffffffffffffffffffffffffffffffff",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
        "0cd6e5d827bb62eb8fc1e262254223817fd068a74b5b449cc2f667c3f1f985a76379b43348d952e2265b4cd129090758b3e3c2c49103b5051aac2eaeb890a528"
    ],
    [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
        "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8"
    ],
    [
        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
        "bc09fca1804f7e69da93c2f2028eb238c227f2e9dda30cd63699232578480a4021b146ad717fbb7e451ce9eb835f43620bf5c514db0f8add49f5d121449d3e87"
    ],
    [
        "8080808080808080808080808080808080808080808080808080808080808080",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
        "c0c519bd0e91a2ed54357d9d1ebef6f5af218a153624cf4f2da911a0ed8f7a09e2ef61af0aca007096df430022f7a2b6fb91661a9589097069720d015e4e982f"
    ],
    [
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
        "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad"
    ],
    [
        "9e885d952ad362caeb4efe34a8e91bd2",
        "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic",
        "274ddc525802f7c828d8ef7ddbcdc5304e87ac3535913611fbbfa986d0c9e5476c91689f9c8a54fd55bd38606aa6a8595ad213d4c9c9f9aca3fb217069a41028"
    ],
    [
        "6610b25967cdcca9d59875f5cb50b0ea75433311869e930b",
        "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog",
        "628c3827a8823298ee685db84f55caa34b5cc195a778e52d45f59bcf75aba68e4d7590e101dc414bc1bbd5737666fbbef35d1f1903953b66624f910feef245ac"
    ],
    [
        "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
        "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
        "64c87cde7e12ecf6704ab95bb1408bef047c22db4cc7491c4271d170a1b213d20b385bc1588d9c7b38f1b39d415665b8a9030c9ec653d75e65f847d8fc1fc440"
    ],
    [
        "c0ba5a8e914111210f2bd131f3d5e08d",
        "scheme spot photo card baby mountain device kick cradle pact join borrow",
        "ea725895aaae8d4c1cf682c1bfd2d358d52ed9f0f0591131b559e2724bb234fca05aa9c02c57407e04ee9dc3b454aa63fbff483a8b11de949624b9f1831a9612"
    ],
    [
        "6d9be1ee6ebd27a258115aad99b7317b9c8d28b6d76431c3",
        "horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack brave",
        "fd579828af3da1d32544ce4db5c73d53fc8acc4ddb1e3b251a31179cdb71e853c56d2fcb11aed39898ce6c34b10b5382772db8796e52837b54468aeb312cfc3d"
    ],
    [
        "9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863",
        "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside",
        "72be8e052fc4919d2adf28d5306b5474b0069df35b02303de8c1729c9538dbb6fc2d731d5f832193cd9fb6aeecbc469594a70e3dd50811b5067f3b88b28c3e8d"
    ],
    [
        "23db8160a31d3e0dca3688ed941adbf3",
        "cat swing flag economy stadium alone churn speed unique patch report train",
        "deb5f45449e615feff5640f2e49f933ff51895de3b4381832b3139941c57b59205a42480c52175b6efcffaa58a2503887c1e8b363a707256bdd2b587b46541f5"
    ],
    [
        "8197a4a47f0425faeaa69deebc05ca29c0a5b5cc76ceacc0",
        "light rule cinnamon wrap drastic word pride squirrel upgrade then income fatal apart sustain crack supply proud access",
        "4cbdff1ca2db800fd61cae72a57475fdc6bab03e441fd63f96dabd1f183ef5b782925f00105f318309a7e9c3ea6967c7801e46c8a58082674c860a37b93eda02"
    ],
    [
        "066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad",
        "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform",
        "26e975ec644423f4a4c4f4215ef09b4bd7ef924e85d1d17c4cf3f136c2863cf6df0a475045652c57eb5fb41513ca2a2d67722b77e954b4b3fc11f7590449191d"
    ],
    [
        "f30f8c1da665478f49b001d94c5fc452",
        "vessel ladder alter error federal sibling chat ability sun glass valve picture",
        "2aaa9242daafcee6aa9d7269f17d4efe271e1b9a529178d7dc139cd18747090bf9d60295d0ce74309a78852a9caadf0af48aae1c6253839624076224374bc63f"
    ],
    [
        "c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05",
        "scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango congress clump",
        "7b4a10be9d98e6cba265566db7f136718e1398c71cb581e1b2f464cac1ceedf4f3e274dc270003c670ad8d02c4558b2f8e39edea2775c9e232c7cb798b069e88"
    ],
    [
        "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
        "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
        "01f5bced59dec48e362f2c45b5de68b9fd6c92c6634f44d6d40aab69056506f0e35524a518034ddc1192e1dacd32c1ed3eaa3c3b131c88ed8e7e54c49a5d0998"
    ]
}

tests! {
// https://github.com/MetacoSA/NBitcoin/blob/master/NBitcoin.Tests/data/bip39_vectors.zh-CN.json
    [ChineseSimplified, "nullius　à　nym.zone ¹teſts² 汉语"]:
    [
        "00000000000000000000000000000000",
        "的 的 的 的 的 的 的 的 的 的 的 在",
        "fe216d54b5731858962df10d5d5cfeb0a2d71c0e0d079e935591d34d95160b789717cdc800bb0f4f676469384f81513e38520e3a906da35c80e784939c9db066"
    ],
    [
        "0000000000000000000000000000000000000000",
        "的 的 的 的 的 的 的 的 的 的 的 的 的 的 地",
        "bd142fd24bcddac1d77fd74a75320776d3a6c2be8cba51d6ba7026eb29d126c0a182756991e0b3010f6e54fd65888534e2a5c4f9a3e0c70e1eff7017ed90e93e"
    ],
    [
        "000000000000000000000000000000000000000000000000",
        "的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 动",
        "e39729a7d2fb07c88176fb2e91f2f45d0fb6637d2d4507a447a6386c3a1765b32e92b46b7c754ee4bcf12f1da8eaf4b84e1a166b81e82bcecbb0ee3bdd5a3ca5"
    ],
    [
        "00000000000000000000000000000000000000000000000000000000",
        "的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 出",
        "9facd65610788c912793e59bd78563f2c9c465d8b36dd2aea9e6bf68b81c8e2f45e3553326cae2cf9ae887b7ed7d729e4f3c490eaaaff01d2d4d5d133d037c77"
    ],
    [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 性",
        "caf9824a76c924d999af42a482b4199739f3e1bcf9631d26a17826aa82cf0467ed68a8c5c0552d539cd49091e9d11fb5ec7a2e02cb9f66be95eed37ac35c2e17"
    ],
    [
        "01010101010101010101010101010101",
        "人 三 谈 我 表 壤 对 据 人 三 谈 于",
        "d0ed65ead74fcea09523e4b3bae64ac1d8082adb1e41960ce66574de3ed714e8d7c0b0ae8ddd38bf6713ffb055f75ff88a23da7639284f13f5a836152e047ee7"
    ],
    [
        "0101010101010101010101010101010101010101",
        "人 三 谈 我 表 壤 对 据 人 三 谈 我 表 壤 而",
        "4ce2ae1398a1c3b3f8aaeefdc4a29c251ac4914a5d10d366b25f401e0edbb798c87af278703dc54bfb754e4b8df8708a1480ca18b72a8fdc3c09d25a7ecb0c29"
    ],
    [
        "010101010101010101010101010101010101010101010101",
        "人 三 谈 我 表 壤 对 据 人 三 谈 我 表 壤 对 据 人 实",
        "d6aae429dde1dd685374ed095066b4b2eca1d1f3800ee0af23bd94ff2c66f83c659e0dc366b7182a47a37ba668b53271f252d43e24365bb434367c8bcce14c6f"
    ],
    [
        "01010101010101010101010101010101010101010101010101010101",
        "人 三 谈 我 表 壤 对 据 人 三 谈 我 表 壤 对 据 人 三 谈 我 原",
        "8add055932c967f840e30b2ab66725cdea0ebc4a0d9890a8f310b75216a2e50a8a2f4a38153b090e5a079e3885586dee2cb2ba2147ce17765cda704a88ea0d88"
    ],
    [
        "0101010101010101010101010101010101010101010101010101010101010101",
        "人 三 谈 我 表 壤 对 据 人 三 谈 我 表 壤 对 据 人 三 谈 我 表 壤 对 研",
        "709c82b309b73b72c912cbe3cedb4a50373bc8642fda4fd0aeccf2202f290e7332b8af15ad5f18cf1891877fc22e19b3fa83861a638c5f2fe04012ca75bb8199"
    ],
    [
        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "枪 疫 霉 尝 俩 闹 饿 贤 枪 疫 霉 卿",
        "df31d1313e4b60bd2972c5a0520721d9f821a5a8346004232c169277a15af37a9ce0787ef9ceb3d99f3af4c98c1b645c158ddfec315bfdbbf688f84e04609798"
    ],
    [
        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "枪 疫 霉 尝 俩 闹 饿 贤 枪 疫 霉 尝 俩 闹 沫",
        "2376aeef884fe4cd384d6f5c04ed49e645bdc2e8efa82c23585ae91785324a913f296bce875b61fac30ee2a81c4e91480da4b8bdc8563afbfcdf91146c68d217"
    ],
    [
        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "枪 疫 霉 尝 俩 闹 饿 贤 枪 疫 霉 尝 俩 闹 饿 贤 枪 殿",
        "ee7559788d1f993994da14a33e79b2dad5e6bd19fc8aa0499598d776a6114d4506fd13e2d432438d5ae0c331e29761ed6b5dca86c33ff9ca23e55a30a38d313b"
    ],
    [
        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "枪 疫 霉 尝 俩 闹 饿 贤 枪 疫 霉 尝 俩 闹 饿 贤 枪 疫 霉 尝 盈",
        "6a5fc40b4a66e5eac4bb1b6ba91171da3edc84a0f7d37025e9a489fe05a0bb715ba3e2f99170cc2575f837a761555ffb1a9d254485b879deefefb2f42cb3af2c"
    ],
    [
        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "枪 疫 霉 尝 俩 闹 饿 贤 枪 疫 霉 尝 俩 闹 饿 贤 枪 疫 霉 尝 俩 闹 饿 搭",
        "e3b214c60b5b3fd4b1c500143ac10e0338d0c78cec6332443bc75b8cba6697d717e55c1a3b77432798742d1664c63a860252527cab4903e305cc2f46d6215d6d"
    ],
    [
        "80808080808080808080808080808080",
        "壤 对 据 人 三 谈 我 表 壤 对 据 不",
        "8282fb28a53329c2312eb4a5b2e0dee0650227f4ab2e83b8e2e5327874b53b8a51311421886663146f8c0496264622763ce903f5a78371de36414d8ca10e921b"
    ],
    [
        "8080808080808080808080808080808080808080",
        "壤 对 据 人 三 谈 我 表 壤 对 据 人 三 谈 大",
        "b51140b60a06398d8121c420ed084f9e93e08f827e8797ab2d0861c7be8e99bdda01367e2bb72f9f110615f24196a7086e138bb46a6d7dba5f8d4c9c764f9b67"
    ],
    [
        "808080808080808080808080808080808080808080808080",
        "壤 对 据 人 三 谈 我 表 壤 对 据 人 三 谈 我 表 壤 民",
        "4c4b05e4dfcc65caeb68b5b24d81f65ad33d8b55cf9615e1107002b8e91bc18b16fedc72ab0a94149232bd4f936cc6a598a5abbd608410cd86f10cefbd609c46"
    ],
    [
        "80808080808080808080808080808080808080808080808080808080",
        "壤 对 据 人 三 谈 我 表 壤 对 据 人 三 谈 我 表 壤 对 据 人 起",
        "62af2863200e4e42f91d4a0b5f6cb9a03d3ca6fd51ce1be0765aa90e2ad02c5185c7eddf6abb755998703e2e02680081a72ab4e0bbfe430a94f600f4f3006109"
    ],
    [
        "8080808080808080808080808080808080808080808080808080808080808080",
        "壤 对 据 人 三 谈 我 表 壤 对 据 人 三 谈 我 表 壤 对 据 人 三 谈 我 五",
        "0f6eda9d1ac68b84a628e82ddfda9c1ce24c7d9c4132049c8c36f58a71867a41dbae0cfe14e60282fb48bd53befb28fa2509cd05cbfb079b057c553f394eae49"
    ],
    [
        "fefefefefefefefefefefefefefefefe",
        "尝 俩 闹 饿 贤 枪 疫 霉 尝 俩 闹 皱",
        "776a1d4bef24b46f16c78de781d67c6e9f511407f4196bcfcc9fbcfdfaeeba25e4cb1dd13ac5fbf2101ea593ff5f251479fddc2408ff803a5ab885b29dd7959b"
    ],
    [
        "fefefefefefefefefefefefefefefefefefefefe",
        "尝 俩 闹 饿 贤 枪 疫 霉 尝 俩 闹 饿 贤 枪 晒",
        "2ea0d61b22d4f7343e65535ba95a36b4157647d3efa63de3c01d4fa848119b241a85bb22da8c9a9d06e9c2c02c6270fde152a7e3a5d51ce412e0112cfbf6617e"
    ],
    [
        "fefefefefefefefefefefefefefefefefefefefefefefefe",
        "尝 俩 闹 饿 贤 枪 疫 霉 尝 俩 闹 饿 贤 枪 疫 霉 尝 泼",
        "e2ea5e461a92330b6495bc88a3cdb302e79998ef9877cef6524a621a1016a7538fb740e1e037a7758d82bdaf7be914f81d81b5374af91009d934112a17629f4d"
    ],
    [
        "fefefefefefefefefefefefefefefefefefefefefefefefefefefefe",
        "尝 俩 闹 饿 贤 枪 疫 霉 尝 俩 闹 饿 贤 枪 疫 霉 尝 俩 闹 饿 坯",
        "0cd655dd9641a0160f13d974d6801c7f5e2fbe07220c0f7ed9f8255bbe211278073719d4c027009faff89566d2b762237bc86143e7ec4caeefdc553805d1d441"
    ],
    [
        "fefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefe",
        "尝 俩 闹 饿 贤 枪 疫 霉 尝 俩 闹 饿 贤 枪 疫 霉 尝 俩 闹 饿 贤 枪 疫 蓄",
        "0f458bca65384b1605618b0f59a549d2433bcb36edb99d7c2ad803c522337a973ab99122d9f92e21c1adc7d67c1948d5697d0ab318911986bd51e64943f12873"
    ],
    [
        "ffffffffffffffffffffffffffffffff",
        "歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 逻",
        "73602246891b2a906164fda4d80375cde53d877641eed4d88e19c3b11d526fa7fefa7df37bbf17d2b7a0c9b91fc2514adde82a41e55c75f6c91bc72f4d1c81b0"
    ],
    [
        "ffffffffffffffffffffffffffffffffffffffff",
        "歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 溜",
        "c065e1ff53d254b4b51859805fd0248f130a30529cc4164eb52adf9ea6ccb05820cc75e7b8c4fecc9b658df9758fe0bbd720c298f4d25e82cad15781cad83338"
    ],
    [
        "ffffffffffffffffffffffffffffffffffffffffffffffff",
        "歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 裕",
        "06a3dcf40d778d276916804266c255d615bc417754b0c8b59c06be7ca54cbbac6e01a0573c104c606dc9f69191e3482b276c1238a6a86b1b67de7bf53dfc6ec4"
    ],
    [
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 躺",
        "389769079e0ccd7fc23aa97b96843dfb2dd9a383128587fc5851d5143208a293ddd4be66581fa0964746497f4357c279762d35935395a9f38f1306a23a53b8a2"
    ],
    [
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 佳",
        "aaf0f4e8292ea1da080391f0a51d6bb88f572d745048e630d2d2345265c6b9f3f20553560011b7a4861876852e10141de2a036a0fe9edc7a0d8900336a9cd55a"
    ],
    [
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "琴 轴 琴 轴 琴 轴 琴 轴 琴 轴 琴 找",
        "b67beaa271f5b17b752ab72d9fd37dfba6eb4345a4ec02c954a7805c361cff82c06c1b3a3a3092184595b46591c7e0af01e8ed739ececbfa88308e1107fd677c"
    ],
    [
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "琴 轴 琴 轴 琴 轴 琴 轴 琴 轴 琴 轴 琴 轴 氏",
        "a95b822166e3d601775488da5148719dec79e1917855e220be56da294b83c91c5909411ff9a39ac2347ae0c8c1c166e3af2b41ce36ad8d5abe2376ec3aa5ff38"
    ],
    [
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "琴 轴 琴 轴 琴 轴 琴 轴 琴 轴 琴 轴 琴 轴 琴 轴 琴 良",
        "744d58a74748deea27eb6511846d49515cfcae0bff31a49d2798fc3cce1a79bfe9f0b452dd84b10a40034f589adb181a9bfb1f82bfa52d0c7ae574acdcffd880"
    ],
    [
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "琴 轴 琴 轴 琴 轴 琴 轴 琴 轴 琴 轴 琴 轴 琴 轴 琴 轴 琴 轴 拍",
        "eef28b231d319e4a9f01849d71763d2ff242651f7073b475540a9614c1d7b9f4c1e50c8588116fc279b4305cf255a1a56dfcb42531f68cbcaf10248772975892"
    ],
    [
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "琴 轴 琴 轴 琴 轴 琴 轴 琴 轴 琴 轴 琴 轴 琴 轴 琴 轴 琴 轴 琴 轴 琴 既",
        "943dd078f051d28c92f36d6a8aa11416f27d45f338429b1aff1504efb84c97d47d228c1d601088adf709d187984a5fe3b01e35b11dc24d5019741035fa96e51a"
    ],
    [
        "55555555555555555555555555555555",
        "轴 琴 轴 琴 轴 琴 轴 琴 轴 琴 轴 腰",
        "8847533fe7f092bbbc90ed676f88a468128a890d7f8e14e73866ded9400c8c11e1fa80b2d85bf784f6dd0d8306c892a60ff37c8cd5620174e9852d6a30f044bc"
    ],
    [
        "5555555555555555555555555555555555555555",
        "轴 琴 轴 琴 轴 琴 轴 琴 轴 琴 轴 琴 轴 琴 让",
        "79f70b496bcc4daf86de9417d8f261f2dcd73f5fa2e7d6088efd68bf5413ca977fe67ecb71b4b3ff217ede3dbcdb864856ce4db992f0cc8aeb112d5b04fd9597"
    ],
    [
        "555555555555555555555555555555555555555555555555",
        "轴 琴 轴 琴 轴 琴 轴 琴 轴 琴 轴 琴 轴 琴 轴 琴 轴 森",
        "7aeb3d6cca2e787856722599def8731453781f4f80da0a34593365a2cbf82c3c3fbe74f8d40afda6d3b04ff88c85281e3c87bafb1b4635b59a323b9d389333fd"
    ],
    [
        "55555555555555555555555555555555555555555555555555555555",
        "轴 琴 轴 琴 轴 琴 轴 琴 轴 琴 轴 琴 轴 琴 轴 琴 轴 琴 轴 琴 让",
        "733bd2103d03241067d0fecee93e59bcb03c97097e94985706ed4a6693fe623f7fe1b9ca24ca30962e787dd91a200350fcd42d10301eb48d1393e301cffe25ac"
    ],
    [
        "5555555555555555555555555555555555555555555555555555555555555555",
        "轴 琴 轴 琴 轴 琴 轴 琴 轴 琴 轴 琴 轴 琴 轴 琴 轴 琴 轴 琴 轴 琴 轴 奖",
        "0e810c1f122835c1afea36761558f9f884e34bc72e76e9a1c06e62bcf32ea248c176385343173ab655854c08ed5a3ef102b675eabd5654f26f621cd5aac1e14d"
    ],
    [
        "9e885d952ad362caeb4efe34a8e91bd2",
        "蒙 台 脱 纪 构 硫 浆 霉 感 仅 鱼 汤",
        "61c956de6d052a168d87d3c693f9d3d752b44ccb4ae4c921ec3cad48d64bbd35dbba8265f3db4592f730d2c0df8f765340b331463f2a8e4c681956d1f3719c81"
    ],
    [
        "6610b25967cdcca9d59875f5cb50b0ea75433311869e930b",
        "父 泥 炼 胁 鞋 控 载 政 惨 逐 整 碗 环 惯 案 棒 订 移",
        "ca508bd8f0bba5c53899571c6435d2cd0b679ac61b0463b7f95bf1fd10566a17931475b45f1ba7d10f555a9ae2a9d792ef350bdf5bd0d99123f610547a763daf"
    ],
    [
        "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
        "宁 照 违 材 交 养 违 野 悉 偷 梅 设 贵 帝 鲜 仰 圈 首 荷 钩 隙 抓 养 熟",
        "3ddc4fbc8161d2e3c69cdd03531fd05ef21ad9ea516500ed69a8a6e7746f308e3ea86a6a6a666f527b1e625726d60c2899b6d0b4e526e67bb3c60223296d03f4"
    ],
    [
        "b3ffe8f56d54805218090de337779328a3a2e758",
        "懂 艇 细 斥 早 目 湖 造 笼 祥 逮 未 置 胞 损",
        "18466eba6abd8cca53b0b5702fee7b668059f87063089401d0462a5ec11314582b89a17fa018c0c4e572c8a34e3755057ccba179e9c0015792bb27eaa3c58df3"
    ],
    [
        "437dd688276ceb711cda3a126eab879a188a30b097b769a931bea6fe",
        "轮 醇 毕 跟 硅 隆 抓 仅 么 危 纬 约 尺 革 巩 泼 香 护 践 春 旨",
        "952fe4f30f671929b4532328ebc61f89b84f742453431fb2dc39571ed017c82ebc9212132808512d7c5ea78b310c0d716592b96d7349527eefc9deb784963d2a"
    ]
}

tests! {
    // https://github.com/MetacoSA/NBitcoin/blob/master/NBitcoin.Tests/data/bip39_vectors.zh-TW.json
    [ChineseTraditional, "nullius　à　nym.zone ¹teſts² 漢語"]:
    [
        "00000000000000000000000000000000",
        "的 的 的 的 的 的 的 的 的 的 的 在",
        "ffcbd7bdf4e8b8fdca65edf8eaa5d23495af24eef7ecb6ede130bb754b5a7db0e3ad0f365398d4ec57114bc443e96349aeae0556f345290cd77ef69244fefc9d"
    ],
    [
        "0000000000000000000000000000000000000000",
        "的 的 的 的 的 的 的 的 的 的 的 的 的 的 地",
        "79643600685d29e90189a3824c11987638876cb52a09cec8a32a7c41dc7eac89e88182cbb9385309f880a96cfe49ee2a739eb3da5dfd936941ae4ffe6e764e13"
    ],
    [
        "000000000000000000000000000000000000000000000000",
        "的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 動",
        "e0064e96c5304d7db689e123370e1cb6595588bcbf37759b49bd7419f77da70777bb581a3d68370b21fbf1dbe5173d4eca26a1fd584f16b11d57598efed052f0"
    ],
    [
        "00000000000000000000000000000000000000000000000000000000",
        "的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 出",
        "3da50615797be8814a6412954f8c040ecf16daa3e6d59b42ca6707bed2989ca05d1d917a7bd9e7e057c962603f58f0c7943a7bba6766699b9b5149871a8a4cc6"
    ],
    [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 的 性",
        "a6795c3e0531fe201bf6b216bd54162e17c62eeadb7ff5e1f7c9c4a8d5b4b7f55008c865c2d43f76f9bb2bd407f99a2c9c2d38ba95ef74c0e79880fb84e553ef"
    ],
    [
        "01010101010101010101010101010101",
        "人 三 談 我 表 壤 對 據 人 三 談 於",
        "e675aaeb5f62b32d6c4926091765681ec89dbb358668bf913435d11bd7e1fdf35c32a7d65480e8ea82e044df0ea8e696c0320a62409a3229b83edb34f64869c4"
    ],
    [
        "0101010101010101010101010101010101010101",
        "人 三 談 我 表 壤 對 據 人 三 談 我 表 壤 而",
        "ee8581f8a234efd53a4a2e7e886cff8cd1563f3699d5e504d4881a911dd72a5335a6c059725950e75ffc9576d1fe38ce7cec5e43158cf83624ded5091e33273d"
    ],
    [
        "010101010101010101010101010101010101010101010101",
        "人 三 談 我 表 壤 對 據 人 三 談 我 表 壤 對 據 人 實",
        "5bed36f80142daffe16df01060f1417b8cb61aaec03fdc4c9600c7114768b43d295c558ffd0dc6d2a83bf79709be3e3e3c0aa3beeb359bd36d039a6582912f1b"
    ],
    [
        "01010101010101010101010101010101010101010101010101010101",
        "人 三 談 我 表 壤 對 據 人 三 談 我 表 壤 對 據 人 三 談 我 原",
        "4bd83974d83b702587096ca4a2b9d8b1c0b3811372ced9503c437d298e9f96467c1dc262c4d0caa9b083b9a2dbafc40dd55fe3644e88bb56f0611746af2a8362"
    ],
    [
        "0101010101010101010101010101010101010101010101010101010101010101",
        "人 三 談 我 表 壤 對 據 人 三 談 我 表 壤 對 據 人 三 談 我 表 壤 對 研",
        "090994ff576ec6d641fa46b71821a9df7a284b0b97b8be12cb9386e5334d6f7eb8dab4c5e00c5ba0d9d0bb76d457c27971f2bc95c159fa74c781ffd9727962e7"
    ],
    [
        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "槍 疫 黴 嘗 倆 鬧 餓 賢 槍 疫 黴 卿",
        "fa5c00f041f13d84d85cb2374bf544bd4fed781656af851ed1ba3e8307f5b6d6f70a9e23f962a9c14fa8b74a945c56eaea89ecce4ddadfb8aef813d16c227d9d"
    ],
    [
        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "槍 疫 黴 嘗 倆 鬧 餓 賢 槍 疫 黴 嘗 倆 鬧 沫",
        "2976bc4eae7859b15c063983f6e8e7b6c85e8ab60403c01c5bfc7b2eab33d33b413a921136656d7a5a0a4acd86d90eeaa042fb57303de7e86b993bb115e53775"
    ],
    [
        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "槍 疫 黴 嘗 倆 鬧 餓 賢 槍 疫 黴 嘗 倆 鬧 餓 賢 槍 殿",
        "ad3f915afa61165e670ef77a8e44e5614b563e8073a25ebc4e4f937d0cdcb0c998365890868b85ff83dc7d10a681fd09f4f1c2ef5d74f0c288d61a591835c9ee"
    ],
    [
        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "槍 疫 黴 嘗 倆 鬧 餓 賢 槍 疫 黴 嘗 倆 鬧 餓 賢 槍 疫 黴 嘗 盈",
        "30511f67b3ef770fa315ebef96822e64026ccc9d1dd1030eeccd8397998730408077a4fd831e4a881796d699c1c71a56a5242f20b6a9df38e17db5069d2dd67b"
    ],
    [
        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "槍 疫 黴 嘗 倆 鬧 餓 賢 槍 疫 黴 嘗 倆 鬧 餓 賢 槍 疫 黴 嘗 倆 鬧 餓 搭",
        "0bb96a63950eabb97ee63baf9a4eb4992939da546a369b052baa29a1627dc6b5ef12fa20e50c6983fc7cd9b7b7e2536c5d1565b6c716721f5516a21ffd0ecf1e"
    ],
    [
        "80808080808080808080808080808080",
        "壤 對 據 人 三 談 我 表 壤 對 據 不",
        "fc6b7f0e517ff0a75ad00789dfac1a0fe83ad622366f0034cb777fe421a45f396ac8e25305ec60eae9b9c7ea1b759cadbcc854a10232d336af3885445764531a"
    ],
    [
        "8080808080808080808080808080808080808080",
        "壤 對 據 人 三 談 我 表 壤 對 據 人 三 談 大",
        "0de3ad7d918e48a3551c99855e142c9e0d228a11a91b9b99d4662c738a776b1fa7fb9b236100c2baf9c3389f71e638320a9f87148c5efdc5283bacb781d5a773"
    ],
    [
        "808080808080808080808080808080808080808080808080",
        "壤 對 據 人 三 談 我 表 壤 對 據 人 三 談 我 表 壤 民",
        "6b994ffd10af76495a2a3de4ba5b2bc750e96845c631749227b7254490dc210a584952831ef593ce3e8cd1b09e222dc94e8f453e7ad30b5c1f99ccd2088e95a0"
    ],
    [
        "80808080808080808080808080808080808080808080808080808080",
        "壤 對 據 人 三 談 我 表 壤 對 據 人 三 談 我 表 壤 對 據 人 起",
        "24d488e4bb7025b1d79de515350477f3e866a79b80a0d34c23f0449bc048685e7bafabc6812205da576f3ed54086f58c9a34f5fd8614567e5df9ef2c4e220231"
    ],
    [
        "8080808080808080808080808080808080808080808080808080808080808080",
        "壤 對 據 人 三 談 我 表 壤 對 據 人 三 談 我 表 壤 對 據 人 三 談 我 五",
        "f1bf5ea488ff2e720efe887f8b9357d345335689270beb80219cf3192474aae1e86e1a9e73f39d3f9065cc68a06a3d85582cf05e1349123baedf4c24940ce5fb"
    ],
    [
        "fefefefefefefefefefefefefefefefe",
        "嘗 倆 鬧 餓 賢 槍 疫 黴 嘗 倆 鬧 皺",
        "018f3752ba1760be86a65337731de5eab0e11af028fc3247f22e7104739f98f94576ea0131715d0cbf0c6ea1f40a40b6aeccbb3b3f595fef64c6e1945f38f354"
    ],
    [
        "fefefefefefefefefefefefefefefefefefefefe",
        "嘗 倆 鬧 餓 賢 槍 疫 黴 嘗 倆 鬧 餓 賢 槍 曬",
        "b23d95709c974f4282adfe1ee4b95482b76b19cb6566ba0f8044aabe0d4df1007d892ccd6af7590860177c378ae87ce7fda5a6d284c7cffae1f0ac5ac265a999"
    ],
    [
        "fefefefefefefefefefefefefefefefefefefefefefefefe",
        "嘗 倆 鬧 餓 賢 槍 疫 黴 嘗 倆 鬧 餓 賢 槍 疫 黴 嘗 潑",
        "1cd6544b7e0b6cee61b94811dfdd32a2ef89db0157212d02966bdb8d0ffcfd8e83c086c4e6754606c5d37a8246556c9b98fd1fb5481384de280d074f05c17420"
    ],
    [
        "fefefefefefefefefefefefefefefefefefefefefefefefefefefefe",
        "嘗 倆 鬧 餓 賢 槍 疫 黴 嘗 倆 鬧 餓 賢 槍 疫 黴 嘗 倆 鬧 餓 坯",
        "7120d92e00f3f86516658d11c694415ec72986c6ff2e446b6c1f58fc5d878dc83f52f6908eadc305bee470bd9856d4c319beb9f9ffda7f91d37922b06fc287a3"
    ],
    [
        "fefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefe",
        "嘗 倆 鬧 餓 賢 槍 疫 黴 嘗 倆 鬧 餓 賢 槍 疫 黴 嘗 倆 鬧 餓 賢 槍 疫 蓄",
        "82cc20b41e3a2fcdfa0d5a5d9cdf3997f995be1bac66da4ab4b7e592353fbf83aa071e643034e161bef23eba4e7d4ddbaf4dc36800aa0243ce415fdd421252b0"
    ],
    [
        "ffffffffffffffffffffffffffffffff",
        "歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 邏",
        "8483090d4ebb5d95b067dd79700f99a7dfca5df072d99c53435d50d4f658ed5c25a6cbcf3d0cd2f558507bd23ecb3cbe938dd4c281a145e0356d702888ad86fb"
    ],
    [
        "ffffffffffffffffffffffffffffffffffffffff",
        "歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 溜",
        "ea7ef94655a0818bedb430249a7542bbe8c2a2555a48ef76314b34eafd617f79128b0478aa725be8aae40fc1dd9b03b3c829695f667fd3f1550d95ed4e16180c"
    ],
    [
        "ffffffffffffffffffffffffffffffffffffffffffffffff",
        "歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 裕",
        "aef1e2d2def86ef048137c603f9316fc4b02b15365560c9e42b676e7a66e92f044de16d76158012030fb891ecc49fd70d842b5034a513fe892d6b02b69d14254"
    ],
    [
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 躺",
        "5f52270a16f76d650b58397a98ca62c651c8092385bb59c1dc55aed74d77bf2f9f44e3f427a546adeb14ea88fc9f6db5686f6a150eaec37e2338836b70e4cff8"
    ],
    [
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 歇 佳",
        "31b0fb9c9f0ce630d36dee706ebef9c4de58f4d418ef19b1568ab0b6cbec3dd50e99d972e308c684b8da38c98a54eb57945067f89d677652c750dd4c429aa4a3"
    ],
    [
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "琴 軸 琴 軸 琴 軸 琴 軸 琴 軸 琴 找",
        "fc86a668066753181dcbac79e6ccf49c1c5526623f8be769f3b9eb3424293dddece99ec28d2a52b5b0ef4db3fc5f15b1993d663c9b0094778d46d3b8bf2a8e96"
    ],
    [
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "琴 軸 琴 軸 琴 軸 琴 軸 琴 軸 琴 軸 琴 軸 氏",
        "9c2e64140fbfe072c1e5f81f9b5c6498820a21843ea315ea338730181f961932b70ef4357948e8b07efdefc647bb656f292a4d3aedb1f9b40c6ff6c5df25cfe5"
    ],
    [
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "琴 軸 琴 軸 琴 軸 琴 軸 琴 軸 琴 軸 琴 軸 琴 軸 琴 良",
        "187c3cfc46a1e81035d8fdd50e3b4928a9de8bfaaad99720324e36669f91464a3accbf4f3fafceed0be03bb91844165b3f6365dec5dc5dc915069da22f1ac298"
    ],
    [
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "琴 軸 琴 軸 琴 軸 琴 軸 琴 軸 琴 軸 琴 軸 琴 軸 琴 軸 琴 軸 拍",
        "d71136f9838f15c76084781902b38cda51f1ebb422ba5f424a8363627d3841f521397fd9ee583a842eaa476c82d90e481c67a3f5fcf19f7e5774820186d9fed8"
    ],
    [
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "琴 軸 琴 軸 琴 軸 琴 軸 琴 軸 琴 軸 琴 軸 琴 軸 琴 軸 琴 軸 琴 軸 琴 既",
        "e0270f1f594afa411909db038c338d8276f0ccb1a03473704b0fd8f5d6098baf36888ea7506202ba0c5303fd436735792fac150a5457af17a7e865c77e0b6e73"
    ],
    [
        "55555555555555555555555555555555",
        "軸 琴 軸 琴 軸 琴 軸 琴 軸 琴 軸 腰",
        "4c18b927aed8436dea6c9d306b90c7df3f1dd90587422d97731a3406910698b4d6c417a19948776bae1834b892ca710da740356b79aec790109eca267c52f1d7"
    ],
    [
        "5555555555555555555555555555555555555555",
        "軸 琴 軸 琴 軸 琴 軸 琴 軸 琴 軸 琴 軸 琴 讓",
        "27483cd991a82cca06dd0eaa41f2cc7f1e1f4412787bf7d7f232361123f9ca7790d38eabe03cf3d81c60fc84943a637f8b848bf8a2760e6e1e85d71e5f46f1e4"
    ],
    [
        "555555555555555555555555555555555555555555555555",
        "軸 琴 軸 琴 軸 琴 軸 琴 軸 琴 軸 琴 軸 琴 軸 琴 軸 森",
        "ddde40fc505a58764a92d8fa74b06bfa8486cf9ecc1a6532887a2b75a39eceb55e55ac4c10be6605aadaae45f7ff6c2243e2b2c29f02c56c4b2852ce5db06f51"
    ],
    [
        "55555555555555555555555555555555555555555555555555555555",
        "軸 琴 軸 琴 軸 琴 軸 琴 軸 琴 軸 琴 軸 琴 軸 琴 軸 琴 軸 琴 讓",
        "f50d5c2d97b377a0e2fdbf4e3fa3994bf4b285c4428ec99f0f0310ecaa43d9d5a670160478465d54719478e5365ec9a3a096245e5653990e5554c4c90ef2b264"
    ],
    [
        "5555555555555555555555555555555555555555555555555555555555555555",
        "軸 琴 軸 琴 軸 琴 軸 琴 軸 琴 軸 琴 軸 琴 軸 琴 軸 琴 軸 琴 軸 琴 軸 獎",
        "aca6b7cab8613a28665b0ad6d671e0348693a1629febd5a2debd83a1fbfe80c657fb6adbdefac8665f19b2d41d13e874164683ac912dfb5adbb302037c37344f"
    ],
    [
        "9e885d952ad362caeb4efe34a8e91bd2",
        "蒙 台 脫 紀 構 硫 漿 黴 感 僅 魚 湯",
        "b51d582ab7007956cd310ebf342c93e0efa5ceeb86dca2ed85c8942fc3420cf4278d0b4c171b430af7c93c9945e6ae6a4ea02d984fdb0861864c559ec38abf07"
    ],
    [
        "6610b25967cdcca9d59875f5cb50b0ea75433311869e930b",
        "父 泥 煉 脅 鞋 控 載 政 慘 逐 整 碗 環 慣 案 棒 訂 移",
        "a36e504d8c1254e2eb632486397c3e14afc09adc79cf0e387ea62f98b45e1271ddc853651055ef06a4759457523669040e21066de748851a6b0b0a33e3360026"
    ],
    [
        "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
        "寧 照 違 材 交 養 違 野 悉 偷 梅 設 貴 帝 鮮 仰 圈 首 荷 鉤 隙 抓 養 熟",
        "0177e904c38b9dd2722dfcf3fef64e513ad835d5afaea4b2f3675729b1ea281c9e13916a400b1b9e115ba13e738c92b3d51a7b3d020c13120851c6a83b5b5011"
    ],
    [
        "b3ffe8f56d54805218090de337779328a3a2e758",
        "懂 艇 細 斥 早 目 湖 造 籠 祥 逮 未 置 胞 損",
        "da352efb5b89a7a00f41efb037b4f911f15ac1cc5e61774f85db61208cfea98a1e8bfc3d0210d005dc1290714ec365521a74b8c49652d68ae5808737b81450f9"
    ],
    [
        "437dd688276ceb711cda3a126eab879a188a30b097b769a931bea6fe",
        "輪 醇 畢 跟 矽 隆 抓 僅 麼 危 緯 約 尺 革 鞏 潑 香 護 踐 春 旨",
        "59aba23fcf0e9e6439b256aa76b7bd70e06b6db7772a3e9e64cf3581d3bc68c670318a9c0c41b09beafbe67f5c3e581168dc2b9471bcfd8dd135d582409d9696"
    ]
}

tests! {
    // https://github.com/bitcoinjs/bip39/blob/master/test/vectors.json
   [Japanese, "㍍ガバヴァぱばぐゞちぢ十人十色"]:
   [
     "00000000000000000000000000000000",
     "あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あおぞら",
     "a262d6fb6122ecf45be09c50492b31f92e9beb7d9a845987a02cefda57a15f9c467a17872029a9e92299b5cbdf306e3a0ee620245cbd508959b6cb7ca637bd55"
   ],
   [
     "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
     "そつう　れきだい　ほんやく　わかす　りくつ　ばいか　ろせん　やちん　そつう　れきだい　ほんやく　わかめ",
     "aee025cbe6ca256862f889e48110a6a382365142f7d16f2b9545285b3af64e542143a577e9c144e101a6bdca18f8d97ec3366ebf5b088b1c1af9bc31346e60d9"
   ],
   [
     "80808080808080808080808080808080",
     "そとづら　あまど　おおう　あこがれる　いくぶん　けいけん　あたえる　いよく　そとづら　あまど　おおう　あかちゃん",
     "e51736736ebdf77eda23fa17e31475fa1d9509c78f1deb6b4aacfbd760a7e2ad769c714352c95143b5c1241985bcb407df36d64e75dd5a2b78ca5d2ba82a3544"
   ],
   [
     "ffffffffffffffffffffffffffffffff",
     "われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　ろんぶん",
     "4cd2ef49b479af5e1efbbd1e0bdc117f6a29b1010211df4f78e2ed40082865793e57949236c43b9fe591ec70e5bb4298b8b71dc4b267bb96ed4ed282c8f7761c"
   ],
   [
     "000000000000000000000000000000000000000000000000",
     "あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あらいぐま",
     "d99e8f1ce2d4288d30b9c815ae981edd923c01aa4ffdc5dee1ab5fe0d4a3e13966023324d119105aff266dac32e5cd11431eeca23bbd7202ff423f30d6776d69"
   ],
   [
     "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
     "そつう　れきだい　ほんやく　わかす　りくつ　ばいか　ろせん　やちん　そつう　れきだい　ほんやく　わかす　りくつ　ばいか　ろせん　やちん　そつう　れいぎ",
     "eaaf171efa5de4838c758a93d6c86d2677d4ccda4a064a7136344e975f91fe61340ec8a615464b461d67baaf12b62ab5e742f944c7bd4ab6c341fbafba435716"
   ],
   [
     "808080808080808080808080808080808080808080808080",
     "そとづら　あまど　おおう　あこがれる　いくぶん　けいけん　あたえる　いよく　そとづら　あまど　おおう　あこがれる　いくぶん　けいけん　あたえる　いよく　そとづら　いきなり",
     "aec0f8d3167a10683374c222e6e632f2940c0826587ea0a73ac5d0493b6a632590179a6538287641a9fc9df8e6f24e01bf1be548e1f74fd7407ccd72ecebe425"
   ],
   [
     "ffffffffffffffffffffffffffffffffffffffffffffffff",
     "われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　りんご",
     "f0f738128a65b8d1854d68de50ed97ac1831fc3a978c569e415bbcb431a6a671d4377e3b56abd518daa861676c4da75a19ccb41e00c37d086941e471a4374b95"
   ],
   [
     "0000000000000000000000000000000000000000000000000000000000000000",
     "あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　いってい",
     "23f500eec4a563bf90cfda87b3e590b211b959985c555d17e88f46f7183590cd5793458b094a4dccc8f05807ec7bd2d19ce269e20568936a751f6f1ec7c14ddd"
   ],
   [
     "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
     "そつう　れきだい　ほんやく　わかす　りくつ　ばいか　ろせん　やちん　そつう　れきだい　ほんやく　わかす　りくつ　ばいか　ろせん　やちん　そつう　れきだい　ほんやく　わかす　りくつ　ばいか　ろせん　まんきつ",
     "cd354a40aa2e241e8f306b3b752781b70dfd1c69190e510bc1297a9c5738e833bcdc179e81707d57263fb7564466f73d30bf979725ff783fb3eb4baa86560b05"
   ],
   [
     "8080808080808080808080808080808080808080808080808080808080808080",
     "そとづら　あまど　おおう　あこがれる　いくぶん　けいけん　あたえる　いよく　そとづら　あまど　おおう　あこがれる　いくぶん　けいけん　あたえる　いよく　そとづら　あまど　おおう　あこがれる　いくぶん　けいけん　あたえる　うめる",
     "6b7cd1b2cdfeeef8615077cadd6a0625f417f287652991c80206dbd82db17bf317d5c50a80bd9edd836b39daa1b6973359944c46d3fcc0129198dc7dc5cd0e68"
   ],
   [
     "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
     "われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　われる　らいう",
     "a44ba7054ac2f9226929d56505a51e13acdaa8a9097923ca07ea465c4c7e294c038f3f4e7e4b373726ba0057191aced6e48ac8d183f3a11569c426f0de414623"
   ],
   [
     "77c2b00716cec7213839159e404db50d",
     "せまい　うちがわ　あずき　かろう　めずらしい　だんち　ますく　おさめる　ていぼう　あたる　すあな　えしゃく",
     "344cef9efc37d0cb36d89def03d09144dd51167923487eec42c487f7428908546fa31a3c26b7391a2b3afe7db81b9f8c5007336b58e269ea0bd10749a87e0193"
   ],
   [
     "b63a9c59a6e641f288ebc103017f1da9f8290b3da6bdef7b",
     "ぬすむ　ふっかつ　うどん　こうりつ　しつじ　りょうり　おたがい　せもたれ　あつめる　いちりゅう　はんしゃ　ごますり　そんけい　たいちょう　らしんばん　ぶんせき　やすみ　ほいく",
     "b14e7d35904cb8569af0d6a016cee7066335a21c1c67891b01b83033cadb3e8a034a726e3909139ecd8b2eb9e9b05245684558f329b38480e262c1d6bc20ecc4"
   ],
   [
     "3e141609b97933b66a060dcddc71fad1d91677db872031e85f4c015c5e7e8982",
     "くのう　てぬぐい　そんかい　すろっと　ちきゅう　ほあん　とさか　はくしゅ　ひびく　みえる　そざい　てんすう　たんぴん　くしょう　すいようび　みけん　きさらぎ　げざん　ふくざつ　あつかう　はやい　くろう　おやゆび　こすう",
     "32e78dce2aff5db25aa7a4a32b493b5d10b4089923f3320c8b287a77e512455443298351beb3f7eb2390c4662a2e566eec5217e1a37467af43b46668d515e41b"
   ],
   [
     "0460ef47585604c5660618db2e6a7e7f",
     "あみもの　いきおい　ふいうち　にげる　ざんしょ　じかん　ついか　はたん　ほあん　すんぽう　てちがい　わかめ",
     "0acf902cd391e30f3f5cb0605d72a4c849342f62bd6a360298c7013d714d7e58ddf9c7fdf141d0949f17a2c9c37ced1d8cb2edabab97c4199b142c829850154b"
   ],
   [
     "72f60ebac5dd8add8d2a25a797102c3ce21bc029c200076f",
     "すろっと　にくしみ　なやむ　たとえる　へいこう　すくう　きない　けってい　とくべつ　ねっしん　いたみ　せんせい　おくりがな　まかい　とくい　けあな　いきおい　そそぐ",
     "9869e220bec09b6f0c0011f46e1f9032b269f096344028f5006a6e69ea5b0b8afabbb6944a23e11ebd021f182dd056d96e4e3657df241ca40babda532d364f73"
   ],
   [
     "2c85efc7f24ee4573d2b81a6ec66cee209b2dcbd09d8eddc51e0215b0b68e416",
     "かほご　きうい　ゆたか　みすえる　もらう　がっこう　よそう　ずっと　ときどき　したうけ　にんか　はっこう　つみき　すうじつ　よけい　くげん　もくてき　まわり　せめる　げざい　にげる　にんたい　たんそく　ほそく",
     "713b7e70c9fbc18c831bfd1f03302422822c3727a93a5efb9659bec6ad8d6f2c1b5c8ed8b0b77775feaf606e9d1cc0a84ac416a85514ad59f5541ff5e0382481"
   ],
   [
     "eaebabb2383351fd31d703840b32e9e2",
     "めいえん　さのう　めだつ　すてる　きぬごし　ろんぱ　はんこ　まける　たいおう　さかいし　ねんいり　はぶらし",
     "06e1d5289a97bcc95cb4a6360719131a786aba057d8efd603a547bd254261c2a97fcd3e8a4e766d5416437e956b388336d36c7ad2dba4ee6796f0249b10ee961"
   ],
   [
     "7ac45cfe7722ee6c7ba84fbc2d5bd61b45cb2fe5eb65aa78",
     "せんぱい　おしえる　ぐんかん　もらう　きあい　きぼう　やおや　いせえび　のいず　じゅしん　よゆう　きみつ　さといも　ちんもく　ちわわ　しんせいじ　とめる　はちみつ",
     "1fef28785d08cbf41d7a20a3a6891043395779ed74503a5652760ee8c24dfe60972105ee71d5168071a35ab7b5bd2f8831f75488078a90f0926c8e9171b2bc4a"
   ],
   [
     "4fa1a8bc3e6d80ee1316050e862c1812031493212b7ec3f3bb1b08f168cabeef",
     "こころ　いどう　きあつ　そうがんきょう　へいあん　せつりつ　ごうせい　はいち　いびき　きこく　あんい　おちつく　きこえる　けんとう　たいこ　すすめる　はっけん　ていど　はんおん　いんさつ　うなぎ　しねま　れいぼう　みつかる",
     "43de99b502e152d4c198542624511db3007c8f8f126a30818e856b2d8a20400d29e7a7e3fdd21f909e23be5e3c8d9aee3a739b0b65041ff0b8637276703f65c2"
   ],
   [
     "18ab19a9f54a9274f03e5209a2ac8a91",
     "うりきれ　さいせい　じゆう　むろん　とどける　ぐうたら　はいれつ　ひけつ　いずれ　うちあわせ　おさめる　おたく",
     "3d711f075ee44d8b535bb4561ad76d7d5350ea0b1f5d2eac054e869ff7963cdce9581097a477d697a2a9433a0c6884bea10a2193647677977c9820dd0921cbde"
   ],
   [
     "18a2e1d81b8ecfb2a333adcb0c17a5b9eb76cc5d05db91a4",
     "うりきれ　うねる　せっさたくま　きもち　めんきょ　へいたく　たまご　ぜっく　びじゅつかん　さんそ　むせる　せいじ　ねくたい　しはらい　せおう　ねんど　たんまつ　がいけん",
     "753ec9e333e616e9471482b4b70a18d413241f1e335c65cd7996f32b66cf95546612c51dcf12ead6f805f9ee3d965846b894ae99b24204954be80810d292fcdd"
   ],
   [
     "15da872c95a13dd738fbf50e427583ad61f18fd99f628c417a61cf8343c90419",
     "うちゅう　ふそく　ひしょ　がちょう　うけもつ　めいそう　みかん　そざい　いばる　うけとる　さんま　さこつ　おうさま　ぱんつ　しひょう　めした　たはつ　いちぶ　つうじょう　てさぎょう　きつね　みすえる　いりぐち　かめれおん",
     "346b7321d8c04f6f37b49fdf062a2fddc8e1bf8f1d33171b65074531ec546d1d3469974beccb1a09263440fc92e1042580a557fdce314e27ee4eabb25fa5e5fe"
   ]
}
