// Governance Voting Nullifier Test
//
// This test validates the core assumption of the ZCash governance voting proposal:
// "Hardware wallets do not verify the nullifier provided in input actions.
//  So we can off-chain alter the nullifier derivation, and the wallet can still sign it."
//
// Test Strategy:
// 1. Take a valid PCZT with correct nullifier
// 2. Modify the nullifier bytes to simulate governance nullifier derivation
// 3. Verify sign_pczt succeeds (proving nullifier isn't validated during signing)
// 4. Verify check_pczt_cypherpunk fails (proving nullifier IS validated during checking)
//
// This demonstrates that the signing and checking are separate code paths,
// and governance nullifiers will work.

#[cfg(test)]
#[cfg(feature = "cypherpunk")]
mod governance_nullifier_tests {
    use super::super::*;
    use alloc::vec::Vec;
    use blake2b_simd::Params as Blake2bParams;
    use ff::PrimeField;
    use halo2_poseidon::{ConstantLength, Hash, P128Pow5T3};
    use keystore::algorithms::zcash::{calculate_seed_fingerprint, derive_ufvk};
    use zcash_vendor::{
        pasta_curves::pallas,
        pczt::Pczt,
        zcash_protocol::consensus::MainNetwork,
    };

    // Pallas base field modulus (q) - nullifier must be less than this
    // q = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001
    // For simplicity, we'll use a mask to ensure validity when converting bytes to field element
    const PALLAS_MODULUS_HIGH_BYTE_MASK: u8 = 0x3F; // Ensures high byte < 0x40

    // Test data: A valid PCZT with Orchard actions and matching seed
    const VALID_PCZT_HEX: &str = "50435a5401000000058ace9cb502d5a09cc70c0100f083ae0185010000000180ade2041976a91467f7aa14f177a7e0058c66c7242e086488bd3d1088ac000001237431544d4c4a376b324e344e6172716b3546643575556f38324e58534d624b5267436300000000fbc2f4300c01f0b7820d00e3347c8da4ee614674376cbc45359daa54f9b5493e010000000000000000000000000000000000000000000000000000000000000000024d2eeb083d7c168f64239c3186d53c72e2b1a3a5140f5250f0963689c08cd61c0999baea13f0be05dc6a2554bb2f8f093f4d20911202567a5ab9fd17bce5142b3f79838a71d14757fcff03ba16486a3efb26c9773ec9596821d1e5f32039fe220001d5d3506f152f62c45198446223abf29e06da700990a779fb60a460712fb666a0ff1fab61e2b2b3566b263d0180b6dc05014b2225d5521d6dbb55ae03d22567ce98b242ba5520bc4e2493ec36fb9211c6350194215c2aa089dfa317c61bab4b9747f4e45abca855e45e00710a3dc5caa40a570186f6f9e818f6674c2df92918a55d20f340944de5c67c1c4a9ee347c2c2d6d71d4753d765f2859a3157f7b05cc3bc7089e3f2c9d5abb3fcb1708e74c790985d3dd90cfe2ed03276dfda527c6e8c08d9a1fdeedcb6aef59d9e5bf0ae5d9477ed030001872727f23f40a96896b66d04de905791bae2bc7ee9dc1f4e4ec5ae493dc2fc1001afb475105f1f5b477c52aa3c32ccf131b0c556b80f55ac555460e6b5148bf85303a0808080088581808008808080800800002585b32c42aa5a12b2763953f09aafed13450eda0c416e32d0978260c4171c375413b91e25fa826399623b6716ae8bbb0b4a1099de22478944627af7e5969aa0c404ffab4d35664c1dafd2d2c0cecf4fb3c8b054179f84b2d35d207077b3d256b429acdee34963c573b55ae20fffce73e0e3e575c8fde9d115e7ffab50b3bee60d2436b72c17677e1d7db141fafa72c7f89002908a7a8de3320e5ad3d1ed0bb545235e136904c5c5e4adfa5a100420ceb2196e5e197e919aeaeefa7cb2a1d98e011539af52d618bfb3ba1dfc2d2c01e9bd67523bb6787eb5a0d28e30ad483c6303efd4796795082cc67ea94ba8548a33da1a5ec7c56174bd6b260f548e83a924b7cdd32980ca489b44e981aa1d81cefe2581eebf3a585fb80542aea4a27862f593203b560a412ba4e737c8f678f239f3d1d07c5a82367435f0a0921c46600eb4f6f7387b3cb5984af98b1337f5148ad6388b62dab7cdc48c66ff81685894c2d1d0fe41716b7cb457fb5bd6ff13e321d2f91c15d431f942d7869955dfeadfff61638266ba38d7ba4db7ffe5ee03550d345715cebd9b378181b5769c22e1b20328165da02eeb5d246c70c008ac0c7f7b1bba2cf8270f013eb99cbc5d534270180f34892fdf08d8c16c518d8b7f62d832d676c65fcae34c640ff30d5bd9d65afeab509117a98374b4b9b016228a65bdd803d6c601d2ad6a654c2fe4487d9c7b088d886c36a6afe63d33f8c474f096500acabbb63968e7408c620cc8139331cf7227e9bdbf4b7bae292e15d310e66186b730f28d0515ac5bb71fcc5de09995fe89d005cc2c7afd0fb8f01b315815d38366ebeb6de9ed565b5d1f2ce14b7795b9ad784851f357beacc454be41aaec506f0148461ba5907043ab8618114bbbede979d7f0e0e0af914750df648079e3625e4f309d13ff74d4ada783203bb3652137abd8327cdd06b9332591c9abdcc0cc16f7fec2e0afd849bef8927b3b0ceeca2b90af7611875b78cf525852ee83e10c8f4cb2c80045cbf33c0801a55eeb15c9dca6e53b3dde8a12daf820f1f76624ee48e3128aaa0ef6f6fb32a0303d89e88be288be1b92a301e893790179ec07711e275f48de2f5f8e0ee7b000091c9d96159746d46f353e67463d7052000000000118c5796d39cd2bc56b0a062c20ebd32feb0b57cc231c262d6703520f8de603211edcf51f6084e3288cbdb02957a02cd68fb84973a6a98260fb60f30951dedb2e1240275687c0bd82a2653a2c212bd3c0ea75cd294f5a4d31dcf507c15461402760282899f6b560858c0b6bd95c708f62d1e856480a52401d0d7d6a642fa1c2a10176072c6147735b785ea4ad9276378885704a44c6246f4630ef1df59438562e055bba6c1411a790727ab27421e6c418df8b65cb636d6786ce9e5b632659f5d32401caffe6271e2d77d8634e67a116926d7566b5eb2f2aadba6498d7a1e120f27f52379bb3f8781090ae47e30b0100011a78b2abbab21b29d79141fdff8a389c2eacde5be75c69ae4c4fabc175aec10a0142b202630def2df1f7cd23fcf362c68194829282c57b0c4d5f0ca023b51a571f01bd466676b53cfc27ba4a94bb4ab3ed19d8db336042e09e1e756b560b5ce7fc05d5dc3269236828f541662db5bfd4ab6e07c4dac2682906ee85eca2d12b6522013dd286fc499141cfebfb53175ea4321e08e8a504604bbc2e9d3e59706a1fa439000130febcd5d0c57c6e3780d6fe1f6c07f01a9d5d7a053ac5562f29304418d33a20000000f7fa16a612e422c34d61c44ae692b255c921239547172fcd26519928a3abb10d22548d840b466f1fed5ccb4c442d97b4b59d1a728455ee1598bae8e316f819bac404c9112693c57e0733d550ddc984d82ecc9047721e7e7bc6f283ba00852e49a4d3cda4dad343a366650b1d75b26025eadc5200113ebcc2a4a7db9ac2291083d76e7a8c04831764caf35e4c18bfc58e58699b4a651ca3686a95a6db7133611b5ce80a14225cdac643311869ea0c4a6d760379f285fa9c396c435361044da7e077f236d589a3eb962129988ea6ccde694cb72fa986748fc106981320f478a1c5402fe75a26dee31ec9fad4240aa19932fa8361c43798aa381c63b0c0b17657ccf37792a28456cfe6562e15d9e4aa26ed2660b6c8fc8a92cd352a6025dabcbed5eba82d88b9df3ba73270ff2f9c44fca8b0c1df8ed4cbfa2a4ebe7d0bcc6e5ce73e43b51e054860d7939ca13d77813b372070fd24cdd9c0e2fad7567471c0279bba19a76f0cdbd3107220821dd676c1df6524c15b87c1318eda418d65f8c66d2a77a65f6894199d44611e60c0291c330d1692bd521aef0e316e2b3f8c377b0d6873b3b645196ba74a79c6e0509869ac66276c3e2dfefd54a12365b5945406e7b673321ed36e89a14a194ae8b864e9ac4684655bae7fcd3123a226f282ac6ac82ca88d6a383d8be90f87f4cb85225f697932abfb4c05cda3b6dadb003621fee663f3fcb8f1c96320a3f148bc106ec231961a8f5142dd614317eef16b81492668a8b8795b85d7b0f737fa8d79e9dc3d78840d158a73dc6d1700ce3a8de2a9f93ff1bc8108703b94fd5bd230a19dd0fd821b832d3508b335e07bac28e95c3ab0eb637334bf166fa2a440ea35c0372bb5a745ee86c727a80f0d0d080fef6642ae7aae1407d6a25c3050c498a52ae300105bded1f19829b10df00e7ba301a9aef2c99ad7c5338b0e259ab97ea852630606b8d59709ca067d32698c8761e0f7d5b76ac07d4860b0fe2992010ba88827bb37cf4e3436488580e79101b366d454f29aa2bdf76725130baa08b38af3a71c251521809c84fe3d086943f39f01d760884b6342fac60c010001c54930d4f4f9946dfe91ac3e94cf5b513871c4a5c0c21137959482da796d2d280000000001c4666732084baff2e402ed7d3e457303c73b77dbd4aa5bc943ac7ca96f3779070398a2e304004aed48232c44dbd0b0b5404063ecc4679436f28c6251cbba91e29388fcd98d0e0001dc2be19f4118dbb7500df3a95e304733b247cea7f8c681f6aaafceb8fc1d7d28";

    const MATCHING_SEED_HEX: &str = "d561f5aba9db8b100a9a84197322e522f952171a388ad74eaab1ab9db815be3335c3099a0a2bb0fee57e630db5ed7251412b6bd4b905cf518627411fee3f32dd";

    /// Converts a 32-byte array to a Pallas base field element.
    ///
    /// Masks the high byte to ensure the value is less than the field modulus.
    /// This is a simplified approach; production code should use proper modular reduction.
    fn bytes_to_pallas_base(bytes: &[u8; 32]) -> pallas::Base {
        let mut masked = *bytes;
        // Pallas uses little-endian, so byte[31] is the most significant byte.
        masked[31] &= PALLAS_MODULUS_HIGH_BYTE_MASK;
        pallas::Base::from_repr(masked).expect("masked bytes should be valid field element")
    }

    /// Hashes a proposal ID to a Pallas field element using Blake2b.
    ///
    /// This allows variable-length proposal IDs to be used in Poseidon hash.
    fn hash_proposal_id(proposal_id: &[u8]) -> pallas::Base {
        let hash = Blake2bParams::new()
            .hash_length(32)
            .personal(b"ZcashGovProposal")
            .hash(proposal_id);
        let bytes: [u8; 32] = hash.as_bytes().try_into().expect("Blake2b output is 32 bytes");
        bytes_to_pallas_base(&bytes)
    }

    /// Derives a governance nullifier using the proposed Poseidon-based scheme.
    ///
    /// Standard Orchard nullifier: Poseidon(nk, rho, psi, cm)
    /// Governance nullifier: Poseidon(H(proposal_id), voting_share_index, nk, rho)
    ///
    /// Per the proposal: "The UI derives governance nullifiers by changing the Poseidon hash
    /// from H(nullifier_key || rho) to instead effectively be
    /// H("gov_proposal_1" || voting_share_3 || nullifier_key || rho)."
    ///
    /// The governance nullifier is intentionally different from the mainnet derivation
    /// so that:
    /// 1. It cannot be used to spend funds on mainnet
    /// 2. It uniquely identifies a vote for a specific (proposal, voting_share, note)
    /// 3. It can be verified in an off-chain ZKP
    fn derive_governance_nullifier(
        proposal_id: &[u8],
        voting_share_index: u8,
        nk: &[u8; 32],  // nullifier deriving key
        rho: &[u8; 32], // note randomness (rho from the note)
    ) -> [u8; 32] {
        // Convert inputs to Pallas field elements
        let proposal_element = hash_proposal_id(proposal_id);
        let voting_share_element = pallas::Base::from(voting_share_index as u64);
        let nk_element = bytes_to_pallas_base(nk);
        let rho_element = bytes_to_pallas_base(rho);

        // Use Poseidon hash with 4 inputs
        // P128Pow5T3 has width 3 and rate 2, so we use ConstantLength<4>
        // which will absorb inputs in 2 rounds (2 elements per round)
        let nullifier: pallas::Base = Hash::<_, P128Pow5T3, ConstantLength<4>, 3, 2>::init()
            .hash([proposal_element, voting_share_element, nk_element, rho_element]);

        // Convert field element back to bytes
        nullifier.to_repr()
    }

    /// Decomposes a ZEC amount into voting shares based on binary representation.
    ///
    /// Per the proposal: "13 ZEC is 'bitwise' split into eligible votes: 8 ZEC, 4 ZEC, 1 ZEC"
    /// (13 = 1101 in binary, so bits 0, 2, 3 are set)
    ///
    /// Returns a vector of (voting_share_index, zec_amount) tuples.
    fn decompose_zec_to_voting_shares(zec_amount: u64) -> Vec<(u8, u64)> {
        let mut shares = Vec::new();
        for bit_position in 0..64 {
            if (zec_amount >> bit_position) & 1 == 1 {
                let share_amount = 1u64 << bit_position;
                shares.push((bit_position as u8, share_amount));
            }
        }
        shares
    }

    /// Modifies the nullifier bytes in a serialized PCZT.
    ///
    /// This is a byte-level manipulation to replace the standard nullifier
    /// with a governance nullifier, simulating what the voting UI would do.
    fn replace_nullifier_in_pczt(pczt_bytes: &[u8], new_nullifier: &[u8; 32]) -> Vec<u8> {
        let mut modified = pczt_bytes.to_vec();

        // Parse to find nullifier location
        if let Ok(pczt) = Pczt::parse(pczt_bytes) {
            if !pczt.orchard().actions().is_empty() {
                let original_nf = pczt.orchard().actions()[0].spend().nullifier();

                // Find this pattern in the bytes and replace
                if let Some(pos) = find_subsequence(&modified, original_nf) {
                    modified[pos..pos + 32].copy_from_slice(new_nullifier);
                }
            }
        }

        modified
    }

    /// Helper to find a byte subsequence
    fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack
            .windows(needle.len())
            .position(|window| window == needle)
    }

    // =========================================================================
    // Core Tests: Prove the governance proposal assumptions
    // =========================================================================

    #[test]
    fn test_signing_succeeds_with_standard_nullifier() {
        // Baseline: Verify signing works with the original PCZT
        let pczt_bytes = hex::decode(VALID_PCZT_HEX).unwrap();
        let seed = hex::decode(MATCHING_SEED_HEX).unwrap();

        let result = sign::sign_pczt(Pczt::parse(&pczt_bytes).unwrap(), &seed);

        assert!(
            result.is_ok(),
            "Signing with standard nullifier should succeed"
        );
    }

    #[test]
    fn test_signing_succeeds_with_governance_nullifier() {
        // CORE TEST: Signing should succeed even with a governance-derived nullifier
        // because sign_pczt does NOT validate nullifier derivation

        let pczt_bytes = hex::decode(VALID_PCZT_HEX).unwrap();
        let seed = hex::decode(MATCHING_SEED_HEX).unwrap();

        // Derive a proper governance nullifier
        let proposal_id = b"zcash_poll_2025_q1";
        let voting_share_index = 3u8; // For 8 ZEC vote chunk
        let mock_nk = [0xAAu8; 32];
        let mock_rho = [0xBBu8; 32];

        let governance_nullifier =
            derive_governance_nullifier(proposal_id, voting_share_index, &mock_nk, &mock_rho);

        // Modify the PCZT to use governance nullifier
        let modified_pczt_bytes = replace_nullifier_in_pczt(&pczt_bytes, &governance_nullifier);

        // Verify the modification worked
        let modified_pczt = Pczt::parse(&modified_pczt_bytes).expect("Modified PCZT should parse");
        if !modified_pczt.orchard().actions().is_empty() {
            let modified_nf = modified_pczt.orchard().actions()[0].spend().nullifier();
            assert_eq!(
                modified_nf, &governance_nullifier,
                "Nullifier should be modified to governance nullifier"
            );
        }

        // THE KEY ASSERTION: Signing should STILL succeed
        let result = sign::sign_pczt(modified_pczt, &seed);

        assert!(
            result.is_ok(),
            "Signing with governance nullifier should succeed because \
             Keystone does NOT verify nullifier derivation during signing. \
             Error: {:?}",
            result.err()
        );

        // Verify the signed PCZT is valid
        let signed_bytes = result.unwrap();
        assert!(
            Pczt::parse(&signed_bytes).is_ok(),
            "Signed PCZT should be parseable"
        );
    }

    #[test]
    fn test_check_fails_with_governance_nullifier() {
        // Complementary test: check_pczt_cypherpunk should FAIL with governance nullifier
        // This proves the nullifier verification exists but is separate from signing

        let pczt_bytes = hex::decode(VALID_PCZT_HEX).unwrap();
        let seed = hex::decode(MATCHING_SEED_HEX).unwrap();

        let seed_fingerprint = calculate_seed_fingerprint(&seed).unwrap();
        let ufvk = derive_ufvk(&MainNetwork, &seed, "m/32'/133'/0'").unwrap();

        // Create governance nullifier
        let governance_nullifier = derive_governance_nullifier(
            b"zcash_poll_2025_q1",
            3u8,
            &[0xAAu8; 32],
            &[0xBBu8; 32],
        );

        let modified_pczt_bytes = replace_nullifier_in_pczt(&pczt_bytes, &governance_nullifier);

        // Check should FAIL because verify_nullifier() will not match
        let check_result = crate::check_pczt_cypherpunk(
            &MainNetwork,
            &modified_pczt_bytes,
            &ufvk,
            &seed_fingerprint,
            0,
        );

        assert!(
            check_result.is_err(),
            "Check should fail with governance nullifier because verify_nullifier() \
             is called in check.rs:357 but NOT in sign.rs"
        );
    }

    // =========================================================================
    // Governance Nullifier Derivation Tests
    // =========================================================================

    #[test]
    fn test_governance_nullifier_is_deterministic() {
        let proposal_id = b"gov_proposal_1";
        let voting_share_index = 3u8;
        let nk = [0xAAu8; 32];
        let rho = [0xBBu8; 32];

        let nf1 = derive_governance_nullifier(proposal_id, voting_share_index, &nk, &rho);
        let nf2 = derive_governance_nullifier(proposal_id, voting_share_index, &nk, &rho);

        assert_eq!(nf1, nf2, "Same inputs must produce same nullifier");
    }

    #[test]
    fn test_governance_nullifier_is_non_zero() {
        let nf = derive_governance_nullifier(b"test_proposal", 0, &[0xAAu8; 32], &[0xBBu8; 32]);

        assert_ne!(nf, [0u8; 32], "Governance nullifier should not be all zeros");
    }

    #[test]
    fn test_different_proposals_produce_different_nullifiers() {
        let nk = [0xAAu8; 32];
        let rho = [0xBBu8; 32];
        let voting_share = 3u8;

        let nf1 = derive_governance_nullifier(b"proposal_A", voting_share, &nk, &rho);
        let nf2 = derive_governance_nullifier(b"proposal_B", voting_share, &nk, &rho);

        assert_ne!(
            nf1, nf2,
            "Different proposals must produce different nullifiers"
        );
    }

    #[test]
    fn test_different_voting_shares_produce_different_nullifiers() {
        let proposal_id = b"gov_proposal_1";
        let nk = [0xAAu8; 32];
        let rho = [0xBBu8; 32];

        let nf_8zec = derive_governance_nullifier(proposal_id, 3, &nk, &rho); // 2^3 = 8 ZEC
        let nf_4zec = derive_governance_nullifier(proposal_id, 2, &nk, &rho); // 2^2 = 4 ZEC
        let nf_1zec = derive_governance_nullifier(proposal_id, 0, &nk, &rho); // 2^0 = 1 ZEC

        assert_ne!(
            nf_8zec, nf_4zec,
            "Different voting shares must produce different nullifiers"
        );
        assert_ne!(
            nf_4zec, nf_1zec,
            "Different voting shares must produce different nullifiers"
        );
        assert_ne!(
            nf_8zec, nf_1zec,
            "Different voting shares must produce different nullifiers"
        );
    }

    #[test]
    fn test_different_notes_produce_different_nullifiers() {
        let proposal_id = b"gov_proposal_1";
        let voting_share = 3u8;

        let nf1 = derive_governance_nullifier(proposal_id, voting_share, &[0xAAu8; 32], &[0xBBu8; 32]);
        let nf2 = derive_governance_nullifier(proposal_id, voting_share, &[0xCCu8; 32], &[0xDDu8; 32]);

        assert_ne!(
            nf1, nf2,
            "Different notes (nk, rho) must produce different nullifiers"
        );
    }

    // =========================================================================
    // Voting Share Decomposition Tests
    // =========================================================================

    #[test]
    fn test_decompose_13_zec() {
        // Per proposal: "13 ZEC is 'bitwise' split into eligible votes: 8 ZEC, 4 ZEC, 1 ZEC"
        // 13 = 1101 in binary (bits 0, 2, 3 are set)
        let shares = decompose_zec_to_voting_shares(13);

        assert_eq!(shares.len(), 3, "13 ZEC should decompose into 3 shares");

        // Check the shares (order: bit 0, bit 2, bit 3)
        assert!(shares.contains(&(0, 1)), "Should have 1 ZEC share (bit 0)");
        assert!(shares.contains(&(2, 4)), "Should have 4 ZEC share (bit 2)");
        assert!(shares.contains(&(3, 8)), "Should have 8 ZEC share (bit 3)");

        // Verify they sum to original
        let sum: u64 = shares.iter().map(|(_, amount)| amount).sum();
        assert_eq!(sum, 13, "Shares should sum to original amount");
    }

    #[test]
    fn test_decompose_127_zec() {
        // Per proposal: "127 ZEC" example for many voting shares
        // 127 = 1111111 in binary (7 bits set)
        let shares = decompose_zec_to_voting_shares(127);

        assert_eq!(shares.len(), 7, "127 ZEC should decompose into 7 shares");

        let sum: u64 = shares.iter().map(|(_, amount)| amount).sum();
        assert_eq!(sum, 127, "Shares should sum to original amount");
    }

    #[test]
    fn test_decompose_power_of_two() {
        // 8 ZEC = 1000 in binary (only bit 3 set)
        let shares = decompose_zec_to_voting_shares(8);

        assert_eq!(shares.len(), 1, "Power of 2 should have single share");
        assert_eq!(shares[0], (3, 8), "8 ZEC should be voting_share_3");
    }

    #[test]
    fn test_unique_nullifiers_per_voting_share() {
        // For a user with 13 ZEC voting on proposal 1:
        // They should get 3 unique nullifiers for their 3 voting shares
        let proposal_id = b"gov_proposal_1";
        let nk = [0xAAu8; 32];
        let rho = [0xBBu8; 32];

        let shares = decompose_zec_to_voting_shares(13);
        let nullifiers: Vec<[u8; 32]> = shares
            .iter()
            .map(|(voting_share_index, _)| {
                derive_governance_nullifier(proposal_id, *voting_share_index, &nk, &rho)
            })
            .collect();

        // All nullifiers should be unique
        for i in 0..nullifiers.len() {
            for j in (i + 1)..nullifiers.len() {
                assert_ne!(
                    nullifiers[i], nullifiers[j],
                    "Each voting share must have a unique nullifier"
                );
            }
        }
    }

    // =========================================================================
    // End-to-End Simulation Test
    // =========================================================================

    #[test]
    fn test_full_voting_flow_simulation() {
        // Simulate the full voting flow for a 13 ZEC holder voting YES on proposal 1
        let proposal_id = b"zcash_governance_2025_proposal_1";
        let vote_choice = "YES";
        let zec_amount = 13u64;

        // Mock note secrets (in reality, derived from user's wallet)
        let nk = [0x11u8; 32]; // nullifier key
        let rho = [0x22u8; 32]; // note randomness

        // Step 1: Decompose holdings into voting shares
        let voting_shares = decompose_zec_to_voting_shares(zec_amount);
        assert_eq!(voting_shares.len(), 3); // 8 + 4 + 1

        // Step 2: Generate governance nullifiers for each share
        let gov_nullifiers: Vec<([u8; 32], u64)> = voting_shares
            .iter()
            .map(|(share_idx, amount)| {
                let nf = derive_governance_nullifier(proposal_id, *share_idx, &nk, &rho);
                (nf, *amount)
            })
            .collect();

        // Step 3: Verify all nullifiers are unique (prevents double-voting)
        let unique_count = gov_nullifiers
            .iter()
            .map(|(nf, _)| nf)
            .collect::<alloc::collections::BTreeSet<_>>()
            .len();
        assert_eq!(
            unique_count,
            gov_nullifiers.len(),
            "All governance nullifiers must be unique"
        );

        // Step 4: Verify total voting power matches holdings
        let total_voting_power: u64 = gov_nullifiers.iter().map(|(_, amount)| amount).sum();
        assert_eq!(
            total_voting_power, zec_amount,
            "Total voting power should equal ZEC holdings"
        );

        // Step 5: In real implementation, each (nullifier, vote_choice, amount) would be:
        // - Included in a PCZT
        // - Signed by Keystone (which we proved works above)
        // - Submitted to vote tallier with ZKP
        // - Tallier verifies: ZKP valid, signature valid, nullifier not seen before

        // This test just verifies the nullifier generation logic is correct
        for (nf, amount) in &gov_nullifiers {
            assert_ne!(nf, &[0u8; 32], "Nullifier should not be zero");
            assert!(
                *amount > 0,
                "Voting share amount should be positive"
            );
        }
    }
}
