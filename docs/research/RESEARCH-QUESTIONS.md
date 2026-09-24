# Final research questions - 2026-09-18

1. **RQ1:** Can privacy-preserving contextual browser evidence distinguish legitimate and phishing activity across unseen websites?
2. **RQ2:** Which evidence families contribute most to accuracy?
3. **RQ3:** How well does the model generalize to unseen domains, brands and templates?
4. **RQ4:** Can legitimate login, payment and SSO workflows be handled with acceptably low false positives?
5. **RQ5:** How early in the browser session can a reliable threat decision be reached?
6. **RQ6:** For threats detected early enough, how often does the extension actually prevent the supported dangerous action?
7. **RQ7:** What accuracy/privacy trade-off results from refusing to inspect secret values and request bodies?

The earlier graph-versus-flat experiment remains a secondary historical engineering comparison. Its approximately 0.007 PR-AUC difference was below the 0.020 exploratory margin; graph superiority was not demonstrated. Flat contextual vectors are the primary model representation. Relationships remain useful for evidence correlation and explanations.

Each question requires scoped empirical evidence. Synthetic holdouts are pipeline checks, controlled browser episodes are controlled observations, and neither establishes performance across unseen real services. Detection, early detection and actual prevention must be measured separately. See `../MASTER-SPECIFICATION.md` and `../../CURRENT-STATUS.md`.
