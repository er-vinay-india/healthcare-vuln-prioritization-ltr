import pandas as pd
from cti_recommender import cti_recommender as cr


def test_attack_flag_matches_technique_name():
    nvd = pd.DataFrame([
        {'cve_id': 'CVE-TEST-1', 'published': '2025-01-01Z', 'description_en': 'This vulnerability enables phishing attacks allowing credential theft.'},
        {'cve_id': 'CVE-TEST-2', 'published': '2025-01-02Z', 'description_en': 'No relevant technique mentioned here.'},
    ])
    attack_df = pd.DataFrame([
        {'id': 'attack-1', 'name': 'Phishing', 'description': '', 'aliases': ['spear-phishing']},
    ])
    out = cr.build_healthcare_features(nvd, attack_df=attack_df)
    assert int(out.loc[out['cve_id'] == 'CVE-TEST-1', 'attack_flag'].iloc[0]) == 1
    assert int(out.loc[out['cve_id'] == 'CVE-TEST-2', 'attack_flag'].iloc[0]) == 0


def test_attack_flag_matches_alias():
    nvd = pd.DataFrame([
        {'cve_id': 'CVE-TEST-3', 'published': '2025-01-03Z', 'description_en': 'Spear-phishing was used to gain initial access.'},
    ])
    attack_df = pd.DataFrame([
        {'id': 'attack-1', 'name': 'Phishing', 'description': '', 'aliases': ['spear-phishing']},
    ])
    out = cr.build_healthcare_features(nvd, attack_df=attack_df)
    assert int(out.loc[out['cve_id'] == 'CVE-TEST-3', 'attack_flag'].iloc[0]) == 1
