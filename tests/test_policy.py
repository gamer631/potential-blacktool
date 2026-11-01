from blacktool.policy import violations

def test_policy_allows_below_threshold():
    assert violations({"findings":[{"severity":"medium"}]},"high")==[]

def test_policy_blocks_high_and_critical():
    assert len(violations({"findings":[{"severity":"high"},{"severity":"critical"}]},"high"))==2
