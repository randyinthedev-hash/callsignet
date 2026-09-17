package nft

import "testing"

func TestCount(t *testing.T) {
	out := []byte(`{"nftables":[{"metainfo":{"version":"1.0.9"}},` +
		`{"counter":{"family":"inet","name":"blocked","table":"callsignet",` +
		`"handle":1,"packets":12,"bytes":720}}]}`)
	if got := Count(out); got != 12 {
		t.Errorf("12여야 하는데 %d", got)
	}
	if got := Count([]byte("JSON이 아니다")); got != 0 {
		t.Errorf("읽지 못하면 0이어야 하는데 %d", got)
	}
}
