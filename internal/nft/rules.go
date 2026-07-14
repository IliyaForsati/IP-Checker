package nft

import (
	"fmt"
	"os/exec"
	"strings"
)

const TableName = "ipchecker"

func Setup(dnsQueueNum, tlsQueueNum uint16) error {
	script := fmt.Sprintf(`table inet %s {
    chain output {
        type filter hook output priority filter; policy accept;
        oifname "lo" accept
        udp dport 53 queue num %d bypass
        tcp dport 53 queue num %d bypass
        tcp dport 443 queue num %d bypass
    }
}
`, TableName, dnsQueueNum, dnsQueueNum, tlsQueueNum)

	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft: setup failed: %w: %s", err, out)
	}
	return nil
}

func Teardown() error {
	cmd := exec.Command("nft", "delete", "table", "inet", TableName)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft: teardown failed: %w: %s", err, out)
	}
	return nil
}
