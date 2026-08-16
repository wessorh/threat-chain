// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

// Command ipfs-verifier is the off-chain IPFS detection-rule verifier daemon.
// It polls the chain for pending verification jobs, fetches the referenced CID
// from an IPFS gateway, hashes the content, and submits a verification report.
//
// It shells out to the threatattestd binary for chain queries and transaction
// submission, so it only needs the binary, a funded relayer key, and an IPFS
// gateway.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os/exec"
	"strconv"
	"time"
)

type pendingJob struct {
	JobID         string `json:"job_id"`
	AttestationID string `json:"attestation_id"`
	RuleID        string `json:"rule_id"`
	CID           string `json:"cid"`
	ExpectedSHA256 string `json:"expected_sha256"`
	Attempts      uint32 `json:"attempts"`
}

type pendingJobsResponse struct {
	Jobs []pendingJob `json:"jobs"`
}

func main() {
	binary := flag.String("binary", "threatattestd", "path to the threatattestd binary")
	node := flag.String("node", "tcp://localhost:26657", "chain RPC address")
	home := flag.String("home", "", "keyring home directory")
	from := flag.String("from", "verifier", "relayer key name")
	chainID := flag.String("chain-id", "threatattest-1", "chain ID")
	gateway := flag.String("gateway", "https://ipfs.io/ipfs/", "IPFS gateway base URL")
	interval := flag.Duration("interval", 30*time.Second, "poll interval")
	maxCount := flag.Uint("max-count", 10, "max jobs per poll")
	timeout := flag.Duration("fetch-timeout", 60*time.Second, "IPFS fetch timeout")
	flag.Parse()

	log.Printf("ipfs-verifier: polling %s every %s (relayer=%s)", *node, *interval, *from)

	for {
		jobs, err := queryPendingJobs(*binary, *node, *maxCount)
		if err != nil {
			log.Printf("query jobs: %v", err)
			time.Sleep(*interval)
			continue
		}
		if len(jobs) == 0 {
			time.Sleep(*interval)
			continue
		}

		for _, j := range jobs {
			if err := verifyJob(j, *binary, *node, *home, *from, *chainID, *gateway, *timeout); err != nil {
				log.Printf("job %s: %v", j.JobID, err)
			}
		}
		time.Sleep(*interval)
	}
}

// queryPendingJobs shells out to `threatattestd query ipfsverify pending-jobs`.
func queryPendingJobs(binary, node string, maxCount uint) ([]pendingJob, error) {
	cmd := exec.Command(binary, "query", "ipfsverify", "pending-jobs",
		"--max-count", strconv.FormatUint(uint64(maxCount), 10),
		"--node", node, "--output", "json")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}
	var resp pendingJobsResponse
	if err := json.Unmarshal(out, &resp); err != nil {
		return nil, fmt.Errorf("parse: %w (output %s)", err, out)
	}
	return resp.Jobs, nil
}

// verifyJob fetches the CID content, hashes it, and submits a report.
func verifyJob(j pendingJob, binary, node, home, from, chainID, gateway string, timeout time.Duration) error {
	url := gateway + j.CID
	actual, err := fetchAndHash(url, timeout)
	matched := false
	errMsg := ""
	if err != nil {
		errMsg = err.Error()
	} else {
		matched = (actual == j.ExpectedSHA256)
	}
	log.Printf("job %s: cid=%s matched=%v", j.JobID, j.CID, matched)

	args := []string{
		"tx", "ipfsverify", "submit-report",
		"--job-id", j.JobID,
		"--attestation-id", j.AttestationID,
		"--rule-id", j.RuleID,
		"--cid", j.CID,
		"--expected-sha256", j.ExpectedSHA256,
		"--matched", strconv.FormatBool(matched),
		"--verified-at", strconv.FormatInt(time.Now().Unix(), 10),
		"--from", from,
		"--chain-id", chainID,
		"--node", node,
	}
	if actual != "" {
		args = append(args, "--actual-sha256", actual)
	}
	if errMsg != "" {
		args = append(args, "--error-msg", errMsg)
	}
	if home != "" {
		args = append(args, "--home", home)
	}
	args = append(args, "-y")

	out, err := exec.Command(binary, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("submit: %w (%s)", err, out)
	}
	log.Printf("job %s: report submitted", j.JobID)
	return nil
}

// fetchAndHash downloads the URL and returns the lowercase hex SHA-256.
func fetchAndHash(url string, timeout time.Duration) (string, error) {
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(url)
	if err != nil {
		return "", fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetch %s: status %d", url, resp.StatusCode)
	}
	h := sha256.New()
	if _, err := io.Copy(h, resp.Body); err != nil {
		return "", fmt.Errorf("read %s: %w", url, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
