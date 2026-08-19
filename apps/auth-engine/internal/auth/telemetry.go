/*
 * Authn Platform — Enterprise Identity Engine
 * File: apps/auth-engine/internal/auth/telemetry.go
 * Tier: Internal Feature Package / Telemetry & Trust Engine
 *
 * Description: High-performance IP subnet parsing (/24 IPv4 and /48 IPv6), signed trusted device token
 *              cookie generation & HMAC verification, device fingerprinting, and familiarity scoring.
 *
 * Security Notice:
 *   - Device cookies use HMAC-SHA256 signatures to prevent tampering.
 *   - Raw device tokens are NEVER stored in database; only SHA-256 hashes are persisted.
 *
 * License: GNU AGPLv3 — Copyright (C) Authn Platform Authors
 */

package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/pkg/idgen"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/trusteddevice"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/ent/useripsubnethistory"
	"github.com/hanan-bhatti/authn-2.0/apps/auth-engine/internal/policy"
)

var (
	ErrInvalidIPAddress = errors.New("invalid IP address string")
)

// ParseSubnet takes an IP address string and returns its /24 (IPv4) or /48 (IPv6) subnet string and version (4 or 6).
func ParseSubnet(ipStr string) (subnet string, version int, err error) {
	return ParseSubnetWithBits(ipStr, 24, 48)
}

// ParseSubnetWithBits takes an IP address string and configurable CIDR bit masks.
func ParseSubnetWithBits(ipStr string, v4Bits, v6Bits int) (subnet string, version int, err error) {
	ipStr = strings.TrimSpace(ipStr)
	parsedIP := net.ParseIP(ipStr)
	if parsedIP == nil {
		return "", 0, ErrInvalidIPAddress
	}

	if ip4 := parsedIP.To4(); ip4 != nil {
		if v4Bits < 16 || v4Bits > 30 {
			v4Bits = 24
		}
		mask := net.CIDRMask(v4Bits, 32)
		network := ip4.Mask(mask)
		return fmt.Sprintf("%s/%d", network.String(), v4Bits), 4, nil
	}

	if ip6 := parsedIP.To16(); ip6 != nil {
		if v6Bits < 32 || v6Bits > 64 {
			v6Bits = 48
		}
		mask := net.CIDRMask(v6Bits, 128)
		network := ip6.Mask(mask)
		return fmt.Sprintf("%s/%d", network.String(), v6Bits), 6, nil
	}

	return "", 0, ErrInvalidIPAddress
}

// GenerateSignedDeviceToken generates a 256-bit random device ID + HMAC-SHA256 signature using kmsKey.
// Returns: rawCookieVal (to set in browser), tokenHash (SHA-256 for DB storage), err
func GenerateSignedDeviceToken(kmsKey string) (rawCookieVal string, tokenHash string, err error) {
	tokenID := uuid.New().String()
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", "", fmt.Errorf("failed generating random device bytes: %w", err)
	}
	rawToken := fmt.Sprintf("%s.%s", tokenID, hex.EncodeToString(randomBytes))

	// Compute HMAC signature
	mac := hmac.New(sha256.New, []byte(kmsKey))
	mac.Write([]byte(rawToken))
	sig := hex.EncodeToString(mac.Sum(nil))

	rawCookieVal = fmt.Sprintf("%s.%s", rawToken, sig)

	// Compute SHA-256 hash for database index
	hashSum := sha256.Sum256([]byte(rawCookieVal))
	tokenHash = hex.EncodeToString(hashSum[:])

	return rawCookieVal, tokenHash, nil
}

// VerifySignedDeviceToken checks the HMAC-SHA256 signature of a raw cookie value.
func VerifySignedDeviceToken(cookieVal, kmsKey string) (tokenHash string, valid bool) {
	parts := strings.Split(cookieVal, ".")
	if len(parts) != 3 { // tokenID.randomBytes.signature
		return "", false
	}

	rawToken := fmt.Sprintf("%s.%s", parts[0], parts[1])
	sig := parts[2]

	mac := hmac.New(sha256.New, []byte(kmsKey))
	mac.Write([]byte(rawToken))
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(sig), []byte(expectedSig)) {
		return "", false
	}

	hashSum := sha256.Sum256([]byte(cookieVal))
	return hex.EncodeToString(hashSum[:]), true
}

// ComputeFingerprintHash computes SHA-256 of client User-Agent and Accept-Language.
func ComputeFingerprintHash(userAgent, acceptLang string) string {
	payload := fmt.Sprintf("%s|%s", strings.TrimSpace(userAgent), strings.TrimSpace(acceptLang))
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

// TelemetryService provides trust evaluation, device registration, and subnet tracking.
type TelemetryService struct {
	repo       *Repository
	kmsKey     string
	policyRepo *policy.Repository
}

// NewTelemetryService constructs a new TelemetryService instance.
func NewTelemetryService(repo *Repository, kmsKey string, policyRepo *policy.Repository) *TelemetryService {
	return &TelemetryService{
		repo:       repo,
		kmsKey:     kmsKey,
		policyRepo: policyRepo,
	}
}

// TrustEvaluationResult holds the familiar device and network scoring outcome.
type TrustEvaluationResult struct {
	IsRecognizedDevice bool   `json:"is_recognized_device"`
	IsFamiliarSubnet   bool   `json:"is_familiar_subnet"`
	DeviceID           string `json:"device_id,omitempty"`
	Subnet             string `json:"subnet"`
}

// EvaluateTrust checks if the incoming request comes from a recognized trusted device and familiar IP subnet.
func (s *TelemetryService) EvaluateTrust(ctx context.Context, userID, deviceCookie, ipAddress, userAgent, acceptLang string) (*TrustEvaluationResult, error) {
	var recPolicy policy.RecoveryPolicy
	if s.policyRepo != nil {
		if u, err := s.repo.GetUserByID(ctx, userID); err == nil && u != nil {
			recPolicy, _ = s.policyRepo.GetRecoveryPolicy(ctx, u.TenantID, string(u.Environment))
		} else {
			recPolicy = policy.DefaultRecoveryPolicy()
		}
	} else {
		recPolicy = policy.DefaultRecoveryPolicy()
	}

	subnet, _, err := ParseSubnetWithBits(ipAddress, recPolicy.IPv4SubnetBits, recPolicy.IPv6SubnetBits)
	if err != nil {
		return nil, err
	}

	res := &TrustEvaluationResult{
		Subnet: subnet,
	}

	// 1. Evaluate IP Subnet Familiarity (seen within policy window)
	client := s.repo.factory.GetClient(ctx, "", "")
	cutoff := time.Now().Add(-time.Duration(recPolicy.TrustedDeviceWindowDays) * 24 * time.Hour)

	subnetExists, err := client.UserIpSubnetHistory.Query().
		Where(
			useripsubnethistory.UserID(userID),
			useripsubnethistory.Subnet(subnet),
			useripsubnethistory.LastSeenAtGT(cutoff),
		).
		Exist(ctx)
	if err == nil && subnetExists {
		res.IsFamiliarSubnet = true
	}

	// 2. Evaluate Trusted Device Cookie
	if deviceCookie != tokenHashEmpty(deviceCookie) {
		tokenHash, valid := VerifySignedDeviceToken(deviceCookie, s.kmsKey)
		if valid {
			fpHash := ComputeFingerprintHash(userAgent, acceptLang)
			td, err := client.TrustedDevice.Query().
				Where(
					trusteddevice.UserID(userID),
					trusteddevice.DeviceTokenHash(tokenHash),
					trusteddevice.StatusEQ(trusteddevice.StatusActive),
					trusteddevice.ExpiresAtGT(time.Now()),
				).
				Only(ctx)

			if err == nil && td != nil {
				// Verify fingerprint hash matches (prevents cookie theft across browsers/OS)
				if td.FingerprintHash == fpHash {
					res.IsRecognizedDevice = true
					res.DeviceID = td.ID

					// Refresh sliding window expiry & last_seen_at
					newExpiry := time.Now().Add(time.Duration(recPolicy.TrustedDeviceWindowDays) * 24 * time.Hour)
					_ = client.TrustedDevice.UpdateOne(td).
						SetLastSeenAt(time.Now()).
						SetLastIPAddress(ipAddress).
						SetLastIPSubnet(subnet).
						SetExpiresAt(newExpiry).
						Exec(ctx)
				}
			}
		}
	}

	return res, nil
}

// IsBlacklisted evaluates if the incoming IP, subnet, or device fingerprint is on the 7-day security blacklist for this user.
//
// environment selects which of the tenant's two recovery policies supplies the
// subnet widths. The widths decide how wide a net a single blacklist entry casts,
// so reading them from the wrong environment would measure the request against a
// configuration its administrator never applied to it.
func (s *TelemetryService) IsBlacklisted(ctx context.Context, tenantID, environment, userID, ipAddress, userAgent, acceptLang string) (bool, error) {
	var recPolicy policy.RecoveryPolicy
	if s.policyRepo != nil {
		recPolicy, _ = s.policyRepo.GetRecoveryPolicy(ctx, tenantID, environment)
	} else {
		recPolicy = policy.DefaultRecoveryPolicy()
	}

	subnet, _, _ := ParseSubnetWithBits(ipAddress, recPolicy.IPv4SubnetBits, recPolicy.IPv6SubnetBits)
	fpHash := ComputeFingerprintHash(userAgent, acceptLang)

	return s.repo.IsOriginBlacklisted(ctx, tenantID, userID, ipAddress, subnet, fpHash)
}

func tokenHashEmpty(cookie string) string {
	if strings.TrimSpace(cookie) == "" {
		return ""
	}
	return "invalid"
}

// RecordSuccessfulLoginTelemetry updates IP subnet history and registers/refreshes trusted device.
func (s *TelemetryService) RecordSuccessfulLoginTelemetry(ctx context.Context, userID, deviceCookie, ipAddress, userAgent, acceptLang string) (newCookieVal string, err error) {
	var recPolicy policy.RecoveryPolicy
	if s.policyRepo != nil {
		if u, err := s.repo.GetUserByID(ctx, userID); err == nil && u != nil {
			recPolicy, _ = s.policyRepo.GetRecoveryPolicy(ctx, u.TenantID, string(u.Environment))
		} else {
			recPolicy = policy.DefaultRecoveryPolicy()
		}
	} else {
		recPolicy = policy.DefaultRecoveryPolicy()
	}

	subnet, version, err := ParseSubnetWithBits(ipAddress, recPolicy.IPv4SubnetBits, recPolicy.IPv6SubnetBits)
	if err != nil {
		return "", err
	}

	client := s.repo.factory.GetClient(ctx, "", "")

	// 1. Record/Update IP Subnet History
	history, err := client.UserIpSubnetHistory.Query().
		Where(
			useripsubnethistory.UserID(userID),
			useripsubnethistory.Subnet(subnet),
		).
		Only(ctx)

	if ent.IsNotFound(err) {
		id := idgen.New("sub")
		_ = client.UserIpSubnetHistory.Create().
			SetID(id).
			SetUserID(userID).
			SetSubnet(subnet).
			SetIPVersion(version).
			SetLoginCount(1).
			SetFirstSeenAt(time.Now()).
			SetLastSeenAt(time.Now()).
			Exec(ctx)
	} else if history != nil {
		_ = client.UserIpSubnetHistory.UpdateOne(history).
			SetLastSeenAt(time.Now()).
			SetLoginCount(history.LoginCount + 1).
			Exec(ctx)
	}

	// 2. Register or Refresh Trusted Device Cookie
	fpHash := ComputeFingerprintHash(userAgent, acceptLang)
	expiresAt := time.Now().Add(time.Duration(recPolicy.TrustedDeviceWindowDays) * 24 * time.Hour)

	if deviceCookie != "" {
		tokenHash, valid := VerifySignedDeviceToken(deviceCookie, s.kmsKey)
		if valid {
			td, err := client.TrustedDevice.Query().
				Where(
					trusteddevice.UserID(userID),
					trusteddevice.DeviceTokenHash(tokenHash),
				).
				Only(ctx)
			if err == nil && td != nil {
				_ = client.TrustedDevice.UpdateOne(td).
					SetLastSeenAt(time.Now()).
					SetLastIPAddress(ipAddress).
					SetLastIPSubnet(subnet).
					SetFingerprintHash(fpHash).
					SetExpiresAt(expiresAt).
					SetStatus(trusteddevice.StatusActive).
					Exec(ctx)
				return deviceCookie, nil
			}
		}
	}

	// Issue new trusted device token cookie
	rawCookieVal, tokenHash, err := GenerateSignedDeviceToken(s.kmsKey)
	if err != nil {
		return "", err
	}

	devID := idgen.New("trd")
	deviceName := parseDeviceName(userAgent)

	_, err = client.TrustedDevice.Create().
		SetID(devID).
		SetUserID(userID).
		SetDeviceTokenHash(tokenHash).
		SetFingerprintHash(fpHash).
		SetDeviceName(deviceName).
		SetLastIPAddress(ipAddress).
		SetLastIPSubnet(subnet).
		SetStatus(trusteddevice.StatusActive).
		SetFirstSeenAt(time.Now()).
		SetLastSeenAt(time.Now()).
		SetExpiresAt(expiresAt).
		Save(ctx)

	if err != nil {
		return "", fmt.Errorf("failed creating trusted device record: %w", err)
	}

	return rawCookieVal, nil
}

// telemetryRetentionWindow is how long inactive subnet and trusted-device
// telemetry is kept before PurgeExpiredTelemetry deletes it.
//
// It is a data-retention period rather than a security control: the risk signals
// derived from this history stop being meaningful well before it elapses, and a
// deployment with a stricter retention obligation should shorten it.
const telemetryRetentionWindow = 90 * 24 * time.Hour

// PurgeExpiredTelemetry removes subnet and trusted-device records untouched for
// longer than telemetryRetentionWindow, returning how many of each it deleted.
func (s *TelemetryService) PurgeExpiredTelemetry(ctx context.Context) (purgedSubnets int, purgedDevices int, err error) {
	client := s.repo.factory.GetClient(ctx, "", "")
	cutoff := time.Now().Add(-telemetryRetentionWindow)

	// Purge subnets last seen > 90 days ago
	purgedSubnets, err = client.UserIpSubnetHistory.Delete().
		Where(useripsubnethistory.LastSeenAtLT(cutoff)).
		Exec(ctx)
	if err != nil {
		return 0, 0, fmt.Errorf("failed purging expired subnets: %w", err)
	}

	// Expire trusted devices
	purgedDevices, err = client.TrustedDevice.Delete().
		Where(trusteddevice.ExpiresAtLT(time.Now())).
		Exec(ctx)
	if err != nil {
		return purgedSubnets, 0, fmt.Errorf("failed purging expired trusted devices: %w", err)
	}

	return purgedSubnets, purgedDevices, nil
}

func parseDeviceName(ua string) string {
	if strings.Contains(ua, "Chrome") {
		return "Chrome Browser"
	}
	if strings.Contains(ua, "Safari") {
		return "Safari Browser"
	}
	if strings.Contains(ua, "Firefox") {
		return "Firefox Browser"
	}
	return "Unknown Web Browser"
}
