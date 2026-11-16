/*
 * checks_test.go - Tests the validity checks for our metadata structures
 *
 * Copyright 2024 Google Inc.
 * Author: fscrypt contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

package metadata

import (
	"testing"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

var (
	testDescriptor1 = "0123456789abcdef"
	testDescriptor2 = "fedcba9876543210"
)

func newTestWrappedPolicyKey(protectorDescriptor string) *WrappedPolicyKey {
	return &WrappedPolicyKey{
		ProtectorDescriptor: protectorDescriptor,
		WrappedKey: &WrappedKeyData{
			EncryptedKey: make([]byte, PolicyKeyLen),
			IV:           make([]byte, IVLen),
			Hmac:         make([]byte, HMACLen),
		},
	}
}

func newTestPolicy(version int64, keyDescriptor string,
	wrappedKeys ...*WrappedPolicyKey) *PolicyData {
	options := &EncryptionOptions{
		Padding:       32,
		Contents:      EncryptionOptions_AES_256_XTS,
		Filenames:     EncryptionOptions_AES_256_CTS,
		PolicyVersion: version,
	}
	return &PolicyData{
		KeyDescriptor:     keyDescriptor,
		Options:           options,
		WrappedPolicyKeys: wrappedKeys,
	}
}

// CheckDescriptor must reject malformed descriptors but accept every legal
// v1/v2 descriptor.
func TestCheckDescriptor(t *testing.T) {
	goodDescriptors := map[int][]string{
		unix.FSCRYPT_KEY_DESCRIPTOR_SIZE: {
			"0000000000000000",
			"0123456789abcdef",
			"abcdef0123456789",
		},
		unix.FSCRYPT_KEY_IDENTIFIER_SIZE: {
			"00000000000000000000000000000000",
			"0123456789abcdef0123456789abcdef",
		},
	}
	for expectedLen, descriptors := range goodDescriptors {
		for _, descriptor := range descriptors {
			if err := CheckDescriptor(descriptor, expectedLen); err != nil {
				t.Errorf("CheckDescriptor(%q, %d) failed: %v", descriptor, expectedLen, err)
			}
		}
	}

	badDescriptors := map[int][]string{
		unix.FSCRYPT_KEY_DESCRIPTOR_SIZE: {
			"0123456789abcde",   // too short
			"0123456789abcdef0", // too long
			"xxxxxxxxxxxxxxxx",  // non-hex characters
			"0123456789abcdeG",  // non-hex character at the end
			"0123456789abcdef ", // trailing space
		},
		unix.FSCRYPT_KEY_IDENTIFIER_SIZE: {
			"0123456789abcdef0123456789abcde",   // too short
			"0123456789abcdef0123456789abcdef0", // too long
			"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",  // non-hex characters
		},
	}
	for expectedLen, descriptors := range badDescriptors {
		for _, descriptor := range descriptors {
			err := CheckDescriptor(descriptor, expectedLen)
			if err == nil {
				t.Errorf("CheckDescriptor(%q, %d) should have failed", descriptor, expectedLen)
				continue
			}
			// Length errors and hex-format errors are distinct kinds of
			// format failures, but only the latter carries ErrInvalidDescriptor.
			if len(descriptor) == 2*expectedLen &&
				!errors.Is(err, ErrInvalidDescriptor) {
				t.Errorf("CheckDescriptor(%q, %d) = %v, want ErrInvalidDescriptor",
					descriptor, expectedLen, err)
			}
		}
	}
}

// Legal v1 and v2 policies must remain valid.
func TestPolicyDataCheckValidityGoodPolicies(t *testing.T) {
	goodPolicies := []*PolicyData{
		newTestPolicy(1, "0123456789abcdef",
			newTestWrappedPolicyKey(testDescriptor1)),
		newTestPolicy(1, "0123456789abcdef",
			newTestWrappedPolicyKey(testDescriptor1),
			newTestWrappedPolicyKey(testDescriptor2)),
		newTestPolicy(2, "0123456789abcdef0123456789abcdef",
			newTestWrappedPolicyKey(testDescriptor1)),
		newTestPolicy(2, "0123456789abcdef0123456789abcdef",
			newTestWrappedPolicyKey(testDescriptor1),
			newTestWrappedPolicyKey(testDescriptor2)),
	}
	for i, policy := range goodPolicies {
		if err := policy.CheckValidity(); err != nil {
			t.Errorf("good policy %d was rejected: %v", i, err)
		}
	}
}

// A policy with an unset version is treated as v1 (backwards compatibility).
func TestPolicyDataCheckValidityDefaultVersion(t *testing.T) {
	policy := newTestPolicy(0, "0123456789abcdef",
		newTestWrappedPolicyKey(testDescriptor1))
	policy.Options.PolicyVersion = 0
	if err := policy.CheckValidity(); err != nil {
		t.Fatalf("legacy v1 policy was rejected: %v", err)
	}
	if policy.Options.PolicyVersion != 1 {
		t.Errorf("PolicyVersion = %d, want 1", policy.Options.PolicyVersion)
	}
}

func TestPolicyDataCheckValidityErrors(t *testing.T) {
	testCases := []struct {
		name      string
		policy    *PolicyData
		wantError error // sentinel the error must wrap; nil means any non-nil
		// error (e.g. a length error) is accepted.
	}{
		{
			name:      "nil policy",
			policy:    nil,
			wantError: errNotInitialized,
		},
		{
			name:      "no key slots",
			policy:    newTestPolicy(1, "0123456789abcdef"),
			wantError: ErrNoKeySlots,
		},
		{
			name: "duplicate protector descriptor",
			policy: newTestPolicy(1, "0123456789abcdef",
				newTestWrappedPolicyKey(testDescriptor1),
				newTestWrappedPolicyKey(testDescriptor1)),
			wantError: ErrDuplicateProtector,
		},
		{
			name: "non-hex policy key descriptor",
			policy: newTestPolicy(1, "xxxxxxxxxxxxxxxx",
				newTestWrappedPolicyKey(testDescriptor1)),
			wantError: ErrInvalidDescriptor,
		},
		{
			name: "wrong length v1 key descriptor",
			policy: newTestPolicy(1, "0123456789abcde",
				newTestWrappedPolicyKey(testDescriptor1)),
			wantError: nil,
		},
		{
			name: "v2 descriptor on a v1 policy",
			policy: newTestPolicy(1, "0123456789abcdef0123456789abcdef",
				newTestWrappedPolicyKey(testDescriptor1)),
			wantError: nil,
		},
		{
			name: "non-hex protector descriptor in key slot",
			policy: newTestPolicy(1, "0123456789abcdef",
				newTestWrappedPolicyKey("xxxxxxxxxxxxxxxx")),
			wantError: ErrInvalidDescriptor,
		},
		{
			name: "v2 policy with non-hex key descriptor",
			policy: newTestPolicy(2, "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
				newTestWrappedPolicyKey(testDescriptor1)),
			wantError: ErrInvalidDescriptor,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.policy.CheckValidity()
			if tc.wantError == nil {
				if err == nil {
					t.Fatalf("CheckValidity() should have failed")
				}
				return
			}
			if err == nil {
				t.Fatalf("CheckValidity() = nil, want %v", tc.wantError)
			}
			if !errors.Is(err, tc.wantError) {
				t.Fatalf("CheckValidity() = %v, want error wrapping %v", err, tc.wantError)
			}
		})
	}
}

func TestProtectorDataCheckValidityBadDescriptor(t *testing.T) {
	protector := &ProtectorData{
		Source:              SourceType_raw_key,
		ProtectorDescriptor: "xxxxxxxxxxxxxxxx",
		WrappedKey: &WrappedKeyData{
			EncryptedKey: make([]byte, InternalKeyLen),
			IV:           make([]byte, IVLen),
			Hmac:         make([]byte, HMACLen),
		},
	}
	err := protector.CheckValidity()
	if err == nil {
		t.Fatal("non-hex protector descriptor should make the protector invalid")
	}
	if !errors.Is(err, ErrInvalidDescriptor) {
		t.Fatalf("CheckValidity() = %v, want error wrapping ErrInvalidDescriptor", err)
	}
}
