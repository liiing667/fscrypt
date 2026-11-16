/*
 * fixtures_test.go - Tests validity checks against serialized metadata
 * fixtures, mirroring how corrupt metadata files are handled after being read
 * from disk and unmarshaled.
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
	"os"
	"path/filepath"
	"testing"

	"github.com/pkg/errors"
	"google.golang.org/protobuf/proto"
)

func TestPolicyDataFixtures(t *testing.T) {
	fixtures := []struct {
		name      string
		file      string
		wantValid bool
		wantError error // sentinel the error must wrap; ignored when wantValid
	}{
		{"good v1 policy", "policy_good_v1.pb", true, nil},
		{"good v2 policy", "policy_good_v2.pb", true, nil},
		{"non-hex key descriptor", "policy_bad_key_descriptor_format.pb", false, ErrInvalidDescriptor},
		{"wrong length key descriptor", "policy_bad_key_descriptor_length.pb", false, nil},
		{"empty key slot list", "policy_empty_key_slots.pb", false, ErrNoKeySlots},
		{"duplicate protector descriptor", "policy_duplicate_protector.pb", false, ErrDuplicateProtector},
		{"non-hex protector descriptor", "policy_bad_protector_descriptor_format.pb", false, ErrInvalidDescriptor},
	}

	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("testdata", fixture.file))
			if err != nil {
				t.Fatal(err)
			}

			// This is the same unmarshal + CheckValidity sequence used by
			// Mount.getMetadata() when reading a metadata file.
			policy := &PolicyData{}
			if err := proto.Unmarshal(raw, policy); err != nil {
				t.Fatalf("could not unmarshal fixture: %v", err)
			}
			err = policy.CheckValidity()
			if fixture.wantValid {
				if err != nil {
					t.Fatalf("fixture should be valid, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("fixture should have failed CheckValidity")
			}
			if fixture.wantError != nil && !errors.Is(err, fixture.wantError) {
				t.Fatalf("CheckValidity() = %v, want error wrapping %v",
					err, fixture.wantError)
			}
		})
	}
}
