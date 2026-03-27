// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package secp256k1

import (
	"math/big"
	"testing"
)

// TestIsOnCurveRejectsCoordinatesAboveP_CVE_2026_26315 verifies that IsOnCurve
// rejects points with coordinates >= P (the field prime). Without this check,
// an attacker can use equivalent coordinates (x+P ≡ x mod P) to bypass
// validation and mount invalid-curve attacks to extract the node key.
func TestIsOnCurveRejectsCoordinatesAboveP_CVE_2026_26315(t *testing.T) {
	curve := S256()

	// The generator point G = (Gx, Gy) is on the curve.
	if !curve.IsOnCurve(curve.Gx, curve.Gy) {
		t.Fatal("generator point should be on the curve")
	}

	// (Gx + P, Gy) is mathematically equivalent mod P, but must be rejected
	// because the coordinate exceeds the field prime.
	xPlusP := new(big.Int).Add(curve.Gx, curve.P)
	if curve.IsOnCurve(xPlusP, curve.Gy) {
		t.Fatal("IsOnCurve should reject x coordinate >= P")
	}

	// (Gx, Gy + P) — same test for the y coordinate.
	yPlusP := new(big.Int).Add(curve.Gy, curve.P)
	if curve.IsOnCurve(curve.Gx, yPlusP) {
		t.Fatal("IsOnCurve should reject y coordinate >= P")
	}

	// Exactly P should also be rejected.
	if curve.IsOnCurve(curve.P, big.NewInt(0)) {
		t.Fatal("IsOnCurve should reject x == P")
	}
}
